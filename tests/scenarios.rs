//! End-to-end scenarios against real git repos in a sandbox directory.
//! "Future" evaluation (`now + N days`) stands in for waiting; ctime cannot be
//! back-dated, which is exactly why the tool supports a simulated clock.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tree_gc::config::Config;
use tree_gc::exec::{self, ApplyOpts, JStatus, Journal};
use tree_gc::model::{Action, Item, Kind, Plan, Verdict};
use tree_gc::scan::build_plan;
use tree_gc::util::{now_epoch, DAY};

const LATER: i64 = 60; // days

struct Env {
    _dir: tempfile::TempDir,
    base: PathBuf,
    projects: PathBuf,
    tmp: PathBuf,
    scratch: PathBuf,
    cfg: Config,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "advice.detachedHead=false"])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(dir: &Path, file: &str, msg: &str) -> String {
    fs::write(dir.join(file), msg).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-qm", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

fn env_with(extra: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let projects = base.join("projects");
    let tmp = base.join("tmp");
    let scratch = base.join("agent-scratch");
    for d in [&projects, &tmp, &scratch] {
        fs::create_dir_all(d).unwrap();
    }
    let toml = format!(
        r#"
enforce = true
state_dir = "{b}/state"
quarantine_dir = "{b}/quarantine"
quarantine_days = 14
active_days = 2
# Never touch the host's docker or other cleaners' locks from tests.
interop_locks = []
user_activity_files = []
# No pacing / I/O-pressure waits in tests (a busy host must not make them flaky).
throttle_secs_per_gib = 0.0
throttle_max_io_psi = 100.0
[[roots]]
path = "{p}"
[[roots]]
path = "{t}"
kind = "tmp"
[[scratch]]
name = "agent"
path = "{s}"
stale_days = 7
keep_newest = 2
exclude = ["*.db"]
{extra}
[docker]
enabled = false
[pressure]
enabled = false
"#,
        b = base.display(),
        p = projects.display(),
        t = tmp.display(),
        s = scratch.display()
    );
    let cfg = Config::from_toml(&toml).unwrap();
    assert!(!cfg.docker.enabled && cfg.interop_locks.is_empty(), "tests must never touch host docker/locks");
    Env { _dir: dir, base, projects, tmp, scratch, cfg }
}

fn env() -> Env {
    env_with("")
}

/// Repo with an origin remote (bare, in the sandbox) and origin/HEAD set.
fn repo(e: &Env, name: &str) -> PathBuf {
    let r = e.projects.join(name);
    fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q"]);
    fs::write(r.join(".gitignore"), "target/\n.env\n*.log\n").unwrap();
    fs::write(r.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
    git(&r, &["add", "."]);
    git(&r, &["commit", "-qm", "init"]);
    let origin = e.base.join(format!("{name}-origin.git"));
    git(&e.base, &["clone", "-q", "--bare", r.to_str().unwrap(), origin.to_str().unwrap()]);
    git(&r, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(&r, &["fetch", "-q", "origin"]);
    git(&r, &["remote", "set-head", "origin", "main"]);
    r
}

fn add_wt(repo: &Path, name: &str, branch: Option<&str>) -> PathBuf {
    let p = repo.parent().unwrap().join(name);
    match branch {
        Some(b) => git(repo, &["worktree", "add", "-q", p.to_str().unwrap(), "-b", b]),
        None => git(repo, &["worktree", "add", "-q", "--detach", p.to_str().unwrap()]),
    };
    p
}

/// Make `dir` look like real Cargo output (Cargo always writes this tag).
fn cargo_out(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("CACHEDIR.TAG"), "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n").unwrap();
}

fn plan(e: &Env, days: i64) -> Plan {
    build_plan(&e.cfg, now_epoch() + days * DAY).unwrap()
}

fn item<'a>(p: &'a Plan, kind: Kind, path: &Path, branch: Option<&str>) -> &'a Item {
    p.items
        .iter()
        .find(|i| i.kind == kind && i.path == path && (branch.is_none() || i.branch.as_deref() == branch))
        .unwrap_or_else(|| panic!("no {kind:?} item for {} {branch:?}\nitems: {:#?}", path.display(), p.items))
}

fn apply_later(e: &Env, p: &Plan) -> exec::Outcome {
    let opts = ApplyOpts { now: now_epoch() + LATER * DAY, max_actions: 1000, max_bytes: u64::MAX, kinds: None };
    exec::apply(&e.cfg, p, &opts).unwrap()
}

fn journal(e: &Env) -> Vec<exec::JEntry> {
    Journal::open(&e.cfg.state_dir).unwrap().load().unwrap()
}

// ------------------------------------------------------------------ worktrees

#[test]
fn clean_stale_worktree_is_quarantined_and_restorable() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-feature", Some("feature"));
    commit(&wt, "f.txt", "feature work");
    fs::create_dir_all(wt.join("target/debug")).unwrap();
    fs::write(wt.join("target/debug/big"), vec![0u8; 100_000]).unwrap();

    assert_eq!(item(&plan(&e, 0), Kind::Worktree, &wt, None).verdict, Verdict::Active);
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Worktree, &wt, None);
    assert_eq!(it.verdict, Verdict::Eligible, "{:?}", it.reasons);

    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    assert!(!wt.exists());
    assert!(!git(&r, &["worktree", "list"]).contains("app-feature"));
    // Branch and its commit survive in the repo; the branch is now free.
    assert!(git(&r, &["branch", "--list", "feature"]).contains("feature"));

    let j = journal(&e).into_iter().find(|j| j.action == Action::QuarantineWorktree).unwrap();
    let q = j.qdir.clone().unwrap();
    assert!(!q.join("tree/target").exists(), "artifacts stripped before quarantine");
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert!(wt.join("f.txt").exists());
    assert!(git(&r, &["worktree", "list"]).contains("app-feature"));
    assert_eq!(git(&wt, &["status", "--porcelain"]), "");
    assert_eq!(git(&wt, &["branch", "--show-current"]), "feature");
}

#[test]
fn dirty_untracked_and_precious_ignored_worktrees_are_protected() {
    let e = env();
    let r = repo(&e, "app");
    let dirty = add_wt(&r, "wt-dirty", Some("d"));
    fs::write(dirty.join("Cargo.toml"), "changed").unwrap();
    let untracked = add_wt(&r, "wt-untracked", Some("u"));
    fs::write(untracked.join("notes.md"), "ideas").unwrap();
    let env_file = add_wt(&r, "wt-env", Some("v"));
    fs::write(env_file.join(".env"), "SECRET=1").unwrap();
    let only_log = add_wt(&r, "wt-log", Some("l"));
    fs::write(only_log.join("build.log"), "noise").unwrap();

    let p = plan(&e, LATER);
    for (wt, needle) in [(&dirty, "uncommitted"), (&untracked, "untracked"), (&env_file, "may not be reproducible")] {
        let it = item(&p, Kind::Worktree, wt, None);
        assert_eq!(it.verdict, Verdict::Protected, "{}", wt.display());
        assert!(it.reasons.iter().any(|r| r.contains(needle)), "{:?}", it.reasons);
    }
    assert_eq!(item(&p, Kind::Worktree, &only_log, None).verdict, Verdict::Eligible);
}

#[test]
fn locks_live_process_and_keep_marker_protect() {
    let e = env();
    let r = repo(&e, "app");
    let me = std::process::id();
    let start = tree_gc::procs::pid_start_ticks(me as i32).unwrap();

    let live = add_wt(&r, "agent-live", Some("agent-live"));
    git(&r, &["worktree", "lock", "--reason", &format!("claude agent x (pid {me} start {start})"), live.to_str().unwrap()]);

    let mut child = Command::new("true").spawn().unwrap();
    let dead_pid = child.id();
    child.wait().unwrap();
    let dead = add_wt(&r, "agent-dead", Some("agent-dead"));
    git(&r, &["worktree", "lock", "--reason", &format!("claude agent y (pid {dead_pid} start 1)"), dead.to_str().unwrap()]);

    let manual = add_wt(&r, "manual-lock", Some("m"));
    git(&r, &["worktree", "lock", "--reason", "on usb disk", manual.to_str().unwrap()]);

    let kept = add_wt(&r, "kept", Some("k"));
    fs::write(kept.join(".tree-gc-keep"), "").unwrap();
    git(&kept, &["add", ".tree-gc-keep"]);
    git(&kept, &["commit", "-qm", "keep"]);

    let busy = add_wt(&r, "busy", Some("b"));
    let mut sleeper = Command::new("sleep").arg("30").current_dir(&busy).stdout(Stdio::null()).spawn().unwrap();

    let p = plan(&e, LATER);
    let verdict = |w: &Path| item(&p, Kind::Worktree, w, None).clone();
    assert_eq!(verdict(&live).verdict, Verdict::Protected);
    assert_eq!(verdict(&manual).verdict, Verdict::Protected);
    assert_eq!(verdict(&kept).verdict, Verdict::Protected);
    let b = verdict(&busy);
    assert_eq!(b.verdict, Verdict::Protected);
    assert!(b.reasons.iter().any(|r| r.contains("in use by pid")), "{:?}", b.reasons);
    let d = verdict(&dead);
    assert_eq!(d.verdict, Verdict::Eligible, "{:?}", d.reasons);
    assert!(d.reasons.iter().any(|r| r.contains("lock is stale")));
    sleeper.kill().ok();
    sleeper.wait().ok();
}

#[test]
fn detached_worktree_commits_survive_as_archive_ref() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "detached", None);
    let sha = commit(&wt, "orphan.txt", "orphan work");
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Worktree, &wt, None);
    assert_eq!(it.verdict, Verdict::Eligible, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("1 commit(s) on no branch")));
    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    let refs = git(&r, &["for-each-ref", "--format=%(objectname)", "refs/tree-gc/"]);
    assert!(refs.contains(&sha), "orphan commit must remain referenced: {refs}");
}

#[test]
fn missing_worktree_dir_prunes_metadata_reversibly() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "gone", None);
    let sha = commit(&wt, "g.txt", "will vanish");
    fs::remove_dir_all(&wt).unwrap();
    let p = plan(&e, LATER);
    let it = item(&p, Kind::StaleWorktreeMeta, &wt, None);
    assert_eq!(it.verdict, Verdict::Eligible, "{:?}", it.reasons);
    apply_later(&e, &p);
    assert!(!git(&r, &["worktree", "list", "--porcelain"]).contains("/gone"));
    assert!(git(&r, &["for-each-ref", "refs/tree-gc/"]).contains(&sha));
    let j = journal(&e).into_iter().find(|j| j.action == Action::PruneWorktreeMeta).unwrap();
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert!(git(&r, &["worktree", "list", "--porcelain"]).contains("/gone"));
}

// ------------------------------------------------------------------ branches

#[test]
fn branch_policy_merged_squashed_unique_checked_out() {
    let e = env();
    let r = repo(&e, "app");
    // merged: fast-forward ancestor of main
    git(&r, &["branch", "merged"]);
    // squash-merged: two commits, applied to main as one
    git(&r, &["checkout", "-q", "-b", "squashed"]);
    commit(&r, "s1.txt", "s1");
    commit(&r, "s2.txt", "s2");
    git(&r, &["checkout", "-q", "main"]);
    git(&r, &["merge", "-q", "--squash", "squashed"]);
    git(&r, &["commit", "-qm", "squash"]);
    // unique local work
    git(&r, &["checkout", "-q", "-b", "precious"]);
    let precious_sha = commit(&r, "p.txt", "precious");
    git(&r, &["checkout", "-q", "main"]);
    // pushed but unmerged: contained in a remote ref
    git(&r, &["checkout", "-q", "-b", "pushed"]);
    commit(&r, "x.txt", "pushed");
    git(&r, &["push", "-q", "origin", "pushed"]);
    git(&r, &["checkout", "-q", "main"]);
    // checked out in a worktree
    add_wt(&r, "wt-co", Some("checked-out"));

    let p = plan(&e, LATER);
    let b = |n: &str| item(&p, Kind::Branch, &r, Some(n)).clone();
    assert_eq!(b("merged").verdict, Verdict::Eligible, "{:?}", b("merged").reasons);
    assert_eq!(b("squashed").verdict, Verdict::Eligible, "{:?}", b("squashed").reasons);
    assert_eq!(b("pushed").verdict, Verdict::Eligible, "{:?}", b("pushed").reasons);
    assert_eq!(b("precious").verdict, Verdict::Protected);
    assert!(b("precious").reasons[0].contains("1 commit(s) not merged and not pushed"));
    assert_eq!(b("checked-out").verdict, Verdict::Protected);
    assert_eq!(b("main").verdict, Verdict::Protected);
    // Fresh branches are only Active today.
    assert_eq!(item(&plan(&e, 0), Kind::Branch, &r, Some("merged")).verdict, Verdict::Active);

    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    let heads = git(&r, &["branch", "--format=%(refname:short)"]);
    assert!(!heads.contains("merged") && !heads.contains("squashed"));
    assert!(heads.contains("precious") && heads.contains("main"));
    assert_eq!(git(&r, &["rev-parse", "precious"]), precious_sha);

    let j = journal(&e).into_iter().find(|j| j.branch.as_deref() == Some("squashed")).unwrap();
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert!(git(&r, &["branch", "--list", "squashed"]).contains("squashed"));
}

#[test]
fn branch_moved_after_plan_is_skipped() {
    let e = env();
    let r = repo(&e, "app");
    git(&r, &["branch", "racy"]);
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Branch, &r, Some("racy")).verdict, Verdict::Eligible);
    // Someone commits to it between plan and apply.
    git(&r, &["checkout", "-q", "racy"]);
    commit(&r, "new.txt", "new work");
    git(&r, &["checkout", "-q", "main"]);
    let o = apply_later(&e, &p);
    assert!(o.done.iter().all(|d| d.branch.as_deref() != Some("racy")));
    assert!(git(&r, &["branch", "--list", "racy"]).contains("racy"));
}

// ------------------------------------------------------------------ artifacts

#[test]
fn artifacts_require_marker_and_gitignore() {
    let e = env();
    let r = repo(&e, "app");
    let target = r.join("target");
    fs::create_dir_all(target.join("debug")).unwrap();
    fs::write(target.join("debug/bin"), vec![1u8; 50_000]).unwrap();

    // node_modules without package.json is not recognised at all.
    let stray = e.projects.join("stray/node_modules");
    fs::create_dir_all(&stray).unwrap();
    // target/ that is NOT ignored (committed vendored content)
    let r2 = repo(&e, "lib");
    fs::write(r2.join(".gitignore"), "").unwrap();
    cargo_out(&r2.join("target"));
    fs::write(r2.join("target/keep.txt"), "tracked").unwrap();
    git(&r2, &["add", "-A"]);
    git(&r2, &["commit", "-qm", "track target"]);

    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Artifact, &target, None).verdict, Verdict::Eligible);
    assert!(!p.items.iter().any(|i| i.path == stray));
    let t2 = item(&p, Kind::Artifact, &r2.join("target"), None);
    assert_eq!(t2.verdict, Verdict::Protected, "{:?}", t2.reasons);
    assert_eq!(item(&plan(&e, 0), Kind::Artifact, &target, None).verdict, Verdict::Active);

    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    assert!(!target.exists());
    assert!(r2.join("target/keep.txt").exists());
    assert!(r.join("Cargo.toml").exists());
}

#[test]
fn artifact_symlinked_from_path_or_in_use_is_protected() {
    let e = env();
    let r = repo(&e, "app");
    let target = r.join("target");
    cargo_out(&target);
    let f = fs::File::open(r.join("Cargo.toml")).unwrap();
    // Holding a file open inside target protects it.
    fs::write(target.join("held"), "x").unwrap();
    let mut holder = Command::new("sleep").arg("30").current_dir(&target).spawn().unwrap();
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Artifact, &target, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    holder.kill().ok();
    holder.wait().ok();
    drop(f);
}

// ------------------------------------------------------------------ tmp + scratch

#[test]
fn tmp_entries_age_out_but_unpushed_repos_are_protected() {
    let e = env();
    let junk = e.tmp.join("build-xyz");
    fs::create_dir_all(junk.join("sub")).unwrap();
    fs::write(junk.join("sub/a.o"), "obj").unwrap();
    let clone = e.tmp.join("scratch-clone");
    fs::create_dir_all(&clone).unwrap();
    git(&clone, &["init", "-q"]);
    commit(&clone, "a", "local only");
    let excluded = e.tmp.join("systemd-private-abc");
    fs::create_dir_all(&excluded).unwrap();

    assert_eq!(item(&plan(&e, 0), Kind::TmpEntry, &junk, None).verdict, Verdict::Active);
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::TmpEntry, &junk, None).verdict, Verdict::Eligible);
    let c = item(&p, Kind::TmpEntry, &clone, None);
    assert_eq!(c.verdict, Verdict::Protected);
    assert!(c.reasons.iter().any(|r| r.contains("not on any trusted remote")), "{:?}", c.reasons);
    assert!(!p.items.iter().any(|i| i.path == excluded));

    apply_later(&e, &p);
    assert!(!junk.exists() && clone.exists() && excluded.exists());
    let j = journal(&e).into_iter().find(|j| j.path == junk).unwrap();
    assert_eq!(j.status, JStatus::Quarantined);
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert!(junk.join("sub/a.o").exists());
}

#[test]
fn scratch_keeps_newest_window_honors_excludes_and_delete_action() {
    let e = env_with(&format!(
        "[[scratch]]\nname = \"cache\"\npath = \"{}\"\nstale_days = 7\naction = \"delete\"\n",
        "CACHE"
    ));
    let mut e = e;
    let cache = e.base.join("cache");
    fs::create_dir_all(&cache).unwrap();
    e.cfg.scratch[1].path = cache.clone();
    for n in 0..5 {
        fs::create_dir_all(e.scratch.join(format!("session-{n}"))).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100)); // distinct ctimes
    }
    fs::write(e.scratch.join("state.db"), "db").unwrap();
    fs::write(cache.join("blob"), "c").unwrap();

    let p = plan(&e, LATER);
    let s: Vec<&Item> = p.items.iter().filter(|i| i.kind == Kind::Scratch && i.path.starts_with(&e.scratch)).collect();
    assert_eq!(s.len(), 5, "state.db excluded");
    assert_eq!(s.iter().filter(|i| i.verdict == Verdict::Eligible).count(), 3);
    let kept: Vec<_> = s.iter().filter(|i| i.verdict == Verdict::Active).map(|i| i.path.clone()).collect();
    assert!(kept.contains(&e.scratch.join("session-4")) && kept.contains(&e.scratch.join("session-3")), "newest kept: {kept:?}");
    let blob = item(&p, Kind::Scratch, &cache.join("blob"), None);
    assert_eq!(blob.action, Some(Action::DeletePath));

    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    assert!(!e.scratch.join("session-0").exists() && e.scratch.join("session-4").exists());
    assert!(e.scratch.join("state.db").exists());
    assert!(!cache.join("blob").exists());
}

// ------------------------------------------------------------------ global safety

#[test]
fn shadow_mode_refuses_to_act() {
    let mut e = env();
    let r = repo(&e, "app");
    git(&r, &["branch", "old"]);
    e.cfg.enforce = false;
    let p = plan(&e, LATER);
    assert!(p.eligible().count() > 0);
    let opts = ApplyOpts { now: now_epoch() + LATER * DAY, max_actions: 100, max_bytes: u64::MAX, kinds: None };
    assert!(exec::apply(&e.cfg, &p, &opts).is_err());
    assert!(exec::purge(&e.cfg, now_epoch() + 365 * DAY).is_err());
    assert!(git(&r, &["branch", "--list", "old"]).contains("old"));
}

#[test]
fn enforce_kinds_limits_staged_rollout() {
    let mut e = env();
    let r = repo(&e, "app");
    git(&r, &["branch", "old"]);
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    e.cfg.enforce_kinds = vec![Kind::Branch];
    let p = plan(&e, LATER);
    let o = apply_later(&e, &p);
    assert!(o.done.iter().all(|d| d.kind == Kind::Branch));
    assert!(e.tmp.join("junk").exists());
}

#[test]
fn purge_only_after_ttl() {
    let e = env();
    let junk = e.tmp.join("old-junk");
    fs::create_dir_all(&junk).unwrap();
    let p = plan(&e, LATER);
    apply_later(&e, &p);
    let j = journal(&e).into_iter().find(|j| j.path == junk).unwrap();
    let q = j.qdir.clone().unwrap();
    assert!(q.exists());
    assert_eq!(exec::purge(&e.cfg, j.ts + 13 * DAY).unwrap().purged.len(), 0);
    assert!(q.exists());
    assert_eq!(exec::purge(&e.cfg, j.ts + 15 * DAY).unwrap().purged.len(), 1);
    assert!(!q.exists());
    assert!(exec::restore(&e.cfg, &j.jid).is_err());
}

#[test]
fn symlinks_are_never_followed() {
    let e = env();
    let outside = e.base.join("outside-precious");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("data"), "irreplaceable").unwrap();
    std::os::unix::fs::symlink(&outside, e.tmp.join("link-to-precious")).unwrap();
    let r = repo(&e, "app");
    std::os::unix::fs::symlink(&outside, r.join("target")).unwrap();

    let p = plan(&e, LATER);
    assert!(!p.items.iter().any(|i| i.kind == Kind::Artifact && i.path == r.join("target")));
    apply_later(&e, &p);
    assert!(outside.join("data").exists(), "symlink target must survive");
}

#[test]
fn bundled_config_parses() {
    let c = Config::builtin();
    assert!(!c.enforce, "must ship in shadow mode");
    assert!(c.scratch.iter().filter(|s| s.name.contains("transcripts")).all(|s| !s.enabled));
}

#[test]
fn artifact_containing_nested_repo_or_keep_marker_is_protected() {
    let e = env();
    let r = repo(&e, "app");
    cargo_out(&r.join("target"));
    let nested = r.join("target/tmp/verify-clone");
    fs::create_dir_all(&nested).unwrap();
    git(&nested, &["init", "-q"]);
    commit(&nested, "w", "work only here");
    let r2 = repo(&e, "app2");
    fs::create_dir_all(r2.join("target/release")).unwrap();
    fs::write(r2.join("target/release/.tree-gc-keep"), "").unwrap();

    let p = plan(&e, LATER);
    let a = item(&p, Kind::Artifact, &r.join("target"), None);
    assert_eq!(a.verdict, Verdict::Protected, "{:?}", a.reasons);
    assert!(a.reasons[0].contains("not on any trusted remote"), "{:?}", a.reasons);
    assert_eq!(item(&p, Kind::Artifact, &r2.join("target"), None).verdict, Verdict::Protected);
    apply_later(&e, &p);
    assert!(nested.join(".git").exists());
}

#[test]
fn deleting_artifacts_does_not_make_their_worktree_look_active() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("feat"));
    fs::create_dir_all(wt.join("target/debug")).unwrap();
    fs::write(wt.join("target/debug/x"), vec![0u8; 10_000]).unwrap();
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Artifact, &wt.join("target"), None).verdict, Verdict::Eligible);
    assert_eq!(item(&p, Kind::Worktree, &wt, None).verdict, Verdict::Eligible);
    let o = apply_later(&e, &p);
    assert!(o.skipped.is_empty() && o.failed.is_empty(), "skipped={:?} failed={:?}", o.skipped, o.failed);
    assert!(o.done.iter().any(|d| d.kind == Kind::Artifact));
    assert!(o.done.iter().any(|d| d.kind == Kind::Worktree));
}

#[test]
fn clean_build_script_clone_inside_artifact_does_not_block() {
    let e = env();
    let r = repo(&e, "app");
    // Like boring-sys: a clone of an upstream repo inside OUT_DIR.
    let out = r.join("target/release/build/boring-sys-abc/out");
    fs::create_dir_all(&out).unwrap();
    let upstream = e.base.join("upstream.git");
    git(&e.base, &["clone", "-q", "--bare", r.to_str().unwrap(), upstream.to_str().unwrap()]);
    git(&out, &["clone", "-q", upstream.to_str().unwrap(), "boringssl"]);
    let p = plan(&e, LATER);
    let a = item(&p, Kind::Artifact, &r.join("target"), None);
    assert_eq!(a.verdict, Verdict::Eligible, "{:?}", a.reasons);

    // boring-sys style: `git init` + copied sources (untracked) in OUT_DIR.
    let r2 = repo(&e, "app2");
    let ssl = r2.join("target/debug/build/boring-sys-def/out/boringssl");
    fs::create_dir_all(&ssl).unwrap();
    git(&ssl, &["init", "-q"]);
    fs::write(ssl.join("CMakeLists.txt"), "x").unwrap();
    // ...but the same thing outside OUT_DIR is protected.
    let r3 = repo(&e, "app3");
    cargo_out(&r3.join("target"));
    let elsewhere = r3.join("target/scratch-work");
    fs::create_dir_all(&elsewhere).unwrap();
    git(&elsewhere, &["init", "-q"]);
    fs::write(elsewhere.join("notes.md"), "x").unwrap();
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Artifact, &r2.join("target"), None).verdict, Verdict::Eligible);
    assert_eq!(item(&p, Kind::Artifact, &r3.join("target"), None).verdict, Verdict::Protected);
}

// ------------------------------------------------------------------ robustness gaps

#[test]
fn two_unpushed_branches_do_not_vouch_for_each_other() {
    let e = env();
    let r = repo(&e, "app");
    git(&r, &["checkout", "-q", "-b", "a"]);
    commit(&r, "w.txt", "local work");
    git(&r, &["branch", "b"]); // same unique commit
    git(&r, &["checkout", "-q", "main"]);
    let p = plan(&e, LATER);
    for b in ["a", "b"] {
        let it = item(&p, Kind::Branch, &r, Some(b));
        assert_eq!(it.verdict, Verdict::Protected, "{b}: {:?}", it.reasons);
    }
}

#[test]
fn paths_referenced_by_config_files_are_protected() {
    let mut e = env();
    let r = repo(&e, "app");
    let target = r.join("target");
    fs::create_dir_all(target.join("release")).unwrap();
    let r2 = repo(&e, "app2");
    fs::create_dir_all(r2.join("target2")).unwrap();
    cargo_out(&r2.join("target")); // sibling-prefix must not match
    let unit = e.base.join("units");
    fs::create_dir_all(&unit).unwrap();
    fs::write(
        unit.join("svc.service"),
        format!("ExecStart={}/release/server --flag\nExecStart={}/target2/x\n", target.display(), r2.display()),
    )
    .unwrap();
    e.cfg.reference_files = vec![unit];
    let p = plan(&e, LATER);
    let a = item(&p, Kind::Artifact, &target, None);
    assert_eq!(a.verdict, Verdict::Protected, "{:?}", a.reasons);
    assert!(a.reasons[0].contains("referenced in"));
    assert_eq!(item(&p, Kind::Artifact, &r2.join("target"), None).verdict, Verdict::Eligible);
}

#[test]
fn recent_agent_session_keeps_worktree_active() {
    let mut e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "agent-wt", Some("agent"));
    let sessions = e.base.join("claude-projects");
    let enc: String = wt.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    fs::create_dir_all(sessions.join(&enc)).unwrap();
    e.cfg.agent_session_dirs = vec![sessions.clone()];
    // Simulate: the session transcript was written "today" relative to the
    // future clock, by evaluating with a clock only 1 day ahead of it.
    let p = plan(&e, 1);
    assert_eq!(item(&p, Kind::Worktree, &wt, None).verdict, Verdict::Active);
    // A session in the *parent* project must not keep the agent worktree alive.
    fs::remove_dir_all(sessions.join(&enc)).unwrap();
    let enc_parent: String = r.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    fs::create_dir_all(sessions.join(enc_parent)).unwrap();
    assert_eq!(item(&plan(&e, LATER), Kind::Worktree, &wt, None).verdict, Verdict::Eligible);
}

#[test]
fn worktree_with_unpushed_submodule_commits_is_protected() {
    let e = env();
    let lib = repo(&e, "lib");
    let r = repo(&e, "app");
    git(&r, &["-c", "protocol.file.allow=always", "submodule", "add", "-q", lib.to_str().unwrap(), "vendor/lib"]);
    git(&r, &["commit", "-qm", "add sub"]);
    let wt = add_wt(&r, "app-wt", Some("feat"));
    git(&wt, &["-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init"]);
    let sub = wt.join("vendor/lib");
    git(&sub, &["checkout", "-q", "-b", "subwork"]);
    commit(&sub, "s.txt", "unpushed submodule work");
    // Record it in the superproject so the worktree itself is clean.
    git(&wt, &["add", "vendor/lib"]);
    git(&wt, &["commit", "-qm", "bump sub"]);
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Worktree, &wt, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("submodule vendor/lib")), "{:?}", it.reasons);
}

#[test]
fn missing_worktree_on_unmounted_drive_is_protected() {
    let mut e = env();
    let r = repo(&e, "app");
    let mnt = e.base.join("media");
    let drive = mnt.join("usb");
    fs::create_dir_all(&drive).unwrap();
    let wt = drive.join("wt");
    git(&r, &["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "usb"]);
    fs::remove_dir_all(&drive).unwrap(); // "unplugged": parent gone too
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::StaleWorktreeMeta, &wt, None).verdict, Verdict::Protected);
    // Parent present but under a removable prefix: still protected.
    fs::create_dir_all(&drive).unwrap();
    e.cfg.removable_prefixes = vec![mnt];
    let p = plan(&e, LATER);
    let it = item(&p, Kind::StaleWorktreeMeta, &wt, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
}

#[test]
fn worktree_whose_ignored_target_hides_unpushed_repo_is_protected() {
    let mut e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("feat"));
    cargo_out(&wt.join("target"));
    let nested = wt.join("target/tmp/experiment");
    fs::create_dir_all(&nested).unwrap();
    git(&nested, &["init", "-q"]);
    commit(&nested, "idea.txt", "unpushed experiment");
    e.cfg.artifacts.enabled = false; // isolate the worktree path
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Worktree, &wt, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("target") && r.contains("not on any trusted remote")), "{:?}", it.reasons);
    apply_later(&e, &p);
    assert!(nested.join("idea.txt").exists());
}

// ================================================================== adversarial review regressions
// Each test reproduces a finding from the independent safety review and
// asserts the *safe* outcome.

#[test]
fn adv01_cachedir_tag_alone_never_means_deletable() {
    let e = env();
    let r = repo(&e, "ml");
    fs::write(r.join(".gitignore"), "target/\ndata/\n").unwrap();
    git(&r, &["commit", "-qam", "ignore data"]);
    let data = r.join("data");
    cargo_out(&data); // a backup-exclusion tag on a dataset dir
    fs::write(data.join("experiment-results.csv"), "irreplaceable").unwrap();
    let notes = e.projects.join("notes/archive");
    cargo_out(&notes);
    fs::write(notes.join("thesis.tex"), "irreplaceable").unwrap();
    let p = plan(&e, LATER);
    apply_later(&e, &p);
    assert!(data.join("experiment-results.csv").exists());
    assert!(notes.join("thesis.tex").exists());
}

#[test]
fn adv02_artifact_that_is_itself_a_repo_is_protected() {
    let e = env();
    let r = repo(&e, "app");
    let t = r.join("target");
    cargo_out(&t);
    git(&t, &["init", "-q"]);
    commit(&t, "deploy-notes.md", "only copy");
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Artifact, &t, None).verdict, Verdict::Protected);
    apply_later(&e, &p);
    assert!(t.join("deploy-notes.md").exists());
}

#[test]
fn adv03_strip_requires_real_artifact_identity() {
    let mut e = env();
    let r = repo(&e, "web");
    git(&r, &["rm", "-q", "Cargo.toml"]);
    git(&r, &["commit", "-qm", "no cargo"]);
    let wt = add_wt(&r, "web-wt", Some("feat"));
    fs::create_dir_all(wt.join("target")).unwrap();
    fs::write(wt.join("target/deploy-hosts.yaml"), "hand-written").unwrap();
    e.cfg.artifacts.enabled = false;
    let p = plan(&e, LATER);
    let it = item(&p, Kind::Worktree, &wt, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    apply_later(&e, &p);
    assert!(wt.join("target/deploy-hosts.yaml").exists());
}

#[test]
fn adv04_assume_unchanged_and_skip_worktree_edits_protect() {
    let e = env();
    let r = repo(&e, "app");
    let a = add_wt(&r, "wt-assume", Some("a"));
    git(&a, &["update-index", "--assume-unchanged", "Cargo.toml"]);
    fs::write(a.join("Cargo.toml"), "LOCAL EDITS").unwrap();
    let s = add_wt(&r, "wt-skip", Some("s"));
    git(&s, &["update-index", "--skip-worktree", "Cargo.toml"]);
    fs::write(s.join("Cargo.toml"), "local override").unwrap();
    let clean = add_wt(&r, "wt-flag-only", Some("c"));
    git(&clean, &["update-index", "--skip-worktree", "Cargo.toml"]); // flagged but unchanged
    let p = plan(&e, LATER);
    for w in [&a, &s] {
        let it = item(&p, Kind::Worktree, w, None);
        assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
        assert!(it.reasons.iter().any(|r| r.contains("assume-unchanged/skip-worktree")));
    }
    assert_eq!(item(&p, Kind::Worktree, &clean, None).verdict, Verdict::Eligible);
}

/// Not a real test: when re-executed by `spawn_socket_holder`, binds a unix
/// socket at $TGC_HOLD_SOCK (relative to the cwd it was started in), moves its
/// own cwd to `/` (so only the socket ties it to the dir) and waits.
#[test]
#[ignore]
fn helper_hold_unix_socket() {
    let Ok(path) = std::env::var("TGC_HOLD_SOCK") else { return };
    let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::env::set_current_dir("/").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

/// Spawn a separate process (this test binary) that holds a bound unix socket
/// `sock` (absolute, or relative to `cwd`). Waits until the socket exists.
fn spawn_socket_holder(cwd: &Path, sock: &str) -> std::process::Child {
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "helper_hold_unix_socket", "--test-threads=1"])
        .env("TGC_HOLD_SOCK", sock)
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let target = cwd.join(sock);
    for _ in 0..100 {
        if target.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(target.exists(), "socket holder did not bind {}", target.display());
    std::thread::sleep(std::time::Duration::from_millis(200)); // let it chdir away
    child
}

#[test]
fn adv05_dir_with_live_unix_socket_is_protected() {
    let e = env();
    let d = e.tmp.join("emacs1000");
    fs::create_dir_all(&d).unwrap();
    let sock = d.join("server");
    let mut child = spawn_socket_holder(Path::new("/"), sock.to_str().unwrap());
    let p = plan(&e, LATER);
    let it = item(&p, Kind::TmpEntry, &d, None);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    // Protected *because of the socket*, not the holder's cwd/fds.
    assert!(it.reasons.iter().any(|r| r.contains("socket")), "{:?}", it.reasons);
}

#[test]
fn adv06_tmp_repo_with_linked_worktree_elsewhere_is_protected() {
    let e = env();
    let seed = e.base.join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    commit(&seed, "a", "a");
    let origin = e.base.join("o.git");
    git(&e.base, &["clone", "-q", "--bare", seed.to_str().unwrap(), origin.to_str().unwrap()]);
    let tr = e.tmp.join("quick-clone");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), tr.to_str().unwrap()]);
    let outside = e.base.join("elsewhere-wt");
    git(&tr, &["worktree", "add", "-q", "--detach", outside.to_str().unwrap()]);
    commit(&outside, "w.txt", "detached unpushed work");
    let p = plan(&e, LATER);
    let it = item(&p, Kind::TmpEntry, &tr, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    apply_later(&e, &p);
    assert!(tr.exists());
}

#[test]
fn adv07_restore_works_after_git_worktree_prune() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("feat"));
    let p = plan(&e, LATER);
    apply_later(&e, &p);
    assert!(!wt.exists());
    git(&r, &["worktree", "prune"]);
    let j = journal(&e).into_iter().find(|j| j.kind == Kind::Worktree).unwrap();
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert_eq!(git(&wt, &["branch", "--show-current"]), "feat");
}

#[test]
fn adv10_jetbrains_shelf_protects_worktree() {
    let e = env();
    let r = repo(&e, "app");
    fs::write(r.join(".gitignore"), "target/\n.env\n*.log\n.idea/\n").unwrap();
    git(&r, &["commit", "-qam", "ign idea"]);
    let wt = add_wt(&r, "app-wt", Some("feat"));
    fs::create_dir_all(wt.join(".idea/shelf")).unwrap();
    fs::write(wt.join(".idea/shelf/WIP.patch"), "shelved").unwrap();
    assert_eq!(item(&plan(&e, LATER), Kind::Worktree, &wt, None).verdict, Verdict::Protected);
}

#[test]
fn adv11_tag_and_custom_ref_only_commits_protect_tmp_repo() {
    let e = env();
    let seed = e.base.join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    commit(&seed, "a", "a");
    let origin = e.base.join("o.git");
    git(&e.base, &["clone", "-q", "--bare", seed.to_str().unwrap(), origin.to_str().unwrap()]);
    let tr = e.tmp.join("rel-prep");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), tr.to_str().unwrap()]);
    git(&tr, &["checkout", "-q", "-b", "tmpwork"]);
    commit(&tr, "b", "release tweak");
    git(&tr, &["update-ref", "refs/jj/keep/x", "HEAD"]);
    git(&tr, &["checkout", "-q", "main"]);
    git(&tr, &["branch", "-D", "tmpwork"]);
    let it = item(&plan(&e, LATER), Kind::TmpEntry, &tr, None).clone();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
}

#[test]
fn adv12_reference_file_with_non_utf8_byte_still_counts() {
    let mut e = env();
    let r = repo(&e, "app");
    let target = r.join("target");
    fs::create_dir_all(target.join("release")).unwrap();
    let rc = e.base.join("bashrc");
    let mut bytes = b"# caf\xe9\nalias srv=".to_vec();
    bytes.extend_from_slice(target.join("release/server").to_str().unwrap().as_bytes());
    fs::write(&rc, bytes).unwrap();
    e.cfg.reference_files = vec![rc];
    assert_eq!(item(&plan(&e, LATER), Kind::Artifact, &target, None).verdict, Verdict::Protected);
}

fn bind(src: &Path, dst: &Path) -> bool {
    Command::new("mount").arg("--bind").arg(src).arg(dst).status().map(|s| s.success()).unwrap_or(false)
}

/// Needs a private mount namespace: `TGC_USERNS=1 unshare -Urm <test-binary> adv13`.
#[test]
fn adv13_mounts_below_items_block_delete_quarantine_and_purge() {
    if std::env::var("TGC_USERNS").is_err() {
        eprintln!("skipped: run under `TGC_USERNS=1 unshare -Urm`");
        return;
    }
    let e = env();
    let remote = e.base.join("remote-data");
    fs::create_dir_all(&remote).unwrap();
    fs::write(remote.join("server-file.txt"), "lives elsewhere").unwrap();
    let work = e.tmp.join("work");
    fs::create_dir_all(work.join("mnt")).unwrap();
    assert!(bind(&remote, &work.join("mnt")));
    let r = repo(&e, "app");
    let shared = e.base.join("shared-cache");
    fs::create_dir_all(&shared).unwrap();
    fs::write(shared.join("precious.bin"), "x").unwrap();
    cargo_out(&r.join("target"));
    fs::create_dir_all(r.join("target/mnt")).unwrap();
    assert!(bind(&shared, &r.join("target/mnt")));
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::TmpEntry, &work, None).verdict, Verdict::Protected);
    assert_eq!(item(&p, Kind::Artifact, &r.join("target"), None).verdict, Verdict::Protected);
    apply_later(&e, &p);
    assert!(remote.join("server-file.txt").exists());
    assert!(shared.join("precious.bin").exists());
    // Even if something with a mount below it got into quarantine, purge refuses it
    // and continues with the rest.
    let junk = e.tmp.join("junk");
    fs::create_dir_all(&junk).unwrap();
    let p = plan(&e, LATER);
    apply_later(&e, &p);
    let j = journal(&e).into_iter().find(|j| j.path == junk).unwrap();
    let q = j.qdir.clone().unwrap();
    fs::create_dir_all(q.join("payload/mnt")).unwrap();
    assert!(bind(&remote, &q.join("payload/mnt")));
    let rep = exec::purge(&e.cfg, j.ts + 15 * DAY).unwrap();
    assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
    assert!(remote.join("server-file.txt").exists());
    // Detach the binds so the TempDir can be removed (no leaked dirs in /tmp).
    for m in [q.join("payload/mnt"), r.join("target/mnt"), work.join("mnt")] {
        let _ = Command::new("umount").arg(&m).status();
    }
}

#[test]
fn adv15_worktrees_outside_roots_are_never_touched() {
    let e = env();
    let ext = e.base.join("ext-repo");
    fs::create_dir_all(&ext).unwrap();
    git(&ext, &["init", "-q"]);
    commit(&ext, "a", "a");
    let inside = e.projects.join("ext-wt");
    git(&ext, &["worktree", "add", "-q", inside.to_str().unwrap(), "-b", "w1"]);
    let far = e.base.join("not-a-root/other-wt");
    fs::create_dir_all(far.parent().unwrap()).unwrap();
    git(&ext, &["worktree", "add", "-q", far.to_str().unwrap(), "-b", "w2"]);
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Worktree, &far, None).verdict, Verdict::Protected);
    apply_later(&e, &p);
    assert!(far.exists());
}

#[test]
fn adv16_tampered_saved_plan_cannot_delete_arbitrary_dirs() {
    let e = env();
    let r = repo(&e, "app");
    cargo_out(&r.join("target"));
    let docs = e.projects.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("handbook.md"), "irreplaceable").unwrap();
    let outside = e.base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let p = plan(&e, LATER);
    let json = serde_json::to_string(&p).unwrap();
    let t = r.join("target").display().to_string();
    for victim in [&docs, &outside] {
        let tampered: Plan = serde_json::from_str(&json.replace(&t, &victim.display().to_string())).unwrap();
        apply_later(&e, &tampered);
        assert!(victim.exists(), "{}", victim.display());
    }
    assert!(docs.join("handbook.md").exists());
}

#[test]
fn adv17_branch_being_rebased_is_not_archived() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("b"));
    commit(&wt, "c.txt", "one");
    git(&wt, &["push", "-q", "origin", "b"]);
    commit(&r, "c.txt", "main-side");
    let _ = Command::new("git")
        .arg("-C")
        .arg(&wt)
        .args(["-c", "user.name=t", "-c", "user.email=t@x", "rebase", "main"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    let p = plan(&e, LATER);
    let b = item(&p, Kind::Branch, &r, Some("b"));
    assert_eq!(b.verdict, Verdict::Protected, "{:?}", b.reasons);
}

#[test]
fn adv18_bare_repo_inside_tmp_entry_is_protected() {
    let e = env();
    let d = e.tmp.join("agent-sandbox");
    fs::create_dir_all(&d).unwrap();
    git(&e.base, &["init", "-q", "--bare", d.join("remote.git").to_str().unwrap()]);
    let it = item(&plan(&e, LATER), Kind::TmpEntry, &d, None).clone();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
}

#[test]
fn adv19_submodule_path_with_space_is_checked() {
    let e = env();
    let lib = repo(&e, "lib");
    let r = repo(&e, "app");
    git(&r, &["-c", "protocol.file.allow=always", "submodule", "add", "-q", lib.to_str().unwrap(), "vendor/my lib"]);
    git(&r, &["commit", "-qm", "add sub"]);
    let wt = add_wt(&r, "app-wt", Some("feat"));
    git(&wt, &["-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init"]);
    let sub = wt.join("vendor/my lib");
    git(&sub, &["checkout", "-q", "-b", "subwork"]);
    commit(&sub, "s.txt", "unpushed");
    git(&wt, &["add", "vendor/my lib"]);
    git(&wt, &["commit", "-qm", "bump sub"]);
    let it = item(&plan(&e, LATER), Kind::Worktree, &wt, None).clone();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("vendor/my lib")));
}

#[test]
fn adv18b_moved_worktree_or_staged_index_blocks_meta_prune() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "will-move", Some("mv"));
    fs::rename(&wt, e.projects.join("moved-here")).unwrap(); // user `mv`ed it
    let wt2 = add_wt(&r, "staged-then-deleted", Some("st"));
    fs::write(wt2.join("new.rs"), "staged only").unwrap();
    git(&wt2, &["add", "new.rs"]);
    fs::remove_dir_all(&wt2).unwrap();
    let p = plan(&e, LATER);
    let a = item(&p, Kind::StaleWorktreeMeta, &wt, None);
    assert_eq!(a.verdict, Verdict::Protected, "{:?}", a.reasons);
    assert!(a.reasons.iter().any(|r| r.contains("moved")));
    let b = item(&p, Kind::StaleWorktreeMeta, &wt2, None);
    assert_eq!(b.verdict, Verdict::Protected, "{:?}", b.reasons);
    assert!(b.reasons.iter().any(|r| r.contains("staged")));
}

#[test]
fn adv_minor_journal_torn_line_and_ambiguous_restore() {
    let e = env();
    for n in ["j1", "j2"] {
        fs::create_dir_all(e.tmp.join(n)).unwrap();
    }
    let p = plan(&e, LATER);
    apply_later(&e, &p);
    let path = e.cfg.state_dir.join("journal.jsonl");
    let mut s = fs::read_to_string(&path).unwrap();
    s.push_str("{\"jid\": \"torn"); // crash mid-write
    fs::write(&path, s).unwrap();
    let entries = journal(&e);
    assert!(entries.iter().filter(|j| j.status == JStatus::Quarantined).count() >= 2);
    // A suffix shared by several entries must not silently pick one.
    assert!(exec::restore(&e.cfg, "").is_err());
    let rep = exec::purge(&e.cfg, now_epoch() + 400 * DAY).unwrap();
    assert!(rep.purged.len() >= 2 && rep.errors.is_empty());
}

#[test]
fn adv_minor_archived_branch_keeps_reflog() {
    let e = env();
    let r = repo(&e, "app");
    git(&r, &["checkout", "-q", "-b", "amended"]);
    let lost = commit(&r, "x.txt", "first try");
    git(&r, &["reset", "-q", "--hard", "main"]); // first try now only in reflog
    git(&r, &["checkout", "-q", "main"]);
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::Branch, &r, Some("amended")).verdict, Verdict::Eligible);
    apply_later(&e, &p);
    let aref = git(&r, &["for-each-ref", "--format=%(refname)", "refs/tree-gc/archive/heads/amended"]);
    assert!(!aref.is_empty());
    // The archive ref's *own* reflog (copied from the branch) still holds it.
    let reflog = git(&r, &["log", "-g", "--format=%H", &aref]);
    assert!(reflog.contains(&lost), "reflog-only commit must remain referenced: {reflog}");
}

// ================================================================== second review round

fn seed_origin(e: &Env) -> PathBuf {
    let seed = e.base.join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    commit(&seed, "a", "a");
    let origin = e.base.join("o.git");
    git(&e.base, &["clone", "-q", "--bare", seed.to_str().unwrap(), origin.to_str().unwrap()]);
    origin
}

#[test]
fn r2_b1_relative_socket_bind_is_live() {
    let e = env();
    let d = e.tmp.join("app-ipc");
    fs::create_dir_all(&d).unwrap();
    // Bound by a *relative* name: /proc/net/unix shows just "srv.sock".
    let mut child = spawn_socket_holder(&d, "srv.sock");
    let p = plan(&e, LATER);
    let it = item(&p, Kind::TmpEntry, &d, None).clone();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("live unix socket")), "{:?}", it.reasons);
    // Once the holder is gone, the leftover socket file no longer protects it.
    assert_eq!(item(&plan(&e, LATER), Kind::TmpEntry, &d, None).verdict, Verdict::Eligible);
}

#[test]
fn r2_b2_tampered_plan_cannot_reach_below_tmp_top_level() {
    let e = env();
    let decoy = e.tmp.join("decoy");
    fs::create_dir_all(&decoy).unwrap();
    let deep = e.tmp.join("systemd-private-abc/inner");
    fs::create_dir_all(&deep).unwrap();
    let p = plan(&e, LATER);
    let json = serde_json::to_string(&p).unwrap().replace(&decoy.display().to_string(), &deep.display().to_string());
    apply_later(&e, &serde_json::from_str(&json).unwrap());
    assert!(deep.exists());
}

#[test]
fn r2_b3_update_refs_rebase_protects_stacked_branch() {
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("b1"));
    commit(&wt, "c.txt", "one");
    git(&wt, &["checkout", "-q", "-b", "b2"]);
    commit(&wt, "d.txt", "two");
    git(&wt, &["push", "-q", "origin", "b1", "b2"]);
    commit(&r, "c.txt", "main-side");
    let _ = Command::new("git")
        .arg("-C")
        .arg(&wt)
        .args(["-c", "user.name=t", "-c", "user.email=t@x", "rebase", "--update-refs", "main"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    let p = plan(&e, LATER);
    let b1 = item(&p, Kind::Branch, &r, Some("b1"));
    assert_eq!(b1.verdict, Verdict::Protected, "{:?}", b1.reasons);
}

#[test]
fn r2_b4_deinited_submodule_history_protects_worktree() {
    let e = env();
    let lib = repo(&e, "lib");
    let r = repo(&e, "app");
    git(&r, &["-c", "protocol.file.allow=always", "submodule", "add", "-q", lib.to_str().unwrap(), "vendor/lib"]);
    git(&r, &["commit", "-qm", "add sub"]);
    let wt = add_wt(&r, "app-wt", Some("feat"));
    git(&wt, &["-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init"]);
    let sub = wt.join("vendor/lib");
    git(&sub, &["checkout", "-q", "-b", "subwork"]);
    commit(&sub, "s.txt", "unpushed");
    git(&wt, &["submodule", "deinit", "-q", "-f", "vendor/lib"]);
    let it = item(&plan(&e, LATER), Kind::Worktree, &wt, None).clone();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("submodule git dir")), "{:?}", it.reasons);
}

#[test]
fn r2_b5_old_reflog_entries_do_not_protect_forever() {
    let e = env();
    let origin = seed_origin(&e);
    let tr = e.tmp.join("readonly-clone");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), tr.to_str().unwrap()]);
    let up = e.base.join("up");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), up.to_str().unwrap()]);
    git(&up, &["commit", "-q", "--amend", "-m", "rewritten"]);
    git(&up, &["push", "-q", "-f", "origin", "main"]);
    git(&tr, &["-c", "pull.rebase=true", "pull", "-q"]);
    // Within the reflog window: protected (it could be someone's amended work)...
    let soon = build_plan(&e.cfg, now_epoch() + 8 * DAY).unwrap();
    assert_eq!(item(&soon, Kind::TmpEntry, &tr, None).verdict, Verdict::Protected);
    // ...but not forever.
    assert_eq!(item(&plan(&e, LATER), Kind::TmpEntry, &tr, None).verdict, Verdict::Eligible);
}

#[test]
fn r2_b6_worktrees_in_tmp_roots_are_collectable() {
    let e = env();
    let r = repo(&e, "app");
    let gone = e.tmp.join("agent-wt-gone");
    git(&r, &["worktree", "add", "-q", gone.to_str().unwrap(), "-b", "ag1"]);
    fs::remove_dir_all(&gone).unwrap();
    let live = e.tmp.join("agent-wt-live");
    git(&r, &["worktree", "add", "-q", live.to_str().unwrap(), "-b", "ag2"]);
    let p = plan(&e, LATER);
    assert_eq!(item(&p, Kind::StaleWorktreeMeta, &gone, None).verdict, Verdict::Eligible);
    assert_eq!(item(&p, Kind::Worktree, &live, None).verdict, Verdict::Eligible);
    // ...and the tmp policy defers to the worktree policy for it.
    assert_eq!(item(&p, Kind::TmpEntry, &live, None).verdict, Verdict::Protected);
    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    assert!(!live.exists());
}

#[test]
fn r2_b7_sparse_checkout_is_not_over_protected() {
    let e = env();
    let r = repo(&e, "mono");
    fs::create_dir_all(r.join("big")).unwrap();
    fs::create_dir_all(r.join("app")).unwrap();
    for i in 0..5100 {
        fs::write(r.join(format!("big/f{i}")), "x").unwrap();
    }
    fs::write(r.join("app/a"), "x").unwrap();
    git(&r, &["add", "."]);
    git(&r, &["commit", "-qm", "big"]);
    git(&r, &["push", "-q", "origin", "main"]);
    let wt = add_wt(&r, "mono-wt", Some("feat"));
    git(&wt, &["sparse-checkout", "set", "app"]);
    let it = item(&plan(&e, LATER), Kind::Worktree, &wt, None).clone();
    assert_eq!(it.verdict, Verdict::Eligible, "{:?}", it.reasons);
}

#[test]
fn r2_b9_forged_pressure_flag_is_ignored() {
    let e = env();
    let r = repo(&e, "app");
    let t = r.join("target");
    cargo_out(&t);
    let now = now_epoch() + 5 * DAY;
    let p = build_plan(&e.cfg, now).unwrap();
    assert_eq!(item(&p, Kind::Artifact, &t, None).verdict, Verdict::Active);
    let mut v: serde_json::Value = serde_json::to_value(&p).unwrap();
    for it in v["items"].as_array_mut().unwrap() {
        if it["kind"] == "artifact" {
            it["pressure"] = true.into();
            it["verdict"] = "eligible".into();
            it["action"] = "delete_artifact".into();
        }
    }
    let p: Plan = serde_json::from_value(v).unwrap();
    exec::apply(&e.cfg, &p, &ApplyOpts { now, max_actions: 100, max_bytes: u64::MAX, kinds: None }).unwrap();
    assert!(t.exists());
}

#[test]
fn r2_b10_b11_tmp_clone_prunable_wt_ok_but_hidden_edits_protect() {
    let e = env();
    let origin = seed_origin(&e);
    let a = e.tmp.join("clone-a");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), a.to_str().unwrap()]);
    let w = e.base.join("w-gone");
    git(&a, &["worktree", "add", "-q", "--detach", w.to_str().unwrap()]);
    fs::remove_dir_all(&w).unwrap();
    let b = e.tmp.join("clone-b");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), b.to_str().unwrap()]);
    git(&b, &["update-index", "--skip-worktree", "a"]);
    fs::write(b.join("a"), "local secret override").unwrap();
    let p = plan(&e, LATER);
    let ia = item(&p, Kind::TmpEntry, &a, None);
    assert_eq!(ia.verdict, Verdict::Eligible, "{:?}", ia.reasons);
    let ib = item(&p, Kind::TmpEntry, &b, None);
    assert_eq!(ib.verdict, Verdict::Protected, "{:?}", ib.reasons);
}

#[test]
fn r2_forged_journal_cannot_purge_whole_quarantine() {
    let e = env();
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    apply_later(&e, &plan(&e, LATER));
    let mut j = journal(&e).into_iter().find(|j| j.status == JStatus::Quarantined).unwrap();
    let q = j.qdir.clone().unwrap();
    let root = q.parent().unwrap().to_path_buf();
    j.jid = "forged".into();
    j.qdir = Some(root.clone());
    let mut line = serde_json::to_string(&j).unwrap();
    line.push('\n');
    let path = e.cfg.state_dir.join("journal.jsonl");
    let mut s = fs::read_to_string(&path).unwrap();
    s.push_str(&line);
    fs::write(&path, s).unwrap();
    let rep = exec::purge(&e.cfg, j.ts + 1).unwrap(); // only the forged one is "expired"... both are
    let rep2 = exec::purge(&e.cfg, j.ts + 400 * DAY).unwrap();
    assert!(rep.errors.iter().chain(rep2.errors.iter()).any(|(id, _)| id == "forged"));
    assert!(root.exists(), "quarantine root must survive");
}

#[test]
fn r2_target_with_only_tool_subdirs_is_recognised() {
    let e = env();
    let r = repo(&e, "app");
    fs::create_dir_all(r.join("target/rust-analyzer/metadata")).unwrap();
    assert_eq!(item(&plan(&e, LATER), Kind::Artifact, &r.join("target"), None).verdict, Verdict::Eligible);
}

#[test]
fn deleted_target_keeps_release_binaries_restorable() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let r = repo(&e, "tool");
    let t = r.join("target");
    cargo_out(&t);
    fs::create_dir_all(t.join("release/deps")).unwrap();
    fs::create_dir_all(t.join("x86_64-unknown-linux-musl/release")).unwrap();
    for (f, exe) in [("release/mytool", true), ("release/libx.rlib", false), ("release/deps/big", true), ("x86_64-unknown-linux-musl/release/mytool", true)] {
        fs::write(t.join(f), "bin").unwrap();
        if exe {
            fs::set_permissions(t.join(f), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let p = plan(&e, LATER);
    let o = apply_later(&e, &p);
    assert!(o.failed.is_empty(), "{:?}", o.failed);
    assert!(!t.exists());
    let j = journal(&e).into_iter().find(|j| j.kind == Kind::Artifact).unwrap();
    assert_eq!(j.status, JStatus::Quarantined);
    exec::restore(&e.cfg, &j.jid).unwrap();
    assert!(t.join("release/mytool").exists());
    assert!(t.join("x86_64-unknown-linux-musl/release/mytool").exists());
    assert!(!t.join("release/libx.rlib").exists() && !t.join("release/deps/big").exists());
}

// ================================================================== round 3: environment edge cases

#[test]
fn e1_untrusted_repo_config_is_never_executed() {
    let e = env();
    let marker = e.base.join("PWNED");
    let tr = e.tmp.join("downloaded");
    fs::create_dir_all(&tr).unwrap();
    git(&tr, &["init", "-q"]);
    commit(&tr, "a.txt", "x");
    fs::write(tr.join(".gitattributes"), "* filter=evil\n").unwrap();
    git(&tr, &["config", "filter.evil.clean", &format!("sh -c 'touch {}; cat'", marker.display())]);
    fs::write(tr.join("a.txt"), "x").unwrap(); // stat-dirty: status would re-run the clean filter
    let p = plan(&e, LATER);
    let it = item(&p, Kind::TmpEntry, &tr, None);
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("config defines commands")), "{:?}", it.reasons);
    assert!(!marker.exists(), "a repo-configured filter was executed");
}

#[test]
fn e2_hooks_and_fsmonitor_in_user_repos_are_neutralised() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let r = repo(&e, "app");
    git(&r, &["branch", "old"]);
    let wt = add_wt(&r, "app-wt", Some("feat"));
    // Configure command-running settings *last*, so test setup never triggers them.
    let marker = e.base.join("HOOKED");
    let hooks = r.join(".githooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("reference-transaction");
    fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    git(&r, &["config", "core.hooksPath", ".githooks"]);
    git(&r, &["config", "core.fsmonitor", &format!("{}", hook.display())]);
    let p = plan(&e, LATER);
    let o = apply_later(&e, &p);
    assert!(o.done.iter().any(|d| d.branch.as_deref() == Some("old")), "branch should still be archived");
    assert!(o.done.iter().any(|d| d.path == wt));
    assert!(!marker.exists(), "a repo hook or fsmonitor command was executed");
}

#[test]
fn e3_remote_inside_gc_scope_does_not_count_as_pushed() {
    let e = env();
    let seed_bare = seed_origin(&e);
    let origin_in_tmp = e.tmp.join("origin.git");
    git(&e.base, &["clone", "-q", "--bare", seed_bare.to_str().unwrap(), origin_in_tmp.to_str().unwrap()]);
    let clone = e.tmp.join("clone-of-tmp-origin");
    git(&e.base, &["clone", "-q", origin_in_tmp.to_str().unwrap(), clone.to_str().unwrap()]);
    let ok = e.tmp.join("clone-of-safe-origin");
    git(&e.base, &["clone", "-q", seed_bare.to_str().unwrap(), ok.to_str().unwrap()]);
    let p = plan(&e, LATER);
    let c = item(&p, Kind::TmpEntry, &clone, None);
    assert_eq!(c.verdict, Verdict::Protected, "{:?}", c.reasons);
    assert!(c.reasons.iter().any(|r| r.contains("trusted remote")), "{:?}", c.reasons);
    assert_eq!(item(&p, Kind::TmpEntry, &ok, None).verdict, Verdict::Eligible);
    assert_eq!(item(&p, Kind::TmpEntry, &origin_in_tmp, None).verdict, Verdict::Protected);
}

#[test]
fn e4_local_lfs_objects_protect_tmp_clone() {
    let e = env();
    let origin = seed_origin(&e);
    let clone = e.tmp.join("lfs-clone");
    git(&e.base, &["clone", "-q", origin.to_str().unwrap(), clone.to_str().unwrap()]);
    let obj = clone.join(".git/lfs/objects/ab/cd");
    fs::create_dir_all(&obj).unwrap();
    fs::write(obj.join("abcd1234"), "big binary only here").unwrap();
    let it = item(&plan(&e, LATER), Kind::TmpEntry, &clone, None).clone();
    assert_eq!(it.verdict, Verdict::Protected, "{:?}", it.reasons);
    assert!(it.reasons.iter().any(|r| r.contains("LFS")));
}

#[test]
fn e5_failed_delete_never_leaves_a_half_deleted_target() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let r = repo(&e, "app");
    let t = r.join("target");
    cargo_out(&t);
    let locked = t.join("debug/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("f"), "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap(); // like root-owned docker output
    let o = apply_later(&e, &plan(&e, LATER));
    assert!(o.failed.iter().any(|(i, _)| i.path == t), "{:?}", o.failed);
    assert!(!t.exists(), "the project must see the target either whole or gone");
    let leftover: Vec<_> = fs::read_dir(&r)
        .unwrap()
        .flatten()
        .filter(|x| x.file_name().to_string_lossy().starts_with(exec::DELETING_PREFIX))
        .collect();
    assert_eq!(leftover.len(), 1);
    // Leftovers are never mistaken for build output or anything else.
    assert!(!plan(&e, LATER).items.iter().any(|i| i.path == leftover[0].path()));
    // Once the blocker is gone, a later run finishes the deletion.
    fs::set_permissions(leftover[0].path().join("debug/locked"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(exec::sweep_deleting(&[r.clone()]).is_empty());
    assert!(!leftover[0].path().exists());
}

#[test]
fn e6_time_away_does_not_age_anything() {
    use tree_gc::clock::{day, ActivityClock};
    let e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("feat"));
    let now = now_epoch();
    // Used today, then 59 days of runs with no user activity (holiday).
    let clock = ActivityClock { first_run: Some(now - DAY), last_run: Some(now + 59 * DAY), active: [day(now)].into() };
    clock.save(&e.cfg.state_dir).unwrap();
    let it = item(&plan(&e, LATER), Kind::Worktree, &wt, None).clone();
    assert_eq!(it.verdict, Verdict::Active, "{:?}", it.reasons);
    assert!(it.reasons[0].contains("in-use day"), "{:?}", it.reasons);
    fs::remove_file(e.cfg.state_dir.join("activity.json")).unwrap();
    assert_eq!(item(&plan(&e, LATER), Kind::Worktree, &wt, None).verdict, Verdict::Eligible);
}

#[test]
fn e7_clock_that_went_backwards_blocks_all_actions() {
    use tree_gc::clock::ActivityClock;
    let e = env();
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    let p = plan(&e, LATER);
    let clock = ActivityClock { first_run: Some(now_epoch()), last_run: Some(now_epoch() + 100 * DAY), active: Default::default() };
    clock.save(&e.cfg.state_dir).unwrap();
    let opts = ApplyOpts { now: now_epoch() + LATER * DAY, max_actions: 100, max_bytes: u64::MAX, kinds: None };
    assert!(exec::apply(&e.cfg, &p, &opts).is_err());
    assert!(exec::purge(&e.cfg, now_epoch() + LATER * DAY).is_err());
    assert!(e.tmp.join("junk").exists());
}

#[test]
fn e8_restore_window_is_not_eaten_by_time_away() {
    use tree_gc::clock::ActivityClock;
    let e = env();
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    apply_later(&e, &plan(&e, LATER));
    let j = journal(&e).into_iter().find(|j| j.status == JStatus::Quarantined).unwrap();
    // Machine ran every day after the quarantine, but nobody used it.
    let clock = ActivityClock { first_run: Some(now_epoch() - DAY), last_run: Some(j.ts + 20 * DAY), active: Default::default() };
    clock.save(&e.cfg.state_dir).unwrap();
    let rep = exec::purge(&e.cfg, j.ts + 20 * DAY).unwrap();
    assert!(rep.purged.is_empty(), "20 calendar days but 0 in-use days must not expire the quarantine");
    assert!(j.qdir.unwrap().exists());
}

#[test]
fn e9_other_cleaners_lock_defers_build_output_only() {
    use std::os::unix::io::AsRawFd;
    let mut e = env();
    let r = repo(&e, "app");
    cargo_out(&r.join("target"));
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    let lock_path = e.base.join("other-cleaner.lock");
    let held = fs::File::create(&lock_path).unwrap();
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    e.cfg.interop_locks = vec![lock_path];
    e.cfg.interop_wait_secs = 1;
    let o = apply_later(&e, &plan(&e, LATER));
    assert!(r.join("target").exists(), "build output must wait for the other cleaner");
    assert!(o.skipped.iter().any(|(_, why)| why.contains("another cleaner")));
    assert!(!e.tmp.join("junk").exists(), "unrelated kinds still proceed");
    drop(held);
}

fn pressure_cfg(e: &mut Env, hard: bool) {
    let p = &mut e.cfg.pressure;
    p.enabled = true;
    p.soft_free_percent = 100.0; // every filesystem counts as pressured
    p.low_free_percent = if hard { 100.0 } else { 0.0 };
    p.low_free_gib = 0.0;
    p.critical_free_percent = 0.0;
    p.target_free_percent = 100.0; // never satisfied: every allowed tier runs
    p.min_age_days = 2;
    p.sweep_active_targets = false;
    p.notify = false;
}

#[test]
fn e10_pressure_soft_tiers_spare_active_work_and_reversible_items() {
    let mut e = env();
    pressure_cfg(&mut e, false);
    let r = repo(&e, "app");
    let t = r.join("target");
    cargo_out(&t);
    let r2 = repo(&e, "lib");
    cargo_out(&r2.join("target"));
    fs::write(r2.join(".gitignore"), "").unwrap(); // not ignored -> protected
    let wt = add_wt(&r, "app-wt", Some("feat"));
    // Something already in quarantine (reversible): soft pressure must leave it.
    apply_later(&e, &plan(&e, LATER));
    let q = journal(&e).into_iter().find(|j| j.kind == Kind::Worktree).unwrap();
    assert!(!wt.exists());
    cargo_out(&t); // rebuilt today: actively worked on
    // Today: everything is fresh -> nothing evicted even under pressure.
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch()).unwrap();
    assert!(!rep.shadow);
    assert!(t.exists(), "actively worked-on build output was evicted: {:?}", rep.steps);
    // Later: stale build output goes; protected and quarantined things stay.
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch() + 10 * DAY).unwrap();
    assert!(!t.exists(), "{:?}", rep.steps);
    assert!(r2.join("target").exists());
    assert!(q.qdir.clone().unwrap().exists(), "soft pressure must not purge quarantine early");
}

#[test]
fn e11_hard_pressure_purges_quarantine_early_most_reproducible_first() {
    let mut e = env();
    let r = repo(&e, "app");
    let wt = add_wt(&r, "app-wt", Some("feat"));
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    apply_later(&e, &plan(&e, LATER));
    let js = journal(&e);
    let wtq = js.iter().find(|j| j.kind == Kind::Worktree).unwrap().clone();
    let tmpq = js.iter().find(|j| j.kind == Kind::TmpEntry).unwrap().clone();
    assert!(!wt.exists());
    pressure_cfg(&mut e, true);
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch() + LATER * DAY).unwrap();
    let steps = rep.steps.join("\n");
    assert!(!wtq.qdir.unwrap().exists() && !tmpq.qdir.unwrap().exists(), "{steps}");
    let wpos = steps.find(&wtq.jid).unwrap();
    let tpos = steps.find(&tmpq.jid).unwrap();
    assert!(wpos < tpos, "worktree (rebuildable from git) must be purged before tmp data:\n{steps}");
    // The branch itself was never touched.
    assert!(git(&r, &["branch", "--list", "feat"]).contains("feat"));
}

#[test]
fn e12_pressure_in_shadow_mode_only_reports() {
    let mut e = env();
    pressure_cfg(&mut e, true);
    e.cfg.enforce = false;
    let r = repo(&e, "app");
    cargo_out(&r.join("target"));
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch() + LATER * DAY).unwrap();
    assert!(rep.shadow);
    assert!(r.join("target").exists());
}

#[test]
fn e13_failures_and_actions_are_logged_with_context() {
    use std::os::unix::fs::PermissionsExt;
    use tree_gc::log::Level;
    let e = env();
    // The only test that initialises the (process-global) logger.
    let log_dir = e.base.join("logs");
    let run = tree_gc::log::init(&log_dir, Level::Debug);
    let r = repo(&e, "app");
    let t = r.join("target");
    cargo_out(&t);
    let locked = t.join("debug/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("f"), "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    fs::create_dir_all(e.tmp.join("junk")).unwrap();
    apply_later(&e, &plan(&e, LATER));
    let recs: Vec<_> = tree_gc::log::read(&log_dir).into_iter().filter(|r| r.run == run).collect();
    let failed = recs
        .iter()
        .find(|r| r.event == "action.failed" && r.fields["path"] == t.to_str().unwrap())
        .unwrap_or_else(|| panic!("no action.failed for {}: {recs:#?}", t.display()));
    assert_eq!(failed.level, Level::Error);
    assert!(failed.fields["error"].as_str().unwrap().contains("removing"), "{failed:?}");
    assert!(failed.fields["jid"].as_str().is_some(), "failure must point at its journal entry");
    let junk = e.tmp.join("junk");
    assert!(recs.iter().any(|r| r.event == "action.done" && r.fields["path"] == junk.to_str().unwrap()));
    // Clean up the leftover so the TempDir can be removed.
    for x in fs::read_dir(&r).unwrap().flatten() {
        if x.file_name().to_string_lossy().starts_with(exec::DELETING_PREFIX) {
            let _ = fs::set_permissions(x.path().join("debug/locked"), fs::Permissions::from_mode(0o755));
        }
    }
}

#[test]
fn e14_relief_stops_when_deletions_free_nothing() {
    // Data still referenced elsewhere (hardlinks here; a btrfs snapshot in
    // real life) is not freed by deleting it: relief must notice and stop.
    let mut e = env();
    pressure_cfg(&mut e, false);
    e.cfg.pressure.stall_min_gib = 40.0 / 1024.0; // 40 MiB
    let keep = e.base.join("still-referenced");
    fs::create_dir_all(&keep).unwrap();
    let mut targets = Vec::new();
    for n in 0..4 {
        let r = repo(&e, &format!("app{n}"));
        let t = r.join("target");
        cargo_out(&t);
        fs::create_dir_all(t.join("debug")).unwrap();
        let src = keep.join(format!("blob{n}"));
        fs::write(&src, vec![7u8; 60 << 20]).unwrap();
        fs::hard_link(&src, t.join("debug/blob")).unwrap();
        targets.push(t);
    }
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch() + 10 * DAY).unwrap();
    assert!(rep.stalled, "{:#?}", rep.steps);
    let deleted = targets.iter().filter(|t| !t.exists()).count();
    assert!(deleted < targets.len(), "kept deleting although nothing was freed: {:#?}", rep.steps);
    assert!(deleted >= 1);
    // The next guard tick is paused instead of deleting more.
    let rep2 = tree_gc::pressure::relieve(&e.cfg, now_epoch() + 10 * DAY).unwrap();
    assert!(rep2.paused, "{:#?}", rep2.steps);
    assert_eq!(targets.iter().filter(|t| !t.exists()).count(), deleted);
}

#[test]
fn e15_relief_stops_at_per_pass_cap() {
    let mut e = env();
    pressure_cfg(&mut e, false);
    e.cfg.pressure.stall_min_gib = 1000.0; // this test is about the cap, not the stall brake
    e.cfg.pressure.max_gib_per_relief = 70.0 / 1024.0; // 70 MiB
    let mut targets = Vec::new();
    for n in 0..5 {
        let r = repo(&e, &format!("app{n}"));
        let t = r.join("target");
        cargo_out(&t);
        fs::write(t.join("debug-blob"), vec![1u8; 30 << 20]).unwrap();
        targets.push(t);
    }
    let rep = tree_gc::pressure::relieve(&e.cfg, now_epoch() + 10 * DAY).unwrap();
    assert!(rep.capped, "{:#?}", rep.steps);
    let deleted = targets.iter().filter(|t| !t.exists()).count();
    assert_eq!(deleted, 3, "30 MiB each, cap 70 MiB: stop right after crossing it\n{:#?}", rep.steps);
    // The next pass continues where this one stopped.
    tree_gc::pressure::relieve(&e.cfg, now_epoch() + 10 * DAY).unwrap();
    assert_eq!(targets.iter().filter(|t| !t.exists()).count(), 5);
}

#[test]
fn e16_sustained_io_pressure_defers_deletions_but_not_ref_work() {
    if exec::io_psi().is_none() {
        eprintln!("skipped: kernel without /proc/pressure/io");
        return;
    }
    let mut e = env();
    let r = repo(&e, "app");
    git(&r, &["branch", "old"]);
    let t = r.join("target");
    cargo_out(&t);
    e.cfg.throttle_max_io_psi = -1.0; // "always under pressure"
    e.cfg.throttle_io_wait_secs = 0;
    let o = apply_later(&e, &plan(&e, LATER));
    assert!(o.stopped_early.as_deref().is_some_and(|s| s.contains("I/O pressure")), "{:?}", o.stopped_early);
    assert!(t.exists(), "deletion must wait for the disk to calm down");
    assert!(o.done.iter().any(|d| d.branch.as_deref() == Some("old")), "branch archiving does no bulk I/O and proceeds");
}
