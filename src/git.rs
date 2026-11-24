//! Thin wrappers over the git CLI (honors the user's git config/hooks layout,
//! and never takes optional locks or rewrites the index while inspecting).
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Every git invocation goes through here. Repo-local config can name
/// commands git will execute; neutralise the ones read-only inspection could
/// trigger (hooks, fsmonitor). Clean/process filters are screened separately
/// by `untrusted_config` before git is run in untrusted repos.
fn base() -> Command {
    let mut c = Command::new("git");
    c.args([
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.untrackedCache=false",
        "-c", "protocol.allow=never",
    ])
    .env("GIT_OPTIONAL_LOCKS", "0")
    .env("LC_ALL", "C")
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_ASKPASS", "/bin/false")
    .env("SSH_ASKPASS", "/bin/false")
    .env_remove("GIT_DIR")
    .env_remove("GIT_WORK_TREE");
    c
}

pub fn cmd(dir: &Path) -> Command {
    let mut c = base();
    c.arg("-C").arg(dir);
    c
}

/// git with an explicit --git-dir (for admin/module dirs).
pub fn cmd_gitdir(gitdir: &Path) -> Command {
    let mut c = base();
    c.arg("--git-dir").arg(gitdir);
    c
}

pub fn output(c: Command, stdin: Option<&[u8]>) -> Result<std::process::Output> {
    let desc = format!("{:?}", c.get_args().collect::<Vec<_>>());
    crate::util::output_with_timeout(c, stdin.map(<[u8]>::to_vec), GIT_TIMEOUT)
        .inspect_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                crate::log_warn!("git.timeout", "git {desc} {e}; the item is protected this run");
            }
        })
        .context("running git")
}

pub fn run(dir: &Path, args: &[&str]) -> Result<String> {
    let mut c = cmd(dir);
    c.args(args);
    let out = output(c, None).with_context(|| format!("git {args:?}"))?;
    if !out.status.success() {
        bail!(
            "git {} (in {}): {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Exit code (0/1 are both "answers"; anything else is an error).
pub fn run_code(dir: &Path, args: &[&str]) -> Result<bool> {
    let mut c = cmd(dir);
    c.args(args);
    let out = output(c, None)?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "git {} (in {}): {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

pub fn run_stdin(dir: &Path, args: &[&str], input: &str) -> Result<String> {
    let mut c = cmd(dir);
    c.args(args);
    let out = output(c, Some(input.as_bytes()))?;
    if !out.status.success() {
        bail!(
            "git {} (in {}): {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Debug, Clone, Default)]
pub struct Wt {
    pub path: PathBuf,
    pub head: Option<String>,
    /// Full refname, e.g. refs/heads/main.
    pub branch: Option<String>,
    pub bare: bool,
    pub detached: bool,
    pub locked: Option<String>,
    pub prunable: bool,
}

pub fn worktrees(repo: &Path) -> Result<Vec<Wt>> {
    let out = run(repo, &["worktree", "list", "--porcelain", "-z"])?;
    let mut v = Vec::new();
    let mut cur: Option<Wt> = None;
    for tok in out.split('\0') {
        if tok.is_empty() {
            if let Some(w) = cur.take() {
                v.push(w);
            }
            continue;
        }
        let (k, val) = tok.split_once(' ').unwrap_or((tok, ""));
        if k == "worktree" {
            if let Some(w) = cur.take() {
                v.push(w);
            }
            cur = Some(Wt { path: PathBuf::from(val), ..Default::default() });
            continue;
        }
        let Some(w) = cur.as_mut() else { continue };
        match k {
            "HEAD" => w.head = Some(val.to_string()),
            "branch" => w.branch = Some(val.to_string()),
            "bare" => w.bare = true,
            "detached" => w.detached = true,
            "locked" => w.locked = Some(val.to_string()),
            "prunable" => w.prunable = true,
            _ => {}
        }
    }
    if let Some(w) = cur.take() {
        v.push(w);
    }
    Ok(v)
}

pub fn common_dir(repo: &Path) -> Result<PathBuf> {
    let s = run(repo, &["rev-parse", "--path-format=absolute", "--git-common-dir"])?;
    Ok(PathBuf::from(s.trim()))
}

/// Map of worktree path -> admin dir (`<common>/worktrees/<id>`).
pub fn admin_dirs(common: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut v = Vec::new();
    let Ok(rd) = fs::read_dir(common.join("worktrees")) else { return v };
    for e in rd.flatten() {
        let admin = e.path();
        if let Ok(s) = fs::read_to_string(admin.join("gitdir")) {
            let gitfile = PathBuf::from(s.trim());
            if let Some(wt) = gitfile.parent() {
                v.push((wt.to_path_buf(), admin));
            }
        }
    }
    v
}

/// Resolve a `.git` *file* to the repo handle of its main worktree.
/// Returns None for submodules / separate-git-dir layouts (no commondir).
/// Admin dir a `.git` file points at (`gitdir: ...`), resolved.
pub fn admin_from_gitfile(gitfile: &Path) -> Option<PathBuf> {
    let s = fs::read_to_string(gitfile).ok()?;
    let rel = s.trim().strip_prefix("gitdir:")?.trim();
    Some(gitfile.parent()?.join(rel))
}

pub fn handle_from_gitfile(gitfile: &Path) -> Option<PathBuf> {
    let s = fs::read_to_string(gitfile).ok()?;
    let rel = s.trim().strip_prefix("gitdir:")?.trim();
    let base = gitfile.parent()?;
    let admin = base.join(rel);
    let common_rel = fs::read_to_string(admin.join("commondir")).ok()?;
    let common = crate::util::canon(&admin.join(common_rel.trim()));
    handle_from_common(&common)
}

pub fn handle_from_common(common: &Path) -> Option<PathBuf> {
    if common.file_name()? == ".git" {
        common.parent().map(Path::to_path_buf)
    } else {
        Some(common.to_path_buf())
    }
}

#[derive(Debug, Default)]
pub struct Status {
    pub tracked: Vec<String>,
    pub untracked: Vec<String>,
    pub ignored: Vec<String>,
}

pub fn status(wt: &Path) -> Result<Status> {
    let out = run(
        wt,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=normal",
            "--ignored=traditional",
            "--ignore-submodules=none",
        ],
    )?;
    let mut st = Status::default();
    let mut toks = out.split('\0');
    while let Some(t) = toks.next() {
        if t.len() < 4 {
            continue;
        }
        let xy = &t[..2];
        let p = t[3..].to_string();
        match xy {
            "??" => st.untracked.push(p),
            "!!" => st.ignored.push(p),
            _ => {
                st.tracked.push(p);
                if xy.contains('R') || xy.contains('C') {
                    toks.next();
                }
            }
        }
    }
    Ok(st)
}

/// In-progress rebase/merge/etc. in a (per-worktree) git dir.
pub fn in_progress_op(gitdir: &Path) -> Option<&'static str> {
    [
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase/am"),
        ("MERGE_HEAD", "merge"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
        ("BISECT_LOG", "bisect"),
    ]
    .into_iter()
    .find(|(f, _)| gitdir.join(f).exists())
    .map(|(_, n)| n)
}

pub fn is_ancestor(repo: &Path, a: &str, b: &str) -> Result<bool> {
    run_code(repo, &["merge-base", "--is-ancestor", a, b])
}

pub fn commit_time(repo: &Path, rev: &str) -> Option<i64> {
    run(repo, &["log", "-1", "--format=%ct", rev, "--"]).ok()?.trim().parse().ok()
}

/// Commits reachable from `sha` but from no local branch (optionally
/// excluding one), tag, or remote-tracking ref.
pub fn unique_commits(repo: &Path, sha: &str, exclude_branch: Option<&str>) -> Result<u64> {
    let ex = exclude_branch.map(|b| format!("--exclude={b}"));
    let mut args = vec!["rev-list", "--count", sha, "--not"];
    if let Some(e) = ex.as_deref() {
        args.push(e);
    }
    args.extend(["--branches", "--tags", "--remotes"]);
    Ok(run(repo, &args)?.trim().parse()?)
}

/// Commits reachable from `sha` that are NOT on any remote-tracking ref, tag,
/// or one of `safe` (integration branches). Other local branches don't count:
/// two unpushed branches sharing work must not vouch for each other.
pub fn unsafe_commits(repo: &Path, sha: &str, safe: &[String]) -> Result<u64> {
    let mut args: Vec<&str> = vec!["rev-list", "--count", sha, "--not", "--remotes", "--tags"];
    args.extend(safe.iter().map(String::as_str));
    Ok(run(repo, &args)?.trim().parse()?)
}

/// Paths of submodules (gitlinks, mode 160000) recorded in the index.
/// NUL-separated, so paths with spaces/newlines are handled.
pub fn submodule_paths(wt: &Path) -> Result<Vec<String>> {
    let out = run(wt, &["ls-files", "-z", "-s"])?;
    Ok(out
        .split('\0')
        .filter_map(|e| {
            let (meta, path) = e.split_once('\t')?;
            meta.starts_with("160000 ").then(|| path.to_string())
        })
        .collect())
}

/// Files flagged assume-unchanged or skip-worktree whose on-disk content
/// differs from the index. `git status` never reports these.
pub fn hidden_local_edits(wt: &Path) -> Result<Vec<String>> {
    let out = run(wt, &["ls-files", "-v", "-z"])?;
    let flagged: Vec<String> = out
        .split('\0')
        .filter_map(|e| {
            let (tag, path) = e.split_once(' ')?;
            let t = tag.chars().next()?;
            (t.is_ascii_lowercase() || t == 'S').then(|| path.to_string())
        })
        .collect();
    // Sparse checkouts flag thousands of files that are simply absent: only
    // files actually present on disk can hold hidden edits.
    let present: Vec<(String, fs::Metadata)> = flagged
        .into_iter()
        .filter_map(|p| fs::symlink_metadata(wt.join(&p)).ok().map(|m| (p, m)))
        .collect();
    if present.len() > 5000 {
        bail!("{} assume-unchanged/skip-worktree files present; too many to verify", present.len());
    }
    let mut changed = Vec::new();
    for (p, m) in present {
        if m.is_dir() {
            changed.push(format!("{p} (replaced by a directory)"));
            continue;
        }
        let staged = run(wt, &["ls-files", "-s", "-z", "--", &p])?;
        let mut f = staged.split_whitespace();
        let (mode, sha) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
        if mode == "120000" || mode == "160000" {
            continue;
        }
        let actual = run(wt, &["hash-object", &format!("--path={p}"), "--", &p])?;
        if actual.trim() != sha {
            changed.push(p);
        }
    }
    Ok(changed)
}

/// Branches named by an in-progress rebase or bisect in any worktree. Like
/// `git branch -d`, treat them as checked out (the worktree shows "detached").
pub fn busy_branches(common: &Path) -> std::collections::HashSet<String> {
    let mut dirs = vec![common.to_path_buf()];
    if let Ok(rd) = fs::read_dir(common.join("worktrees")) {
        dirs.extend(rd.flatten().map(|e| e.path()));
    }
    let mut set = std::collections::HashSet::new();
    for d in dirs {
        for f in ["rebase-merge/head-name", "rebase-apply/head-name", "BISECT_START"] {
            if let Ok(s) = fs::read_to_string(d.join(f)) {
                let s = s.trim();
                if !s.is_empty() {
                    set.insert(if s.starts_with("refs/") { s.to_string() } else { format!("refs/heads/{s}") });
                }
            }
        }
        // `rebase --update-refs`: stacked branches the rebase will rewrite.
        if let Ok(s) = fs::read_to_string(d.join("rebase-merge/update-refs")) {
            set.extend(s.lines().filter(|l| l.starts_with("refs/")).map(str::to_string));
        }
    }
    set
}

/// Git dirs of submodules stored under `<gitdir>/modules/**` (recursive).
/// These hold submodule history even after `git submodule deinit`.
pub fn module_git_dirs(gitdir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![gitdir.join("modules")];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if p.join("HEAD").is_file() && p.join("objects").is_dir() {
                stack.push(p.join("modules"));
                out.push(p);
            } else {
                stack.push(p); // nested path components (modules/vendor/lib)
            }
        }
    }
    out
}

/// Commits in a bare/ module git dir that are on no remote-tracking ref,
/// plus whether it has stashes.
pub fn gitdir_unpushed(gitdir: &Path, remote_globs: &[String]) -> Result<(u64, bool)> {
    let n = unpushed_count(cmd_gitdir(gitdir), &[], remote_globs)?;
    let mut c = cmd_gitdir(gitdir);
    c.args(["rev-parse", "-q", "--verify", "refs/stash"]);
    let stash = output(c, None).map(|o| o.status.success()).unwrap_or(false);
    Ok((n, stash))
}

/// Commits recorded in the reflogs of HEAD and local branches within the
/// last `days` days (amended/reset-away work). Remote-tracking reflogs are
/// ignored: they record upstream history, not local work.
pub fn recent_local_reflog_shas(repo: &Path, now: i64, days: u64) -> Result<Vec<String>> {
    let cutoff = now - days as i64 * 86_400;
    let mut refs = vec!["HEAD".to_string()];
    refs.extend(branches(repo)?.into_iter().map(|b| b.refname));
    let mut shas = std::collections::BTreeSet::new();
    for r in refs {
        let Ok(out) = run(repo, &["reflog", "show", "--date=unix", "--format=%H %gd", &r, "--"]) else { continue };
        for l in out.lines() {
            // "<sha> HEAD@{1700000000}"
            let mut f = l.split_whitespace();
            let (Some(sha), Some(sel)) = (f.next(), f.next()) else { continue };
            let ts = sel.rsplit_once('{').and_then(|(_, t)| t.trim_end_matches('}').parse::<i64>().ok());
            if ts.is_some_and(|t| t >= cutoff) {
                shas.insert(sha.to_string());
            }
        }
    }
    Ok(shas.into_iter().collect())
}

/// Repo-local config that would make git *execute* something during
/// inspection (clean/process filters, external diff, textconv, pager...).
/// Read with `git config --file`, which never executes anything. Standard
/// git-lfs filters are allowed. Used before running git in untrusted repos
/// (found under tmp/scratch/build output), where such config may be hostile.
pub fn untrusted_config(gitdir: &Path) -> Option<String> {
    let cfg = gitdir.join("config");
    if !cfg.is_file() {
        return None;
    }
    let mut c = base();
    c.args(["config", "--file"]).arg(&cfg).args([
        "--includes",
        "--get-regexp",
        r"^(filter\..*\.(clean|smudge|process)|diff\..*\.(command|textconv)|diff\.external|core\.(pager|editor|sshcommand|askpass|gitproxy)|include\.path|includeif\..*)$",
    ]);
    let out = output(c, None).ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let bad: Vec<&str> = text
        .lines()
        .filter(|l| {
            let (k, v) = l.split_once(' ').unwrap_or((l, ""));
            !(k.starts_with("filter.lfs.") && v.trim_start().starts_with("git-lfs "))
        })
        .collect();
    (!bad.is_empty()).then(|| bad.iter().take(2).copied().collect::<Vec<_>>().join("; "))
}

/// (remote name, url) pairs.
pub fn remote_urls(c: Command) -> Vec<(String, String)> {
    let mut c = c;
    c.args(["config", "--get-regexp", r"^remote\..*\.url$"]);
    let Ok(out) = output(c, None) else { return vec![] };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(' ')?;
            let name = k.strip_prefix("remote.")?.strip_suffix(".url")?;
            Some((name.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Local filesystem path of a remote URL, or None for network remotes.
pub fn local_remote_path(url: &str) -> Option<PathBuf> {
    if let Some(p) = url.strip_prefix("file://") {
        return Some(PathBuf::from(p));
    }
    if url.contains("://") {
        return None; // https://, ssh://, git://
    }
    // scp-like "host:path" (colon before any slash) is a network remote.
    match (url.find(':'), url.find('/')) {
        (Some(c), Some(s)) if c < s => None,
        (Some(_), None) => None,
        _ => Some(PathBuf::from(url)),
    }
}

/// Count of commits reachable from `positive` revs (or --all) that are not
/// on any of the given remote-tracking globs.
pub fn unpushed_count(mut c: Command, positive: &[&str], remote_globs: &[String]) -> Result<u64> {
    c.args(["rev-list", "--count"]);
    if positive.is_empty() {
        c.arg("--all");
    } else {
        c.args(positive);
    }
    c.arg("--not");
    for g in remote_globs {
        c.arg(format!("--glob={g}"));
    }
    let out = output(c, None)?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(1))
}

/// Git LFS objects / git-annex content stored only in this git dir.
pub fn large_file_store(gitdir: &Path) -> Option<String> {
    if gitdir.join("annex").is_dir() {
        return Some("git-annex content (may be the only copy)".into());
    }
    let lfs = gitdir.join("lfs/objects");
    let has_objects = fs::read_dir(&lfs).map(|mut r| r.next().is_some()).unwrap_or(false);
    has_objects.then(|| "local Git LFS objects (can't verify offline that the server has them)".into())
}

/// Index of a worktree admin dir has staged changes relative to its HEAD.
pub fn admin_has_staged_changes(repo: &Path, admin: &Path) -> Result<bool> {
    let mut c = cmd_gitdir(admin);
    c.args(["diff-index", "--cached", "--quiet", "HEAD", "--"]).current_dir(repo);
    let out = output(c, None)?;
    match out.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => bail!("diff-index: {}", String::from_utf8_lossy(&out.stderr).trim()),
    }
}

/// Every commit of `tip` not in `target` has a patch-equivalent in target
/// (detects squash/rebase merges).
pub fn all_patches_applied(repo: &Path, target: &str, tip: &str) -> Result<bool> {
    let out = run(repo, &["cherry", target, tip])?;
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    Ok(!lines.is_empty() && lines.iter().all(|l| l.starts_with('-')))
}

/// The branch's *combined* change since the merge base appears as a single
/// commit on `target` (squash merge). Read-only: compares patch-ids.
pub fn squash_merged(repo: &Path, target: &str, tip: &str) -> Result<bool> {
    let mb = run(repo, &["merge-base", target, tip])?.trim().to_string();
    let diff = run(repo, &["diff", "--no-color", "--no-ext-diff", &mb, tip])?;
    if diff.trim().is_empty() {
        return Ok(true); // no net change relative to the merge base
    }
    let want = patch_ids(repo, &format!("commit {tip}\n{diff}"))?;
    let Some((want, _)) = want.first().cloned() else { return Ok(false) };
    let log = run(
        repo,
        &["log", "-p", "--no-color", "--no-ext-diff", "--no-merges", "-n", "2000", &format!("{mb}..{target}")],
    )?;
    Ok(patch_ids(repo, &log)?.iter().any(|(id, _)| *id == want))
}

fn patch_ids(repo: &Path, input: &str) -> Result<Vec<(String, String)>> {
    Ok(run_stdin(repo, &["patch-id", "--stable"], input)?
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(a, b)| (a.to_string(), b.to_string())))
        .collect())
}

pub fn count_range(repo: &Path, range: &str) -> Result<u64> {
    Ok(run(repo, &["rev-list", "--count", range])?.trim().parse()?)
}

pub fn on_remote(repo: &Path, sha: &str) -> bool {
    run(repo, &["for-each-ref", "--count=1", "--contains", sha, "refs/remotes"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

pub fn ref_value(repo: &Path, r: &str) -> Option<String> {
    run(repo, &["rev-parse", "-q", "--verify", &format!("{r}^{{commit}}")])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn has_stash(repo: &Path) -> bool {
    ref_value(repo, "refs/stash").is_some()
}

/// Atomic ref transaction via `git update-ref --stdin`.
pub fn update_refs(repo: &Path, cmds: &[String]) -> Result<()> {
    let mut input = String::from("start\n");
    for c in cmds {
        input.push_str(c);
        input.push('\n');
    }
    input.push_str("prepare\ncommit\n");
    run_stdin(repo, &["update-ref", "--stdin"], &input)?;
    Ok(())
}

pub fn is_ignored(wt: &Path, rel: &Path) -> Result<bool> {
    let r = rel.to_string_lossy();
    run_code(wt, &["check-ignore", "-q", "--", &r])
}

pub fn has_tracked(wt: &Path, rel: &Path) -> Result<bool> {
    let r = rel.to_string_lossy();
    Ok(!run(wt, &["ls-files", "-z", "--", &r])?.is_empty())
}

#[derive(Debug, Clone)]
pub struct BranchRef {
    pub refname: String,
    pub sha: String,
    pub ctime: Option<i64>,
}

pub fn branches(repo: &Path) -> Result<Vec<BranchRef>> {
    let out = run(
        repo,
        &["for-each-ref", "--format=%(refname)%00%(objectname)%00%(committerdate:unix)", "refs/heads"],
    )?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let mut p = l.split('\0');
            Some(BranchRef {
                refname: p.next()?.to_string(),
                sha: p.next()?.to_string(),
                ctime: p.next().and_then(|s| s.parse().ok()),
            })
        })
        .collect())
}

/// Integration branches to compare against: remote default branches plus
/// local branches matching the protected patterns (main/master/...).
pub fn integration_targets(repo: &Path, protected: &[String]) -> Vec<String> {
    let mut t = Vec::new();
    if let Ok(remotes) = run(repo, &["remote"]) {
        for r in remotes.lines().filter(|l| !l.is_empty()) {
            if let Ok(s) = run(repo, &["symbolic-ref", "-q", &format!("refs/remotes/{r}/HEAD")]) {
                t.push(s.trim().to_string());
            } else {
                for b in ["main", "master"] {
                    let rr = format!("refs/remotes/{r}/{b}");
                    if ref_value(repo, &rr).is_some() {
                        t.push(rr);
                    }
                }
            }
        }
    }
    if let Ok(bs) = branches(repo) {
        for b in bs {
            let name = b.refname.trim_start_matches("refs/heads/");
            if protected.iter().any(|p| crate::util::glob_match(p, name)) {
                t.push(b.refname);
            }
        }
    }
    t.sort();
    t.dedup();
    t
}
