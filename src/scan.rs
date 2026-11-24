//! Discovery + evaluation. Strictly read-only: nothing in this module mutates
//! the filesystem or any git repository.
use crate::config::{Config, RootKind, ScratchAction, ScratchRule};
use crate::git::{self, Wt};
use crate::model::{Action, Item, Kind, Plan, Verdict};
use crate::procs::{parse_pid_lock, pid_alive, Procs};
use crate::util::*;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Everything evaluation needs, snapshotted once per run.
pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub now: i64,
    pub procs: Procs,
    pub uid: u32,
    pub home: Option<PathBuf>,
    /// (symlink, resolved target) for symlinks in $PATH dirs, ~/.local/bin, ~/bin.
    pub path_links: Vec<(PathBuf, PathBuf)>,
    /// (source, contents) of reference files (units, rc files, agent configs).
    pub ref_texts: Vec<(String, String)>,
    pub mounts: Vec<MountEntry>,
    pub volatile_mounts: Vec<PathBuf>,
    /// admin dir -> directory whose `.git` file points at it (seen during discovery).
    pub gitfile_owners: HashMap<PathBuf, PathBuf>,
    pub clock: crate::clock::ActivityClock,
    /// Set only by the pressure-relief engine after it measured (or
    /// predicted) pressure; never taken from a plan file.
    pub pressure_active: bool,
}

impl<'a> Ctx<'a> {
    pub fn new(cfg: &'a Config, now: i64) -> Self {
        Ctx {
            clock: crate::clock::ActivityClock::load(&cfg.state_dir),
            pressure_active: false,
            cfg,
            now,
            procs: Procs::snapshot(),
            uid: uid(),
            home: home(),
            path_links: collect_path_links(),
            ref_texts: collect_ref_texts(cfg),
            mounts: mounts(),
            volatile_mounts: volatile_mount_prefixes(&mounts()),
            gitfile_owners: HashMap::new(),
        }
    }

    /// Re-snapshot fast-changing state (processes, mounts) right before acting.
    pub fn refresh(&mut self) {
        self.procs = Procs::snapshot();
        self.mounts = mounts();
    }

    /// `p` is itself a mount point. Checked *before* any stat: stat on the
    /// mount point of a dead NFS/sshfs server blocks forever.
    pub fn is_mount_point(&self, p: &Path) -> bool {
        self.mounts.iter().any(|m| m.point == p)
    }

    pub fn mount_inside(&self, p: &Path) -> Option<String> {
        mount_at_or_below(&self.mounts, p).map(|m| format!("contains mount point {}", display_path(&m)))
    }

    /// Configured tree root strictly containing `p`.
    pub fn tree_root_of(&self, p: &Path) -> Option<PathBuf> {
        self.root_of(p, &[RootKind::Tree])
    }

    /// Configured root of one of `kinds` strictly containing `p`.
    pub fn root_of(&self, p: &Path, kinds: &[RootKind]) -> Option<PathBuf> {
        self.cfg
            .roots
            .iter()
            .filter(|r| kinds.contains(&r.kind))
            .find(|r| p.starts_with(&r.path) && p != r.path)
            .map(|r| r.path.clone())
    }

    /// Remote-tracking globs for remotes that count as "safe elsewhere":
    /// network remotes, and local-path remotes that exist and lie outside
    /// every root and scratch dir tree-gc manages (so they can't be
    /// collected themselves).
    pub fn trusted_remote_globs(&self, c: std::process::Command) -> Vec<String> {
        git::remote_urls(c)
            .into_iter()
            .filter(|(_, url)| match git::local_remote_path(url) {
                None => true,
                Some(p) => {
                    p.is_absolute()
                        && p.exists()
                        && !self.cfg.roots.iter().any(|r| p.starts_with(&r.path))
                        && !self.cfg.scratch.iter().any(|s| p.starts_with(&s.path))
                }
            })
            .map(|(name, _)| format!("refs/remotes/{name}/*"))
            .collect()
    }

    /// A unix socket file whose name some live process has bound.
    pub fn live_socket(&self, sockets: &[PathBuf]) -> Option<String> {
        sockets
            .iter()
            .find(|s| s.file_name().is_some_and(|n| self.procs.socket_names.contains(&*n.to_string_lossy())))
            .map(|s| format!("live unix socket {}", display_path(s)))
    }

    /// Stale = idle for at least `days` *in-use* days (see clock.rs) and at
    /// least max(days, active_days) calendar days. Unknown activity is never stale.
    pub fn is_stale(&self, t: Option<i64>, days: u64) -> bool {
        let floor = days.max(self.cfg.active_days) as i64;
        matches!(t, Some(t) if self.now - t >= floor * DAY && self.clock.idle_days(t, self.now) >= days as i64)
    }

    /// Calendar-only staleness, for disk pressure: a full disk doesn't care
    /// whether you were on holiday.
    pub fn is_stale_calendar(&self, t: Option<i64>, days: u64) -> bool {
        let days = days.max(1) as i64;
        matches!(t, Some(t) if self.now - t >= days * DAY)
    }

    pub fn age_days(&self, t: Option<i64>) -> Option<i64> {
        t.map(|t| (self.now - t) / DAY)
    }

    pub fn in_use_idle_days(&self, t: Option<i64>) -> Option<i64> {
        t.map(|t| self.clock.idle_days(t, self.now))
    }

    /// Keep marker on the path or any ancestor; configured protect_paths.
    pub fn protection(&self, p: &Path) -> Option<String> {
        let marker = &self.cfg.keep_marker;
        for anc in p.ancestors() {
            if anc.join(marker).exists() {
                return Some(format!("keep marker {}", display_path(&anc.join(marker))));
            }
        }
        for pp in &self.cfg.protect_paths {
            if p.starts_with(pp) || pp.starts_with(p) {
                return Some(format!("protect_paths: {}", display_path(pp)));
            }
        }
        None
    }

    pub fn in_use(&self, p: &Path) -> Option<String> {
        self.procs
            .user_of(p)
            .map(|r| format!("in use by pid {} ({}): {}", r.pid, r.comm, display_path(&r.path)))
    }

    /// A config/unit/rc file mentions this path (or something inside it).
    pub fn referenced_by(&self, p: &Path) -> Option<String> {
        let abs = p.to_string_lossy().into_owned();
        let mut forms = vec![abs.clone()];
        if let Some(h) = &self.home {
            if let Ok(rest) = p.strip_prefix(h) {
                let r = rest.to_string_lossy();
                forms.push(format!("~/{r}"));
                forms.push(format!("$HOME/{r}"));
                forms.push(format!("${{HOME}}/{r}"));
                forms.push(format!("%h/{r}"));
            }
        }
        for (src, text) in &self.ref_texts {
            for f in &forms {
                // Match the path itself or anything below it, not a mere prefix
                // of a sibling name (target vs target2).
                let mut from = 0;
                while let Some(i) = text[from..].find(f.as_str()) {
                    let end = from + i + f.len();
                    let next = text[end..].chars().next();
                    if !next.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
                        return Some(format!("referenced in {src}"));
                    }
                    from = end;
                }
            }
        }
        None
    }

    /// Newest agent-session activity recorded for exactly the directory `p`,
    /// e.g. ~/.claude/projects/-home-u-projects-x/*.jsonl. Deliberately not
    /// ancestors: a session in ~/projects must not mark everything as active.
    pub fn agent_activity(&self, p: &Path) -> Option<i64> {
        let mut t = None;
        {
            let anc = p;
            let enc: String = anc.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
            for d in &self.cfg.agent_session_dirs {
                let dir = d.join(&enc);
                if let Ok(rd) = fs::read_dir(&dir) {
                    t = max_opt(t, mtime(&dir));
                    for e in rd.flatten().take(10_000) {
                        t = max_opt(t, e.metadata().ok().map(|m| mctime(&m)));
                    }
                }
            }
        }
        t
    }

    pub fn linked_from_path(&self, p: &Path) -> Option<String> {
        let c = canon(p);
        self.path_links
            .iter()
            .find(|(_, t)| t.starts_with(&c))
            .map(|(l, t)| format!("{} -> {} is on PATH", display_path(l), display_path(t)))
    }

    /// Root of the global quarantine if it is on the same filesystem as `p`,
    /// else `<fallback>/.tree-gc-quarantine`, else None (we never copy).
    pub fn quarantine_root(&self, p: &Path, fallback: Option<&Path>) -> Option<PathBuf> {
        let d = dev_of(p)?;
        if dev_of_nearest(&self.cfg.quarantine_dir) == Some(d) {
            return Some(self.cfg.quarantine_dir.clone());
        }
        let fb = fallback?;
        (dev_of(fb) == Some(d)).then(|| fb.join(fallback_quarantine_name()))
    }

    pub fn is_internal(&self, p: &Path) -> bool {
        p.starts_with(&self.cfg.quarantine_dir)
            || p.starts_with(&self.cfg.state_dir)
            || p.file_name().is_some_and(is_quarantine_name)
            || p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(crate::exec::DELETING_PREFIX))
    }
}

fn collect_ref_texts(cfg: &Config) -> Vec<(String, String)> {
    const MAX: u64 = 256 << 20;
    let mut out = Vec::new();
    let mut read = |p: &Path| {
        if fs::metadata(p).map(|m| m.is_file() && m.len() <= MAX).unwrap_or(false) {
            // Lossy: one odd byte must not hide the rest of the file.
            if let Ok(b) = fs::read(p) {
                out.push((display_path(p), String::from_utf8_lossy(&b).into_owned()));
            }
        }
    };
    for f in &cfg.reference_files {
        if f.is_dir() {
            // Two levels: covers foo.service.d/override.conf, conf.d/*.fish.
            for e in walkdir::WalkDir::new(f).max_depth(2).follow_links(false).into_iter().flatten() {
                read(e.path());
            }
        } else {
            read(f);
        }
    }
    if cfg.reference_crontab {
        if let Ok(o) = std::process::Command::new("crontab").arg("-l").stderr(std::process::Stdio::null()).output() {
            if o.status.success() {
                out.push(("crontab".into(), String::from_utf8_lossy(&o.stdout).into_owned()));
            }
        }
    }
    out
}

fn collect_path_links() -> Vec<(PathBuf, PathBuf)> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(h) = home() {
        dirs.push(h.join(".local/bin"));
        dirs.push(h.join("bin"));
    }
    dirs.sort();
    dirs.dedup();
    let mut v = Vec::new();
    for d in dirs {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_symlink()).unwrap_or(false) {
                if let Ok(t) = fs::read_link(e.path()) {
                    v.push((e.path(), canon(&d.join(t))));
                }
            }
        }
    }
    v
}

/// Accumulates protections and notes, then decides the verdict.
pub(crate) struct Eval {
    pub(crate) item: Item,
    protect: Vec<String>,
    notes: Vec<String>,
}

impl Eval {
    pub(crate) fn new(kind: Kind, path: PathBuf) -> Self {
        Eval { item: Item::new(kind, path), protect: vec![], notes: vec![] }
    }
    pub(crate) fn protect(&mut self, s: impl Into<String>) {
        self.protect.push(s.into());
    }
    pub(crate) fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
    pub(crate) fn protected(&self) -> bool {
        !self.protect.is_empty()
    }
    pub(crate) fn touch(&mut self, t: Option<i64>) {
        self.item.last_activity = max_opt(self.item.last_activity, t);
    }
    pub(crate) fn finish(mut self, ctx: &Ctx, stale_days: u64, action: Action) -> Item {
        let it = &mut self.item;
        let age = ctx.age_days(it.last_activity);
        if !self.protect.is_empty() {
            it.verdict = Verdict::Protected;
            it.reasons = self.protect;
            it.reasons.extend(self.notes);
        } else if ctx.is_stale(it.last_activity, stale_days) {
            it.verdict = Verdict::Eligible;
            it.action = Some(action);
            it.reasons = vec![format!(
                "idle {}d ({} in-use days) >= {}d",
                age.unwrap_or(0),
                ctx.in_use_idle_days(it.last_activity).unwrap_or(0),
                stale_days.max(ctx.cfg.active_days)
            )];
            it.reasons.extend(self.notes);
        } else {
            it.verdict = Verdict::Active;
            let used = ctx.in_use_idle_days(it.last_activity);
            it.reasons = vec![match (age, used) {
                (Some(a), Some(u)) if u < a => {
                    format!("touched {a}d ago but only {u} in-use day(s) since (< {stale_days}d)")
                }
                (Some(a), _) => format!("active {a}d ago (< {}d)", stale_days.max(ctx.cfg.active_days)),
                (None, _) => "activity unknown; kept".to_string(),
            }];
            it.reasons.extend(self.notes);
        }
        it.compute_id();
        self.item
    }
}

// ---------------------------------------------------------------- discovery

#[derive(Default)]
struct Discovery {
    repos: BTreeSet<PathBuf>,
    gitfile_owners: HashMap<PathBuf, PathBuf>,
    artifacts: Vec<(PathBuf, PathBuf)>, // (dir, root)
    tmp: Vec<(PathBuf, PathBuf)>,       // (entry, root)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ident {
    /// Known build-output name + its project marker file + expected contents.
    Known,
    /// Only a CACHEDIR.TAG (opt-in; must also be git-ignored inside a repo).
    CacheDirTag,
}

/// Contents look like what the named tool actually produces.
fn signature_ok(name: &str, dir: &Path) -> bool {
    let has = |f: &str| dir.join(f).exists();
    match name {
        "target" => {
            ["CACHEDIR.TAG", ".rustc_info.json", "debug", "release", "doc", "rust-analyzer", "llvm-cov-target",
             "nextest", "criterion", "package", "flycheck0"]
                .iter()
                .any(|f| has(f))
                // target/<triple>/{debug,release} for cross builds
                || fs::read_dir(dir).map(|rd| rd.flatten().take(64).any(|e| {
                    e.file_name().to_string_lossy().matches('-').count() >= 2
                        && (e.path().join("debug").is_dir() || e.path().join("release").is_dir())
                })).unwrap_or(false)
        }
        "node_modules" => {
            has(".package-lock.json") || has(".modules.yaml") || has(".yarn-state.yml") || has(".yarn-integrity")
                || fs::read_dir(dir).map(|rd| {
                    rd.flatten().take(50).any(|e| e.path().join("package.json").is_file()
                        || (e.file_name().to_string_lossy().starts_with('@') && e.path().is_dir()))
                }).unwrap_or(false)
        }
        "__pycache__" => fs::read_dir(dir)
            .map(|rd| rd.flatten().all(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.ends_with(".pyc") || n.ends_with(".pyo")
            }))
            .unwrap_or(false),
        ".pytest_cache" | ".mypy_cache" | ".ruff_cache" => has("CACHEDIR.TAG"),
        _ => true,
    }
}

pub fn artifact_identity(cfg: &Config, dir: &Path, name: &str) -> Option<Ident> {
    if let Some(marker) = cfg.artifacts.markers.get(name) {
        let marker_ok = marker.is_empty() || dir.parent().is_some_and(|p| p.join(marker).is_file());
        if marker_ok && signature_ok(name, dir) {
            return Some(Ident::Known);
        }
    }
    (cfg.artifacts.respect_cachedir_tag && is_cachedir_tag(dir)).then_some(Ident::CacheDirTag)
}

fn artifact_candidate(cfg: &Config, dir: &Path, name: &str) -> bool {
    artifact_identity(cfg, dir, name).is_some()
}

fn walk_tree(ctx: &Ctx, root: &Path, max_depth: usize, d: &mut Discovery) {
    let Some(root_dev) = dev_of(root) else { return };
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let gitp = dir.join(".git");
        if let Ok(m) = fs::symlink_metadata(&gitp) {
            if m.is_dir() {
                d.repos.insert(canon(&dir));
            } else if m.is_file() {
                if let Some(h) = git::handle_from_gitfile(&gitp) {
                    d.repos.insert(canon(&h));
                }
                if let Some(admin) = git::admin_from_gitfile(&gitp) {
                    d.gitfile_owners.insert(canon(&admin), dir.clone());
                }
            }
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() {
                continue; // file_type() does not follow symlinks
            }
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == ".git" {
                continue;
            }
            let p = e.path();
            if ctx.is_internal(&p) || ctx.is_mount_point(&p) {
                continue; // never stat into (possibly dead) mounts
            }
            if ctx.cfg.artifacts.enabled && artifact_candidate(ctx.cfg, &p, name) {
                d.artifacts.push((p, root.to_path_buf()));
                continue; // never descend into build output
            }
            if depth + 1 <= max_depth && dev_of(&p) == Some(root_dev) {
                stack.push((p, depth + 1));
            }
        }
    }
}

fn discover(ctx: &Ctx) -> Discovery {
    let mut d = Discovery::default();
    for root in &ctx.cfg.roots {
        if !root.path.is_dir() {
            continue;
        }
        match root.kind {
            RootKind::Tree => walk_tree(ctx, &root.path, root.max_depth, &mut d),
            RootKind::Tmp if ctx.cfg.tmp.enabled => {
                if let Ok(rd) = fs::read_dir(&root.path) {
                    for e in rd.flatten() {
                        if !ctx.is_mount_point(&e.path()) {
                            d.tmp.push((e.path(), root.path.clone()));
                        }
                    }
                }
            }
            RootKind::Tmp => {}
        }
    }
    d
}

// ---------------------------------------------------------------- worktrees

fn worktree_gitdir_activity(admin: &Path) -> Option<i64> {
    let mut t = reflog_last_ts(&admin.join("logs/HEAD"));
    for f in ["HEAD", "index", "ORIG_HEAD", "FETCH_HEAD"] {
        t = max_opt(t, mtime(&admin.join(f)));
    }
    t
}

fn is_disposable_ignored(ctx: &Ctx, wt: &Path, rel: &str) -> bool {
    let trimmed = rel.trim_end_matches('/');
    let name = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let p = wt.join(trimmed);
    if p.is_dir() && artifact_identity(ctx.cfg, &p, name) == Some(Ident::Known) {
        return true;
    }
    ctx.cfg.worktrees.disposable_ignored.iter().any(|g| glob_match(g, name))
}

/// Evaluate one linked worktree (never call with the main worktree).
pub fn eval_worktree(ctx: &Ctx, repo: &Path, wt: &Wt, admin: Option<PathBuf>) -> Item {
    let cfg = &ctx.cfg.worktrees;
    let missing = wt.prunable || !wt.path.exists();
    let kind = if missing { Kind::StaleWorktreeMeta } else { Kind::Worktree };
    let mut e = Eval::new(kind, wt.path.clone());
    e.item.repo = Some(repo.to_path_buf());
    e.item.branch = wt.branch.as_deref().map(|b| b.trim_start_matches("refs/heads/").to_string());
    e.item.head = wt.head.clone();
    e.item.admin_dir = admin.clone();

    // Worktrees may live under tree roots or tmp roots (agents often put them in /tmp).
    e.item.root = ctx.root_of(&wt.path, &[RootKind::Tree, RootKind::Tmp]);
    if e.item.root.is_none() {
        e.protect("outside every configured root");
    }
    let Some(admin) = admin else {
        e.protect("worktree admin dir not found under .git/worktrees");
        return e.finish(ctx, cfg.stale_days, Action::QuarantineWorktree);
    };
    e.touch(worktree_gitdir_activity(&admin));

    // Locks: honored unless the lock names a pid that is provably gone.
    if let Some(reason) = &wt.locked {
        let shown = if reason.is_empty() { "(no reason)" } else { reason.as_str() };
        match parse_pid_lock(reason) {
            Some((pid, start)) if cfg.break_dead_pid_locks && !pid_alive(pid, start) => {
                e.note(format!("lock is stale: owner pid {pid} is gone ({shown})"))
            }
            Some((pid, _)) if cfg.break_dead_pid_locks => {
                e.protect(format!("locked by live process {pid}: {shown}"))
            }
            _ if cfg.honor_locks => e.protect(format!("locked: {shown}")),
            _ => e.note(format!("lock ignored (honor_locks=false): {shown}")),
        }
    }
    if let Some(p) = ctx.protection(&wt.path) {
        e.protect(p);
    }
    if let Some(op) = git::in_progress_op(&admin) {
        e.protect(format!("{op} in progress"));
    }
    if let Some(h) = &wt.head {
        e.touch(git::commit_time(repo, h));
    }

    if missing {
        let parent_gone = wt.path.parent().is_none_or(|p| !p.is_dir());
        if parent_gone {
            e.protect("parent directory is also missing (unmounted drive?)");
        }
        if let Some(pre) = ctx.cfg.removable_prefixes.iter().chain(&ctx.volatile_mounts).find(|r| wt.path.starts_with(r)) {
            e.protect(format!("under {} (may just be unmounted)", pre.display()));
        }
        if let Some(moved_to) = ctx.gitfile_owners.get(&canon(&admin)) {
            e.protect(format!("worktree was moved to {}; run `git worktree repair` there", display_path(moved_to)));
        }
        match git::admin_has_staged_changes(repo, &admin) {
            Ok(false) => {}
            Ok(true) => e.protect("its index holds staged changes that exist nowhere else"),
            Err(err) => e.protect(format!("cannot inspect its index: {err}")),
        }
        if ctx.quarantine_root(&admin, None).is_none() {
            e.protect("admin dir is on a different filesystem than the quarantine");
        }
        if wt.detached {
            e.note("detached HEAD will be kept as an archive ref");
        }
        e.note("working directory is gone; only git metadata remains");
        return e.finish(ctx, cfg.stale_days, Action::PruneWorktreeMeta);
    }

    if let Some(u) = ctx.in_use(&wt.path) {
        e.protect(u);
    }
    if let Some(r) = ctx.referenced_by(&wt.path) {
        e.protect(r);
    }
    e.touch(ctx.agent_activity(&wt.path));
    if let Some(m) = ctx.mount_inside(&wt.path) {
        e.protect(m);
    }
    match git::hidden_local_edits(&wt.path) {
        Ok(v) if v.is_empty() => {}
        Ok(v) => e.protect(format!("{} assume-unchanged/skip-worktree file(s) edited locally: {}", v.len(), sample(&v))),
        Err(err) => e.protect(format!("cannot check hidden local edits: {err}")),
    }
    for why in submodule_protection(ctx, &wt.path, 0) {
        e.protect(why);
    }
    for why in module_dirs_protection(ctx, &admin) {
        e.protect(why);
    }
    // Deliberately NOT the worktree dir's own mtime: removing an artifact
    // inside it would look like fresh activity. Real edits show up as
    // dirty/untracked status; commits/checkouts show up in the reflog.
    match git::status(&wt.path) {
        Err(err) => e.protect(format!("git status failed: {err}")),
        Ok(st) => {
            if !st.tracked.is_empty() {
                e.protect(format!("{} uncommitted change(s): {}", st.tracked.len(), sample(&st.tracked)));
            }
            if !st.untracked.is_empty() {
                e.protect(format!("{} untracked path(s): {}", st.untracked.len(), sample(&st.untracked)));
            }
            let precious: Vec<String> = st
                .ignored
                .iter()
                .filter(|r| !is_disposable_ignored(ctx, &wt.path, r))
                .cloned()
                .collect();
            if !precious.is_empty() {
                e.protect(format!(
                    "ignored files that may not be reproducible: {}",
                    sample(&precious)
                ));
            }
            for r in &st.ignored {
                let p = wt.path.join(r.trim_end_matches('/'));
                e.touch(mtime(&p));
                // Disposable dirs still must not hide repos, keep markers, mounts.
                if !e.protected() && p.is_dir() {
                    if let Some(why) = scan_protection(ctx, &p, &dir_scan(&p, &ctx.cfg.keep_marker)) {
                        e.protect(format!("{r}: {why}"));
                    }
                }
            }
        }
    }
    if ctx.quarantine_root(&wt.path, None).is_none() || ctx.quarantine_root(&admin, None).is_none() {
        e.protect("on a different filesystem than the quarantine (tree-gc never copies)");
    }
    if !e.protected() {
        match (&e.item.branch, &wt.head) {
            (Some(b), _) => e.note(format!("branch {b} stays in the repo")),
            (None, Some(h)) => match git::unique_commits(repo, h, None) {
                Ok(0) => e.note("detached HEAD is contained in other refs"),
                Ok(n) => e.note(format!("detached HEAD has {n} commit(s) on no branch; kept as archive ref")),
                Err(err) => e.protect(format!("cannot check detached HEAD: {err}")),
            },
            _ => {}
        }
    }
    e.finish(ctx, cfg.stale_days, Action::QuarantineWorktree)
}

/// Submodules (recursively) holding dirty files, stashes or unpushed commits.
/// Their object stores live inside the worktree's admin dir, so purging a
/// quarantined worktree would destroy them.
/// Submodule git dirs stored in `<gitdir>/modules/**` keep history even after
/// `git submodule deinit` empties the working tree.
fn module_dirs_protection(ctx: &Ctx, gitdir: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for gd in git::module_git_dirs(gitdir) {
        let name = gd.strip_prefix(gitdir).unwrap_or(&gd).display().to_string();
        if let Some(cmds) = git::untrusted_config(&gd) {
            v.push(format!("submodule git dir {name}: config defines commands ({cmds}); not inspected"));
            continue;
        }
        let globs = ctx.trusted_remote_globs(git::cmd_gitdir(&gd));
        match git::gitdir_unpushed(&gd, &globs) {
            Ok((0, false)) => {}
            Ok((n, stash)) => v.push(format!(
                "submodule git dir {name}: {n} commit(s) not on any remote{}",
                if stash { ", has stashes" } else { "" }
            )),
            Err(err) => v.push(format!("cannot inspect submodule git dir {name}: {err}")),
        }
    }
    v
}

fn submodule_protection(ctx: &Ctx, dir: &Path, depth: usize) -> Vec<String> {
    let mut v = Vec::new();
    if depth > 4 {
        return v;
    }
    let subs = match git::submodule_paths(dir) {
        Ok(s) => s,
        Err(err) => return vec![format!("cannot inspect submodules: {err}")],
    };
    for s in subs {
        let sp = dir.join(&s);
        if !sp.join(".git").exists() {
            continue; // not initialised: nothing local
        }
        for why in repo_irreplaceable(ctx, &sp) {
            v.push(format!("submodule {s}: {why}"));
        }
        v.extend(submodule_protection(ctx, &sp, depth + 1));
    }
    v
}

fn sample(v: &[String]) -> String {
    let mut s = v.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if v.len() > 3 {
        s.push_str(&format!(", +{} more", v.len() - 3));
    }
    s
}

// ---------------------------------------------------------------- branches

pub struct RepoInfo {
    pub handle: PathBuf,
    pub common: PathBuf,
    pub wts: Vec<Wt>,
    pub targets: Vec<String>,
    pub busy: std::collections::HashSet<String>,
}

impl RepoInfo {
    pub fn load(ctx: &Ctx, handle: &Path) -> Result<Self> {
        let common = git::common_dir(handle)?;
        Ok(RepoInfo {
            handle: handle.to_path_buf(),
            busy: git::busy_branches(&common),
            common,
            wts: git::worktrees(handle)?,
            targets: git::integration_targets(handle, &ctx.cfg.branches.protected),
        })
    }
    pub fn admin_for(&self, wt: &Path) -> Option<PathBuf> {
        let c = canon(wt);
        git::admin_dirs(&self.common)
            .into_iter()
            .find(|(p, _)| p == wt || canon(p) == c)
            .map(|(_, a)| a)
    }
}

pub fn eval_branch(ctx: &Ctx, ri: &RepoInfo, b: &git::BranchRef) -> Item {
    let cfg = &ctx.cfg.branches;
    let repo = &ri.handle;
    let name = b.refname.trim_start_matches("refs/heads/").to_string();
    let mut e = Eval::new(Kind::Branch, repo.clone());
    e.item.repo = Some(repo.clone());
    e.item.branch = Some(name.clone());
    e.item.head = Some(b.sha.clone());
    e.touch(b.ctime);
    let reflog = ri.common.join("logs").join(&b.refname);
    e.touch(reflog_last_ts(&reflog));

    if cfg.protected.iter().any(|p| glob_match(p, &name)) {
        e.protect("protected branch name");
    } else if ri.wts.iter().any(|w| w.branch.as_deref() == Some(b.refname.as_str())) {
        e.protect("checked out in a worktree");
    } else if ri.busy.contains(&b.refname) {
        e.protect("being rebased or bisected in a worktree");
    } else if ri.targets.is_empty() {
        e.protect("no integration branch (origin/HEAD, main, master...) to compare against");
    } else if let Some(p) = ctx.protection(repo) {
        e.protect(p);
    } else {
        let short = |t: &str| t.trim_start_matches("refs/heads/").trim_start_matches("refs/remotes/").to_string();
        let merged = ri.targets.iter().find(|t| git::is_ancestor(repo, &b.sha, t).unwrap_or(false));
        if let Some(t) = merged {
            e.note(format!("merged into {}", short(t)));
        } else {
            let squashed = cfg.include_squash_merged
                && ri.targets.iter().find(|t| {
                    let ahead = git::count_range(repo, &format!("{t}..{}", b.sha)).unwrap_or(u64::MAX);
                    ahead <= 300
                        && (git::all_patches_applied(repo, t, &b.sha).unwrap_or(false)
                            || git::squash_merged(repo, t, &b.sha).unwrap_or(false))
                })
                .map(|t| e.notes.push(format!("all commits patch-equivalent in {} (squash/rebase merged)", short(t))))
                .is_some();
            if !squashed {
                match git::unsafe_commits(repo, &b.sha, &ri.targets) {
                    Ok(0) => e.note("every commit is on a remote, tag or integration branch"),
                    Ok(n) => e.protect(format!(
                        "{n} commit(s) not merged and not pushed (exist only locally)"
                    )),
                    Err(err) => e.protect(format!("cannot inspect: {err}")),
                }
            }
        }
        if !e.protected() {
            e.note(format!("will be kept as {}heads/{name}/<sha>", cfg.archive_prefix));
        }
    }
    e.finish(ctx, cfg.stale_days, Action::ArchiveBranch)
}

fn eval_repo(ctx: &Ctx, handle: &Path, out: &mut Vec<Item>, notes: &mut Vec<String>) {
    let ri = match RepoInfo::load(ctx, handle) {
        Ok(r) => r,
        Err(err) => {
            crate::log_warn!("scan.repo_skipped", "{}: {err:#}", display_path(handle));
            notes.push(format!("skipped repo {}: {err}", display_path(handle)));
            return;
        }
    };
    if ctx.cfg.worktrees.enabled {
        for wt in ri.wts.iter().skip(1).filter(|w| !w.bare) {
            let admin = ri.admin_for(&wt.path);
            out.push(eval_worktree(ctx, handle, wt, admin));
        }
    }
    if ctx.cfg.branches.enabled {
        match git::branches(handle) {
            Ok(bs) => out.extend(bs.iter().map(|b| eval_branch(ctx, &ri, b))),
            Err(err) => {
                crate::log_warn!("scan.branches_failed", "{}: {err:#}", display_path(handle));
                notes.push(format!("branches of {}: {err}", display_path(handle)))
            }
        }
    }
}

// ---------------------------------------------------------------- artifacts

fn find_git_worktree(p: &Path) -> Option<PathBuf> {
    p.ancestors().skip(1).find(|a| a.join(".git").exists()).map(Path::to_path_buf)
}

fn git_head_activity(wt: &Path) -> Option<i64> {
    let g = wt.join(".git");
    let gitdir = if g.is_dir() {
        g
    } else {
        let s = fs::read_to_string(&g).ok()?;
        let rel = s.trim().strip_prefix("gitdir:")?.trim().to_string();
        wt.join(rel)
    };
    max_opt(reflog_last_ts(&gitdir.join("logs/HEAD")), mtime(&gitdir.join("HEAD")))
}

pub fn eval_artifact(ctx: &Ctx, path: &Path, root: Option<&Path>) -> Item {
    let mut e = Eval::new(Kind::Artifact, path.to_path_buf());
    e.item.root = root.map(Path::to_path_buf);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ident = artifact_identity(ctx.cfg, path, name);
    let enclosing = find_git_worktree(path);
    match ident {
        None => e.protect("not a recognised build-output directory (name/marker/contents)"),
        Some(Ident::CacheDirTag) if enclosing.is_none() => {
            e.protect("only a CACHEDIR.TAG and not inside a git repo: not proof it is regenerable")
        }
        _ => {}
    }
    if let Some(m) = ctx.mount_inside(path) {
        e.protect(m);
    }
    match fs::symlink_metadata(path) {
        Err(err) => e.protect(format!("cannot stat: {err}")),
        Ok(m) if !m.is_dir() => e.protect("not a real directory (symlink?)"),
        Ok(m) if m.uid() != ctx.uid => e.protect(format!("owned by uid {}", m.uid())),
        Ok(m) => e.touch(Some(mctime(&m))),
    }
    if let Some(p) = ctx.protection(path) {
        e.protect(p);
    }
    if let Some(u) = ctx.in_use(path) {
        e.protect(u);
    }
    if let Some(l) = ctx.linked_from_path(path) {
        e.protect(l);
    }
    if let Some(r) = ctx.referenced_by(path) {
        e.protect(r);
    }
    // Agent sessions in the owning project dir count as use of its build output.
    if let Some(parent) = path.parent() {
        e.touch(ctx.agent_activity(parent));
    }
    if let Some(wt) = find_git_worktree(path) {
        e.touch(ctx.agent_activity(&wt));
    }
    // First-level children (target/debug, node_modules/.package-lock.json...).
    if let Ok(rd) = fs::read_dir(path) {
        for c in rd.flatten().take(5000) {
            e.touch(c.metadata().ok().map(|m| mctime(&m)));
        }
    }
    // Not the parent dir's mtime: deleting a sibling artifact would bump it.
    let parent = path.parent().unwrap_or(path);
    if let Some(marker) = ctx.cfg.artifacts.markers.get(name).filter(|m| !m.is_empty()) {
        e.touch(mtime(&parent.join(marker)));
    }
    if let Some(wt) = enclosing {
        e.touch(git_head_activity(&wt));
        let rel = path.strip_prefix(&wt).unwrap_or(path);
        match git::has_tracked(&wt, rel) {
            Ok(true) => e.protect("contains git-tracked files"),
            Ok(false) => match git::is_ignored(&wt, rel) {
                Ok(true) => {}
                Ok(false) => e.protect("not git-ignored (may be intentional content)"),
                Err(err) => e.protect(format!("git check-ignore failed: {err}")),
            },
            Err(err) => e.protect(format!("git ls-files failed: {err}")),
        }
    }
    // Opt-in CACHEDIR.TAG-only matches are reversible, never deleted outright.
    let action = if ident == Some(Ident::CacheDirTag) { Action::QuarantinePath } else { Action::DeleteArtifact };
    e.finish(ctx, ctx.cfg.artifacts.stale_days, action)
}

// ---------------------------------------------------------------- tmp + scratch

/// Shared rules for "a directory entry that ages out" (tmp roots and scratch).
fn eval_entry(ctx: &Ctx, path: &Path, m: &fs::Metadata, mut e: Eval, stale_days: u64, action: Action) -> Item {
    if let Some(p) = ctx.protection(path) {
        e.protect(p);
    }
    if let Some(u) = ctx.in_use(path) {
        e.protect(u);
    }
    if let Some(r) = ctx.referenced_by(path) {
        e.protect(r);
    }
    e.touch(Some(mctime(m)));
    if let Some(mp) = ctx.mount_inside(path) {
        e.protect(mp);
    }
    if m.is_dir() {
        if path.join(".git").is_file() {
            e.protect("linked git worktree (handled by worktree policy)");
        }
        let ws = walk_stat(path, ctx.cfg.tmp.max_walk_entries, &ctx.cfg.keep_marker);
        e.touch(ws.newest);
        if let Some(k) = ws.keep_marker {
            e.protect(format!("keep marker {}", display_path(&k)));
        }
        if ws.truncated {
            e.protect(format!("too large to verify (> {} entries)", ctx.cfg.tmp.max_walk_entries));
        }
        for l in &ws.linked {
            if l != path {
                e.protect(format!("contains linked worktree/submodule {}", display_path(l)));
            }
        }
        if let Some(s) = ctx.live_socket(&ws.sockets) {
            e.protect(s);
        }
        for r in &ws.repos {
            for why in repo_irreplaceable(ctx, r) {
                e.protect(format!("{}: {why}", display_path(r)));
            }
        }
        for b in &ws.bare {
            e.protect(format!("contains bare repository {} (may be the only copy)", display_path(b)));
        }
    }
    e.finish(ctx, stale_days, action)
}

/// Git dir of a working tree (`.git` dir, or the dir a `.git` file points at).
fn gitdir_of(repo: &Path) -> Option<PathBuf> {
    let g = repo.join(".git");
    if g.is_dir() {
        Some(g)
    } else if g.is_file() {
        git::admin_from_gitfile(&g)
    } else if is_bare_repo(repo) {
        Some(repo.to_path_buf())
    } else {
        None
    }
}

/// Common git dir (where config, refs and objects live) for a git dir.
fn common_of(gitdir: &Path) -> PathBuf {
    fs::read_to_string(gitdir.join("commondir"))
        .map(|c| canon(&gitdir.join(c.trim())))
        .unwrap_or_else(|_| gitdir.to_path_buf())
}

/// Reasons a standalone repo holds work that exists nowhere else.
/// Used for repos found in untrusted places (tmp, scratch, build output,
/// submodules), so the repo's own config is screened before git runs there.
pub fn repo_irreplaceable(ctx: &Ctx, repo: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let Some(gitdir) = gitdir_of(repo) else { return vec!["git dir not found".into()] };
    let common = common_of(&gitdir);
    for g in [&gitdir, &common] {
        if let Some(cmds) = git::untrusted_config(g) {
            return vec![format!("repo config defines commands git would run ({cmds}); not inspected")];
        }
    }
    if let Some(why) = git::large_file_store(&common) {
        v.push(why);
    }
    let globs = ctx.trusted_remote_globs(git::cmd_gitdir(&common));
    match git::status(repo) {
        Err(err) => v.push(format!("git status failed: {err}")),
        Ok(st) => {
            if !st.tracked.is_empty() {
                v.push(format!("{} uncommitted change(s)", st.tracked.len()));
            }
            if !st.untracked.is_empty() {
                v.push(format!("{} untracked path(s)", st.untracked.len()));
            }
        }
    }
    match git::hidden_local_edits(repo) {
        Ok(h) if h.is_empty() => {}
        Ok(h) => v.push(format!("{} assume-unchanged/skip-worktree file(s) edited locally", h.len())),
        Err(err) => v.push(format!("cannot check hidden local edits: {err}")),
    }
    if git::has_stash(repo) {
        v.push("has stashes".into());
    }
    match git::worktrees(repo) {
        // Prunable entries (directory already gone) hold nothing.
        Ok(w) => {
            let live = w.iter().skip(1).filter(|w| !w.prunable).count();
            if live > 0 {
                v.push(format!("has {live} linked worktree(s)"));
            }
        }
        Err(err) => v.push(format!("cannot list worktrees: {err}")),
    }
    // All refs (branches, tags, custom refs like refs/jj/*, stash, worktree
    // HEADs) minus what a remote has.
    if git::ref_value(repo, "HEAD").is_some() || !git::run(repo, &["for-each-ref", "--count=1"]).unwrap_or_default().trim().is_empty() {
        // "Pushed" only counts remotes that live outside tree-gc's own scope
        // (a remote that is another /tmp repo may be collected too).
        match git::unpushed_count(git::cmd(repo), &[], &globs) {
            Ok(0) => {}
            Ok(n) => v.push(format!("{n} commit(s) not on any trusted remote (incl. tags and custom refs)")),
            Err(err) => v.push(format!("cannot count unpushed commits: {err}")),
        }
        // Recently amended/reset-away local work, for a bounded window.
        match git::recent_local_reflog_shas(repo, ctx.now, ctx.cfg.reflog_protect_days) {
            Ok(shas) if !shas.is_empty() => {
                let mut c = git::cmd(repo);
                c.args(["rev-list", "--count"]).args(&shas).args(["--not", "--all"]);
                for g in &globs {
                    c.arg(format!("--glob={g}"));
                }
                let counted = git::output(c, None)
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().unwrap_or(1))
                    .ok_or_else(|| anyhow::anyhow!("rev-list failed"));
                match counted {
                    Ok(0) => {}
                    Ok(n) => v.push(format!(
                        "{n} commit(s) only in reflogs from the last {}d (amended/reset away)",
                        ctx.cfg.reflog_protect_days
                    )),
                    Err(err) => v.push(format!("cannot inspect reflogs: {err}")),
                }
            }
            Ok(_) => {}
            Err(err) => v.push(format!("cannot read reflogs: {err}")),
        }
    }
    v.extend(module_dirs_protection(ctx, &gitdir));
    v
}

pub fn eval_tmp(ctx: &Ctx, path: &Path, root: &Path) -> Option<Item> {
    let m = fs::symlink_metadata(path).ok()?;
    let name = path.file_name()?.to_str()?;
    if is_special_file(&m)
        || (ctx.cfg.tmp.only_own && m.uid() != ctx.uid)
        || ctx.cfg.tmp.exclude.iter().any(|g| glob_match(g, name))
        || ctx.is_internal(path)
    {
        return None;
    }
    let mut e = Eval::new(Kind::TmpEntry, path.to_path_buf());
    e.item.root = Some(root.to_path_buf());
    if ctx.quarantine_root(path, Some(root)).is_none() {
        e.protect("no same-filesystem quarantine available");
    }
    let on_tmpfs = ctx
        .mounts
        .iter()
        .filter(|mt| root.starts_with(&mt.point))
        .max_by_key(|mt| mt.point.components().count())
        .is_some_and(|mt| mt.fstype == "tmpfs");
    if on_tmpfs {
        e.note("quarantine stays on this tmpfs: lost at reboot, and systemd-tmpfiles may clear it before quarantine_days");
    }
    Some(eval_entry(ctx, path, &m, e, ctx.cfg.tmp.stale_days, Action::QuarantinePath))
}

pub fn eval_scratch_entry(ctx: &Ctx, rule: &ScratchRule, path: &Path) -> Option<Item> {
    let m = fs::symlink_metadata(path).ok()?;
    let name = path.file_name()?.to_str()?;
    if is_special_file(&m) || rule.exclude.iter().any(|g| glob_match(g, name)) || ctx.is_internal(path) {
        return None;
    }
    let mut e = Eval::new(Kind::Scratch, path.to_path_buf());
    e.item.root = Some(rule.path.clone());
    e.item.rule = Some(rule.name.clone());
    if m.uid() != ctx.uid {
        e.protect(format!("owned by uid {}", m.uid()));
    }
    let action = match rule.action {
        ScratchAction::Delete => Action::DeletePath,
        ScratchAction::Quarantine => {
            if ctx.quarantine_root(path, Some(&rule.path)).is_none() {
                e.protect("no same-filesystem quarantine available");
            }
            Action::QuarantinePath
        }
    };
    Some(eval_entry(ctx, path, &m, e, rule.stale_days, action))
}

/// Evaluate all children of a scratch dir, then apply the keep_newest window.
pub fn eval_scratch_rule(ctx: &Ctx, rule: &ScratchRule) -> Vec<Item> {
    let Ok(rd) = fs::read_dir(&rule.path) else { return vec![] };
    let mut items: Vec<Item> = rd
        .flatten()
        .filter(|e| !ctx.is_mount_point(&e.path()))
        .filter_map(|e| eval_scratch_entry(ctx, rule, &e.path()))
        .collect();
    items.sort_by_key(|i| std::cmp::Reverse(i.last_activity.unwrap_or(i64::MAX)));
    for it in items.iter_mut().take(rule.keep_newest) {
        if it.verdict == Verdict::Eligible {
            it.verdict = Verdict::Active;
            it.action = None;
            it.reasons.insert(0, format!("within newest {} of rule (FIFO window)", rule.keep_newest));
        }
    }
    items
}

// ---------------------------------------------------------------- planning

fn compute_sizes(ctx: &Ctx, items: &mut [Item]) {
    let idx = AtomicUsize::new(0);
    let todo: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, i)| i.verdict != Verdict::Protected && !matches!(i.kind, Kind::Branch | Kind::StaleWorktreeMeta | Kind::Docker))
        .map(|(n, _)| n)
        .collect();
    let paths: Vec<PathBuf> = todo.iter().map(|&n| items[n].path.clone()).collect();
    let results: Vec<std::sync::Mutex<Option<DirScan>>> = paths.iter().map(|_| Default::default()).collect();
    let threads = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(4);
    let marker = ctx.cfg.keep_marker.as_str();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let k = idx.fetch_add(1, Ordering::Relaxed);
                if k >= paths.len() {
                    break;
                }
                *results[k].lock().unwrap() = Some(dir_scan(&paths[k], marker));
            });
        }
    });
    for (k, &n) in todo.iter().enumerate() {
        let Some(ds) = results[k].lock().unwrap().take() else { continue };
        let it = &mut items[n];
        it.bytes = Some(ds.bytes);
        // Build output / deletable scratch must not hide repos or kept files.
        let deletes = matches!(it.action, Some(Action::DeleteArtifact | Action::DeletePath)) || it.kind == Kind::Artifact;
        if deletes {
            if let Some(why) = scan_protection(ctx, &it.path, &ds) {
                it.verdict = Verdict::Protected;
                it.action = None;
                it.reasons.insert(0, why);
            }
        }
    }
}

/// Why a to-be-deleted tree must be kept: a keep marker, a nested linked
/// worktree/submodule, or a nested repo holding work that exists nowhere
/// else. Clean clones made by build scripts (e.g. boring-sys cloning
/// BoringSSL into OUT_DIR) do not block deletion.
pub fn scan_protection(ctx: &Ctx, top: &Path, ds: &DirScan) -> Option<String> {
    if let Some(k) = &ds.keep_marker {
        return Some(format!("keep marker {}", display_path(k)));
    }
    if let Some(m) = ctx.mount_inside(top) {
        return Some(m);
    }
    if let Some(u) = ctx.in_use(top) {
        return Some(u);
    }
    if let Some(b) = ds.bare.first() {
        return Some(format!("contains bare repository {} (may be the only copy)", display_path(b)));
    }
    if let Some(s) = ctx.live_socket(&ds.sockets) {
        return Some(s);
    }
    if ds.nested_git.len() > 50 {
        return Some(format!("contains {} nested git repos; too many to verify", ds.nested_git.len()));
    }
    for g in &ds.nested_git {
        let repo = g.parent().unwrap_or(g);
        if in_cargo_out_dir(top, repo) {
            continue;
        }
        if !g.is_dir() {
            return Some(format!("contains linked worktree/submodule {}", display_path(repo)));
        }
        let why = repo_irreplaceable(ctx, repo);
        if !why.is_empty() {
            return Some(format!("contains repo {} with {}", display_path(repo), why.join(", ")));
        }
    }
    None
}

/// `<top>=.../target` and `repo` lies under `build/<crate>[-hash]/[hash/]out/`:
/// Cargo build-script OUT_DIR, which Cargo itself wipes on rebuild.
fn in_cargo_out_dir(top: &Path, repo: &Path) -> bool {
    if top.file_name().is_none_or(|n| n != "target") {
        return false;
    }
    let Ok(rel) = repo.strip_prefix(top) else { return false };
    let c: Vec<&std::ffi::OsStr> = rel.components().map(|c| c.as_os_str()).collect();
    c.iter().enumerate().any(|(i, x)| {
        *x == "build" && (c.get(i + 2).is_some_and(|o| *o == "out") || c.get(i + 3).is_some_and(|o| *o == "out"))
    })
}

/// Plan-time *preview* of pressure relief for build output: promote
/// least-recently-used artifacts until the projected free space reaches the
/// target. The real relief (`pressure::relieve`) re-measures after each step.
fn apply_pressure(ctx: &Ctx, items: &mut [Item], notes: &mut Vec<String>) {
    let a = &ctx.cfg.pressure;
    if !a.enabled {
        return;
    }
    let mut by_dev: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (n, it) in items.iter().enumerate() {
        if it.kind == Kind::Artifact {
            if let Some(d) = dev_of(&it.path) {
                by_dev.entry(d).or_default().push(n);
            }
        }
    }
    for (_, idxs) in by_dev {
        let Some((total, avail)) = fs_usage(&items[idxs[0]].path) else { continue };
        if total == 0 {
            continue;
        }
        let free_pct = avail as f64 * 100.0 / total as f64;
        if !crate::pressure::under_pressure(a, total, avail) {
            continue;
        }
        let need = crate::pressure::target_avail(a, total);
        let mut projected = avail
            + idxs.iter().filter(|&&n| items[n].verdict == Verdict::Eligible).filter_map(|&n| items[n].bytes).sum::<u64>();
        let mut cands: Vec<usize> = idxs
            .iter()
            .copied()
            .filter(|&n| items[n].verdict == Verdict::Active && ctx.is_stale_calendar(items[n].last_activity, a.min_age_days))
            .collect();
        cands.sort_by_key(|&n| items[n].last_activity.unwrap_or(i64::MAX));
        let mut promoted = 0;
        for n in cands {
            if projected >= need {
                break;
            }
            let it = &mut items[n];
            it.verdict = Verdict::Eligible;
            it.action = Some(Action::DeleteArtifact);
            it.pressure = true;
            it.reasons.insert(0, format!("disk pressure: {free_pct:.1}% free (relief below {}%)", a.low_free_percent));
            projected += it.bytes.unwrap_or(0);
            promoted += 1;
        }
        notes.push(format!(
            "disk pressure on {}: {free_pct:.1}% free; promoted {promoted} LRU artifact(s)",
            display_path(&items[idxs[0]].path)
        ));
    }
}

pub fn build_plan(cfg: &Config, now: i64) -> Result<Plan> {
    let real_now = now_epoch();
    let mut ctx = Ctx::new(cfg, now);
    let mut d = discover(&ctx);
    ctx.gitfile_owners = std::mem::take(&mut d.gitfile_owners);
    let mut items = Vec::new();
    let mut notes = Vec::new();
    for repo in &d.repos {
        eval_repo(&ctx, repo, &mut items, &mut notes);
    }
    for (p, root) in &d.artifacts {
        items.push(eval_artifact(&ctx, p, Some(root)));
    }
    for rule in cfg.scratch.iter().filter(|r| r.enabled) {
        items.extend(eval_scratch_rule(&ctx, rule));
    }
    for (p, root) in &d.tmp {
        items.extend(eval_tmp(&ctx, p, root));
    }
    if let Some(snap) = crate::docker::snapshot(cfg) {
        items.extend(crate::docker::items(&ctx, &snap));
    }
    // A path may be reached twice (e.g. a worktree under two roots).
    let mut seen = HashMap::new();
    items.retain(|i| seen.insert(i.id.clone(), ()).is_none());
    compute_sizes(&ctx, &mut items);
    apply_pressure(&ctx, &mut items, &mut notes);
    sort_items(&mut items);
    Ok(Plan {
        generated_at: real_now,
        now,
        simulated: now != real_now,
        enforce: cfg.enforce,
        items,
        notes,
    })
}

/// Eligible first; within that the cheapest/most lossless tier first; within
/// a tier least-recently-active first (FIFO by activity).
pub fn sort_items(items: &mut [Item]) {
    items.sort_by(|a, b| {
        (a.verdict, a.kind, a.last_activity.unwrap_or(i64::MAX), &a.path)
            .cmp(&(b.verdict, b.kind, b.last_activity.unwrap_or(i64::MAX), &b.path))
    });
}

/// Re-evaluate one planned item against the *current* state of the system.
pub fn reverify(ctx: &Ctx, item: &Item) -> Item {
    let gone = |why: &str| {
        let mut i = item.clone();
        i.verdict = Verdict::Protected;
        i.action = None;
        i.reasons = vec![why.to_string()];
        i
    };
    // A saved plan is untrusted input: its root must be a currently
    // configured root of the right kind, and the path strictly inside it.
    let root_ok = |kind: RootKind| {
        item.root.as_ref().is_some_and(|r| {
            ctx.cfg.roots.iter().any(|c| &c.path == r && c.kind == kind) && item.path.starts_with(r) && &item.path != r
        })
    };
    match item.kind {
        Kind::Artifact if !root_ok(RootKind::Tree) => return gone("not inside a configured tree root"),
        Kind::Worktree | Kind::StaleWorktreeMeta if !root_ok(RootKind::Tree) && !root_ok(RootKind::Tmp) => {
            return gone("not inside a configured root")
        }
        Kind::TmpEntry if !root_ok(RootKind::Tmp) || item.path.parent() != item.root.as_deref() => {
            return gone("not a top-level entry of a configured tmp root")
        }
        Kind::Scratch => {
            let ok = ctx.cfg.scratch.iter().any(|r| {
                r.enabled && Some(&r.name) == item.rule.as_ref() && Some(&r.path) == item.root.as_ref()
                    && item.path.parent() == Some(r.path.as_path())
            });
            if !ok {
                return gone("not a direct child of its configured scratch dir");
            }
        }
        Kind::Branch => {
            let Some(repo) = &item.repo else { return gone("no repo recorded") };
            let in_scope = ctx.tree_root_of(repo).is_some()
                || git::worktrees(repo).map(|w| w.iter().any(|w| ctx.tree_root_of(&w.path).is_some())).unwrap_or(false);
            if !in_scope {
                return gone("repo is not under a configured tree root");
            }
        }
        _ => {}
    }
    let mut fresh = match item.kind {
        Kind::Worktree | Kind::StaleWorktreeMeta => {
            let Some(repo) = &item.repo else { return gone("no repo recorded") };
            let Ok(ri) = RepoInfo::load(ctx, repo) else { return gone("repo unreadable") };
            match ri.wts.iter().skip(1).find(|w| w.path == item.path) {
                None => return gone("worktree no longer registered"),
                Some(w) => eval_worktree(ctx, repo, w, ri.admin_for(&w.path)),
            }
        }
        Kind::Branch => {
            let Some(repo) = &item.repo else { return gone("no repo recorded") };
            let Ok(ri) = RepoInfo::load(ctx, repo) else { return gone("repo unreadable") };
            let refname = format!("refs/heads/{}", item.branch.as_deref().unwrap_or(""));
            let Ok(bs) = git::branches(repo) else { return gone("cannot list branches") };
            match bs.iter().find(|b| b.refname == refname) {
                None => return gone("branch no longer exists"),
                Some(b) => eval_branch(ctx, &ri, b),
            }
        }
        Kind::Artifact => {
            if !item.path.exists() {
                return gone("no longer exists");
            }
            // eval_artifact re-derives identity (name + marker + contents).
            let mut a = eval_artifact(ctx, &item.path, item.root.as_deref());
            if a.verdict != Verdict::Protected {
                if let Some(why) = scan_protection(ctx, &item.path, &dir_scan(&item.path, &ctx.cfg.keep_marker)) {
                    a.verdict = Verdict::Protected;
                    a.action = None;
                    a.reasons.insert(0, why);
                }
            }
            a
        }
        Kind::TmpEntry => {
            let root = item.root.clone().unwrap_or_default();
            match eval_tmp(ctx, &item.path, &root) {
                Some(i) => i,
                None => return gone("no longer exists or no longer in scope"),
            }
        }
        Kind::Scratch => {
            let rule = ctx.cfg.scratch.iter().find(|r| Some(&r.name) == item.rule.as_ref() && r.enabled);
            let Some(rule) = rule else { return gone("scratch rule removed or disabled") };
            // Re-run the whole rule so the keep_newest window is recomputed.
            match eval_scratch_rule(ctx, rule).into_iter().find(|i| i.path == item.path) {
                Some(i) => i,
                None => return gone("no longer exists or no longer in scope"),
            }
        }
        Kind::Docker => {
            // Rebuild from a fresh docker snapshot; the plan's fields aren't trusted.
            let Some(snap) = crate::docker::snapshot(ctx.cfg) else { return gone("docker disabled or unreachable") };
            match crate::docker::items(ctx, &snap).into_iter().find(|i| i.path == item.path) {
                Some(i) => i,
                None => return gone("docker object no longer present"),
            }
        }
    };
    if fresh.head != item.head && fresh.verdict == Verdict::Eligible {
        return gone("HEAD moved since the plan was made");
    }
    // Never trust a plan's pressure flag: disk pressure must exist *now*.
    let pressure_now = ctx.cfg.pressure.enabled
        && (ctx.pressure_active
            || fs_usage(&item.path).is_some_and(|(t, a)| crate::pressure::under_pressure(&ctx.cfg.pressure, t, a)));
    if item.pressure && pressure_now && fresh.kind == Kind::Artifact && fresh.verdict == Verdict::Active
        && ctx.is_stale_calendar(fresh.last_activity, ctx.cfg.pressure.min_age_days)
    {
        fresh.verdict = Verdict::Eligible;
        fresh.action = Some(Action::DeleteArtifact);
        fresh.pressure = true;
    }
    fresh.bytes = item.bytes;
    fresh
}
