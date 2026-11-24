//! The only module that mutates anything. Every action:
//!   1. requires `enforce = true` and the kind to be in `enforce_kinds`,
//!   2. re-evaluates the item against the live system (plan may be stale),
//!   3. passes structural safety checks,
//!   4. is recorded in an append-only journal with what is needed to undo it.
use crate::config::Config;
use crate::git;
use crate::model::{Action, Item, Kind, Plan, Verdict};
use crate::safety;
use crate::scan::{reverify, Ctx};
use crate::util::*;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JStatus {
    /// Written *before* acting: if tree-gc dies mid-action, the journal still
    /// says what was being done and where the quarantine dir is.
    Pending,
    /// Irreversible action completed (artifact / delete-path).
    Done,
    /// Ref moved to archive namespace (reversible, no expiry).
    Archived,
    /// Moved to quarantine (reversible until purged).
    Quarantined,
    Failed,
    Purged,
    Restored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JEntry {
    pub jid: String,
    pub ts: i64,
    pub status: JStatus,
    pub action: Action,
    pub kind: Kind,
    pub path: PathBuf,
    pub repo: Option<PathBuf>,
    pub branch: Option<String>,
    pub sha: Option<String>,
    pub archive_ref: Option<String>,
    pub qdir: Option<PathBuf>,
    pub admin_dir: Option<PathBuf>,
    pub bytes: Option<u64>,
    pub reasons: Vec<String>,
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn open(state_dir: &Path) -> Result<Self> {
        fs::create_dir_all(state_dir)?;
        Ok(Journal { path: state_dir.join("journal.jsonl") })
    }

    pub fn append(&self, e: &JEntry) -> Result<()> {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        let mut line = serde_json::to_string(e)?;
        line.push('\n');
        f.write_all(line.as_bytes())?;
        f.sync_data()?;
        Ok(())
    }

    /// Latest state of every journal id, in order of first appearance.
    /// Unparseable (e.g. torn) lines are skipped, never fatal.
    pub fn load(&self) -> Result<Vec<JEntry>> {
        Ok(self.load_with_errors()?.0)
    }

    pub fn load_with_errors(&self) -> Result<(Vec<JEntry>, usize)> {
        let Ok(s) = fs::read_to_string(&self.path) else { return Ok((vec![], 0)) };
        let mut order: Vec<String> = Vec::new();
        let mut latest: std::collections::HashMap<String, JEntry> = Default::default();
        let mut bad = 0;
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(e) = serde_json::from_str::<JEntry>(line) else {
                bad += 1;
                continue;
            };
            if !latest.contains_key(&e.jid) {
                order.push(e.jid.clone());
            }
            latest.insert(e.jid.clone(), e);
        }
        Ok((order.into_iter().filter_map(|k| latest.remove(&k)).collect(), bad))
    }
}

/// Exclusive run lock.
pub struct RunLock(#[allow(dead_code)] fs::File);

impl RunLock {
    pub fn acquire(state_dir: &Path) -> Result<Self> {
        fs::create_dir_all(state_dir)?;
        let f = fs::OpenOptions::new().create(true).truncate(false).write(true).open(state_dir.join("run.lock"))?;
        // The run timer and the pressure guard can overlap: wait our turn
        // (actions are serialized, never concurrent). Also covers a forked
        // child (e.g. git) transiently holding a copy of the descriptor.
        let start = std::time::Instant::now();
        let mut announced = false;
        loop {
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                if announced {
                    crate::log_info!("lock.acquired", "after waiting {}s", start.elapsed().as_secs());
                }
                return Ok(RunLock(f));
            }
            if !announced && start.elapsed() > std::time::Duration::from_secs(10) {
                crate::log_info!("lock.waiting", "another tree-gc run is acting; waiting for it to finish");
                announced = true;
            }
            if start.elapsed() > std::time::Duration::from_secs(30 * 60) {
                bail!("another tree-gc run has held {} for over 30 minutes", state_dir.join("run.lock").display());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

pub struct ApplyOpts {
    /// Evaluation time. Always the real clock from the CLI; tests may override.
    pub now: i64,
    pub max_actions: usize,
    pub max_bytes: u64,
    pub kinds: Option<Vec<Kind>>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub done: Vec<JEntry>,
    pub skipped: Vec<(Item, String)>,
    pub failed: Vec<(Item, String)>,
    pub stopped_early: Option<String>,
}

pub fn apply(cfg: &Config, plan: &Plan, opts: &ApplyOpts) -> Result<Outcome> {
    if !cfg.enforce {
        bail!("enforce = false in the config (shadow mode); refusing to change anything. Use `tree-gc plan` to simulate.");
    }
    let _lock = RunLock::acquire(&cfg.state_dir)?;
    let interop = InteropLocks::acquire(cfg);
    let journal = Journal::open(&cfg.state_dir)?;
    let mut ctx = Ctx::new(cfg, opts.now);
    if ctx.clock.went_backwards(opts.now) {
        bail!("system clock is earlier than the last tree-gc run; refusing to act until it is correct");
    }
    let mut out = Outcome::default();
    let mut bytes = 0u64;
    for item in plan.items.iter().filter(|i| i.verdict == Verdict::Eligible) {
        if !cfg.enforce_kinds.contains(&item.kind) {
            continue;
        }
        if let Some(k) = &opts.kinds {
            if !k.contains(&item.kind) {
                continue;
            }
        }
        if out.done.len() >= opts.max_actions {
            out.stopped_early = Some(format!("max_actions_per_run ({}) reached", opts.max_actions));
            break;
        }
        if bytes >= opts.max_bytes {
            out.stopped_early = Some(format!("max_gib_per_run ({}) reached", fmt_bytes(Some(opts.max_bytes))));
            break;
        }
        if item.kind == Kind::Artifact && !interop.all_held {
            out.skipped.push((item.clone(), format!("another cleaner holds {}", interop.busy.join(", "))));
            continue;
        }
        match act_one(&mut ctx, &journal, item)? {
            ItemResult::Done(entry) => {
                bytes += entry.bytes.unwrap_or(0);
                out.done.push(entry);
            }
            ItemResult::Skipped(i, why) => out.skipped.push((i, why)),
            ItemResult::Failed(i, why) => out.failed.push((i, why)),
            ItemResult::Deferred(_, why) => {
                out.stopped_early = Some(why);
                break;
            }
        }
    }
    Ok(out)
}

pub enum ItemResult {
    Done(JEntry),
    Skipped(Item, String),
    Failed(Item, String),
    /// Not attempted because the system is under sustained I/O pressure:
    /// the caller should stop this run and leave the rest for later.
    Deferred(Item, String),
}

// ---------------------------------------------------------------- throttling

/// "some avg10" (% of time tasks stalled on I/O over 10s) from /proc/pressure/io.
pub fn parse_io_psi(s: &str) -> Option<f64> {
    let line = s.lines().find(|l| l.starts_with("some "))?;
    line.split_whitespace().find_map(|f| f.strip_prefix("avg10=")).and_then(|v| v.parse().ok())
}

pub fn io_psi() -> Option<f64> {
    parse_io_psi(&fs::read_to_string("/proc/pressure/io").ok()?)
}

/// Wait while I/O pressure is above the limit. false = still busy.
fn wait_for_io(cfg: &Config) -> bool {
    let Some(mut psi) = io_psi() else { return true }; // no PSI support: don't block
    let start = std::time::Instant::now();
    while psi > cfg.throttle_max_io_psi {
        if start.elapsed() >= std::time::Duration::from_secs(cfg.throttle_io_wait_secs) {
            return false;
        }
        crate::log_debug!("throttle.io_wait", "I/O pressure {psi:.1}% > {:.1}%; waiting", cfg.throttle_max_io_psi);
        std::thread::sleep(std::time::Duration::from_secs(2));
        psi = io_psi().unwrap_or(0.0);
    }
    true
}

/// Pause after deleting `bytes`, so the filesystem commits in small steps.
fn pace_after(cfg: &Config, bytes: u64) {
    if cfg.throttle_secs_per_gib <= 0.0 {
        return;
    }
    let gib = bytes as f64 / (1u64 << 30) as f64;
    let secs = (gib * cfg.throttle_secs_per_gib).clamp(0.2, cfg.throttle_max_secs.max(0.2));
    std::thread::sleep(std::time::Duration::from_secs_f64(secs));
}

fn frees_space(a: Option<Action>) -> bool {
    matches!(
        a,
        Some(
            Action::DeleteArtifact
                | Action::DeletePath
                | Action::QuarantineWorktree
                | Action::DockerBuildCache
                | Action::DockerImages
                | Action::DockerContainer
        )
    )
}

/// The single path every action takes: fresh process/mount snapshot,
/// re-evaluation against the live system, structural safety checks, intent
/// journaled, act, outcome journaled. Callers hold the run lock.
pub fn act_one(ctx: &mut Ctx, journal: &Journal, item: &Item) -> Result<ItemResult> {
    let fields = |i: &Item| {
        serde_json::json!({
            "kind": i.kind.label(),
            "action": i.action.map(|a| a.label()),
            "path": i.path,
            "branch": i.branch,
            "id": i.id,
            "pressure": i.pressure,
        })
    };
    ctx.refresh();
    let fresh = reverify(ctx, item);
    if fresh.verdict != Verdict::Eligible {
        let why = fresh.reasons.join("; ");
        crate::log::emit(crate::log::Level::Info, "action.skipped", format!("{}: {why}", display_path(&fresh.path)), fields(&fresh));
        return Ok(ItemResult::Skipped(fresh, why));
    }
    if let Err(e) = safety::check_target(ctx, &fresh) {
        crate::log::emit(
            crate::log::Level::Error,
            "action.refused",
            format!("safety check refused {}: {e:#}", display_path(&fresh.path)),
            fields(&fresh),
        );
        return Ok(ItemResult::Failed(fresh, format!("safety check: {e}")));
    }
    let deletes = frees_space(fresh.action);
    if deletes && !wait_for_io(ctx.cfg) {
        let why = format!(
            "I/O pressure stayed above {:.0}% for {}s; deferring the rest of this run",
            ctx.cfg.throttle_max_io_psi, ctx.cfg.throttle_io_wait_secs
        );
        crate::log::emit(crate::log::Level::Warn, "throttle.io_busy", why.clone(), fields(&fresh));
        return Ok(ItemResult::Deferred(fresh, why));
    }
    let mut entry = new_entry(ctx, &fresh);
    let started = std::time::Instant::now();
    match act(ctx, journal, &fresh, &mut entry) {
        Ok(()) => {
            journal.append(&entry)?;
            if deletes {
                pace_after(ctx.cfg, entry.bytes.unwrap_or(0));
            }
            let mut f = fields(&fresh);
            f["jid"] = entry.jid.clone().into();
            f["status"] = format!("{:?}", entry.status).into();
            f["bytes"] = entry.bytes.into();
            f["ms"] = (started.elapsed().as_millis() as u64).into();
            crate::log::emit(
                crate::log::Level::Info,
                "action.done",
                format!("{} {} ({})", fresh.action.map(|a| a.label()).unwrap_or("?"), display_path(&fresh.path), fmt_bytes(entry.bytes)),
                f,
            );
            Ok(ItemResult::Done(entry))
        }
        Err(e) => {
            entry.status = JStatus::Failed;
            entry.reasons.push(format!("{e:#}"));
            let _ = journal.append(&entry);
            let mut f = fields(&fresh);
            f["jid"] = entry.jid.clone().into();
            f["error"] = format!("{e:#}").into();
            crate::log::emit(
                crate::log::Level::Error,
                "action.failed",
                format!("{} {}: {e:#}", fresh.action.map(|a| a.label()).unwrap_or("?"), display_path(&fresh.path)),
                f,
            );
            Ok(ItemResult::Failed(fresh, format!("{e:#}")))
        }
    }
}

/// Other cleaners' locks (e.g. build-hygiene's), held while deleting build
/// output so two tools never sweep the same `target/` at once.
pub struct InteropLocks {
    _files: Vec<fs::File>,
    pub all_held: bool,
    pub busy: Vec<String>,
}

impl InteropLocks {
    pub fn acquire(cfg: &Config) -> Self {
        let mut files = Vec::new();
        let mut busy = Vec::new();
        for p in &cfg.interop_locks {
            let Ok(f) = fs::OpenOptions::new().create(true).truncate(false).write(true).open(p) else {
                crate::log_warn!("interop.open_failed", "cannot open lock {}; build output is deferred", p.display());
                busy.push(format!("{} (cannot open)", p.display()));
                continue;
            };
            // The other tool's sweep may take a while; wait for it.
            let mut held = false;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(cfg.interop_wait_secs);
            loop {
                if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    held = true;
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if held {
                files.push(f);
            } else {
                crate::log_warn!(
                    "interop.busy",
                    "{} still held after {}s; build output is deferred this run",
                    p.display(),
                    cfg.interop_wait_secs
                );
                busy.push(p.display().to_string());
            }
        }
        InteropLocks { _files: files, all_held: busy.is_empty(), busy }
    }
}

fn new_entry(ctx: &Ctx, item: &Item) -> JEntry {
    JEntry {
        jid: format!("{}-{}", stamp(now_epoch()), item.id),
        ts: ctx.now,
        status: JStatus::Pending,
        action: item.action.unwrap_or(Action::QuarantinePath),
        kind: item.kind,
        path: item.path.clone(),
        repo: item.repo.clone(),
        branch: item.branch.clone(),
        sha: item.head.clone(),
        archive_ref: None,
        qdir: None,
        admin_dir: item.admin_dir.clone(),
        bytes: item.bytes,
        reasons: item.reasons.clone(),
    }
}

fn act(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    let action = item.action.ok_or_else(|| anyhow!("no action"))?;
    match action {
        Action::ArchiveBranch => archive_branch(ctx, j, item, e),
        Action::DeleteArtifact | Action::DeletePath => delete_path(ctx, j, item, e),
        Action::QuarantinePath => quarantine_path(ctx, j, item, e),
        Action::QuarantineWorktree => quarantine_worktree(ctx, j, item, e),
        Action::PruneWorktreeMeta => prune_meta(ctx, j, item, e),
        Action::DockerBuildCache | Action::DockerImages | Action::DockerContainer => docker_act(ctx, j, item, e, action),
    }
}

fn docker_act(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry, action: Action) -> Result<()> {
    let d = &ctx.cfg.docker;
    if !d.enabled {
        bail!("docker handling is disabled");
    }
    j.append(e)?;
    // Under measured/predicted disk pressure, shorter ages apply.
    let (cache_h, image_h) = if ctx.pressure_active {
        (d.pressure_build_cache_hours, d.pressure_image_days * 24)
    } else {
        (d.build_cache_days * 24, d.image_days * 24)
    };
    e.bytes = match action {
        Action::DockerBuildCache => crate::docker::prune_build_cache(ctx.cfg, cache_h)?,
        Action::DockerImages => crate::docker::prune_images(ctx.cfg, image_h)?,
        _ => {
            let id = item.head.as_deref().ok_or_else(|| anyhow!("no container id"))?;
            crate::docker::remove_container(ctx.cfg, id, item.last_activity)?;
            item.bytes
        }
    };
    e.status = JStatus::Done;
    Ok(())
}

/// Refuse if anything at or below `p` is a mount point *right now*.
fn no_mounts_below(p: &Path) -> Result<()> {
    if let Some(m) = mount_at_or_below(&mounts(), p) {
        bail!("refusing: mount point {} at or below {}", m.display(), p.display());
    }
    Ok(())
}

fn archive_branch(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    let repo = item.repo.as_ref().ok_or_else(|| anyhow!("no repo"))?;
    let name = item.branch.as_ref().ok_or_else(|| anyhow!("no branch"))?;
    let sha = item.head.as_ref().ok_or_else(|| anyhow!("no sha"))?;
    let aref = format!("{}heads/{}/{}", ctx.cfg.branches.archive_prefix, name, &sha[..12.min(sha.len())]);
    e.archive_ref = Some(aref.clone());
    e.bytes = None;
    j.append(e)?;
    let mut cmds = Vec::new();
    match git::ref_value(repo, &aref) {
        Some(v) if &v == sha => {}
        Some(_) => bail!("archive ref {aref} exists with a different value"),
        None => cmds.push(format!("create {aref} {sha}")),
    }
    // Keep the branch's reflog alive under the archive ref: commits reachable
    // only from that reflog (amended/reset-away work) stay protected from gc.
    let common = git::common_dir(repo)?;
    let src_log = common.join("logs/refs/heads").join(name);
    if src_log.is_file() {
        let dst_log = common.join("logs").join(&aref);
        if let Some(p) = dst_log.parent() {
            fs::create_dir_all(p)?;
        }
        if !dst_log.exists() {
            fs::copy(&src_log, &dst_log)?;
        }
    }
    // Old-value check makes this a compare-and-swap: fails if the branch moved.
    cmds.push(format!("delete refs/heads/{name} {sha}"));
    git::update_refs(repo, &cmds)?;
    e.status = JStatus::Archived;
    Ok(())
}

fn archive_head(ctx: &Ctx, repo: &Path, admin: &Path, sha: &str) -> Result<String> {
    let id = admin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let aref = format!("{}worktrees/{}/{}", ctx.cfg.branches.archive_prefix, id, &sha[..12.min(sha.len())]);
    if git::ref_value(repo, &aref).is_none() {
        git::update_refs(repo, &[format!("create {aref} {sha}")])?;
    }
    Ok(aref)
}

/// Prefix of dirs that are mid-deletion (renamed aside first).
pub const DELETING_PREFIX: &str = ".tree-gc-deleting-";

/// Rename `p` aside, then delete it. Builds never see a half-deleted dir:
/// it is either fully present or gone. If deletion fails part-way (e.g.
/// root-owned files from a docker/sudo build), the renamed remainder is
/// cleaned up by `sweep_deleting` on later runs.
fn remove_tree_atomically(p: &Path, id: &str) -> Result<()> {
    let parent = p.parent().ok_or_else(|| anyhow!("no parent"))?;
    let aside = parent.join(format!("{DELETING_PREFIX}{id}"));
    rename_noreplace(p, &aside).with_context(|| format!("renaming {} aside", p.display()))?;
    fs::remove_dir_all(&aside).with_context(|| format!("removing {} (left as {})", p.display(), aside.display()))
}

/// Finish deletions that failed part-way in earlier runs. Only touches our
/// own `.tree-gc-deleting-*` dirs, directly inside the given parents.
pub fn sweep_deleting(parents: &[PathBuf]) -> Vec<String> {
    let mut errs = Vec::new();
    for parent in parents {
        let Ok(rd) = fs::read_dir(parent) else { continue };
        for e in rd.flatten() {
            let is_ours = e.file_name().to_string_lossy().starts_with(DELETING_PREFIX)
                && e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_ours && no_mounts_below(&e.path()).is_ok() {
                if let Err(err) = fs::remove_dir_all(e.path()) {
                    errs.push(format!("{}: {err}", e.path().display()));
                }
            }
        }
    }
    errs
}

/// Release executables in a Cargo target dir, as paths relative to it.
fn release_binaries(target: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs = vec![PathBuf::from("release")];
    if let Ok(rd) = fs::read_dir(target) {
        for e in rd.flatten() {
            if e.path().join("release").is_dir() && e.file_name().to_string_lossy().matches('-').count() >= 2 {
                dirs.push(PathBuf::from(e.file_name()).join("release"));
            }
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        let Ok(rd) = fs::read_dir(target.join(&d)) else { continue };
        for f in rd.flatten() {
            let Ok(m) = f.metadata() else { continue };
            let name = f.file_name();
            let n = name.to_string_lossy();
            // Executables, not build intermediates (.d, .rlib, .so, ...).
            if m.is_file() && m.permissions().mode() & 0o111 != 0 && !n.contains('.') {
                out.push(d.join(&name));
            }
        }
    }
    out
}

fn delete_path(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    let p = &item.path;
    let m = fs::symlink_metadata(p)?;
    if m.is_dir() {
        // Final checks right before an irreversible delete.
        no_mounts_below(p)?;
        if let Some(why) = crate::scan::scan_protection(ctx, p, &dir_scan(p, &ctx.cfg.keep_marker)) {
            bail!("refusing to delete {}: {why}", p.display());
        }
        let keep = if item.action == Some(Action::DeleteArtifact)
            && ctx.cfg.artifacts.preserve_release_binaries
            && p.file_name().is_some_and(|n| n == "target")
        {
            release_binaries(p)
        } else {
            vec![]
        };
        if !keep.is_empty() {
            let qroot = ctx
                .quarantine_root(p, item.root.as_deref())
                .ok_or_else(|| anyhow!("no same-filesystem quarantine for release binaries"))?;
            let qdir = make_qdir(&qroot, item)?;
            e.qdir = Some(qdir.clone());
            write_manifest(&qdir, e)?;
            j.append(e)?;
            for rel in &keep {
                let dst = qdir.join("payload").join(rel);
                fs::create_dir_all(dst.parent().unwrap())?;
                rename_noreplace(&p.join(rel), &dst)?;
            }
            e.reasons.push(format!("kept {} release binar(ies) in quarantine", keep.len()));
        } else {
            j.append(e)?;
        }
        remove_tree_atomically(p, &item.id)?;
        if !keep.is_empty() {
            e.status = JStatus::Quarantined; // binaries restorable until purged
            return Ok(());
        }
    } else {
        j.append(e)?;
        fs::remove_file(p)?;
    }
    e.status = JStatus::Done;
    Ok(())
}

/// Create (or validate) a quarantine root: ours, a real dir, mode 0700.
fn ensure_qroot(qroot: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if qroot.symlink_metadata().is_err() {
        if let Some(p) = qroot.parent() {
            fs::create_dir_all(p)?;
        }
        fs::DirBuilder::new().mode(0o700).create(qroot)?;
    }
    let m = fs::symlink_metadata(qroot)?;
    if !m.is_dir() || m.uid() != uid() {
        bail!("quarantine {} is not a directory owned by us; refusing", qroot.display());
    }
    if m.mode() & 0o077 != 0 {
        fs::set_permissions(qroot, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn make_qdir(qroot: &Path, item: &Item) -> Result<PathBuf> {
    ensure_qroot(qroot)?;
    let q = qroot.join(format!("{}-{}-{}", stamp(now_epoch()), item.kind.label(), item.id));
    fs::create_dir(&q)?;
    Ok(q)
}

fn write_manifest(qdir: &Path, e: &JEntry) -> Result<()> {
    fs::write(qdir.join("manifest.json"), serde_json::to_vec_pretty(e)?)?;
    Ok(())
}

fn quarantine_path(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    no_mounts_below(&item.path)?;
    let qroot = ctx
        .quarantine_root(&item.path, item.root.as_deref())
        .ok_or_else(|| anyhow!("no same-filesystem quarantine"))?;
    let qdir = make_qdir(&qroot, item)?;
    e.qdir = Some(qdir.clone());
    write_manifest(&qdir, e)?;
    j.append(e)?;
    rename_noreplace(&item.path, &qdir.join("payload")).with_context(|| format!("moving {}", item.path.display()))?;
    e.status = JStatus::Quarantined;
    Ok(())
}

fn quarantine_worktree(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    let wt = &item.path;
    let repo = item.repo.as_ref().ok_or_else(|| anyhow!("no repo"))?;
    let admin = item.admin_dir.as_ref().ok_or_else(|| anyhow!("no admin dir"))?;
    no_mounts_below(wt)?;
    // The worktree's .git file must point at exactly this admin dir.
    let gitfile = fs::read_to_string(wt.join(".git"))?;
    let target = gitfile.trim().strip_prefix("gitdir:").map(|s| PathBuf::from(s.trim())).unwrap_or_default();
    if canon(&wt.join(target)) != canon(admin) {
        bail!("{}/.git does not point at {}", wt.display(), admin.display());
    }
    let qroot = ctx.quarantine_root(wt, None).ok_or_else(|| anyhow!("no same-filesystem quarantine"))?;
    if ctx.quarantine_root(admin, None).as_ref() != Some(&qroot) {
        bail!("admin dir and worktree are on different filesystems");
    }
    // Decide what to strip *before* moving (needs git), delete only *after*
    // the move succeeded, so a failed move never costs anything.
    let mut strip: Vec<String> = Vec::new();
    if ctx.cfg.worktrees.strip_artifacts {
        for rel in git::status(wt)?.ignored {
            let rel = rel.trim_end_matches('/').to_string();
            let p = wt.join(&rel);
            let Ok(m) = fs::symlink_metadata(&p) else { continue };
            if !m.is_dir() || !p.starts_with(wt) {
                continue;
            }
            // Full artifact identity + protections (refs, PATH links, in-use,
            // nested repos, keep markers, mounts). Anything protected simply
            // travels into quarantine with the rest of the tree.
            let a = crate::scan::eval_artifact(ctx, &p, Some(wt));
            let nested = crate::scan::scan_protection(ctx, &p, &dir_scan(&p, &ctx.cfg.keep_marker));
            if a.verdict != Verdict::Protected && nested.is_none() {
                strip.push(rel);
            }
        }
    }
    if item.branch.is_none() {
        if let Some(h) = &item.head {
            e.archive_ref = Some(archive_head(ctx, repo, admin, h)?);
        }
    }
    let qdir = make_qdir(&qroot, item)?;
    e.qdir = Some(qdir.clone());
    write_manifest(&qdir, e)?;
    j.append(e)?;
    let tree = qdir.join("tree");
    rename_noreplace(wt, &tree).with_context(|| format!("moving {}", wt.display()))?;
    if let Err(err) = rename_noreplace(admin, &qdir.join("admin")) {
        let _ = rename_noreplace(&tree, wt); // roll back
        bail!("moving admin dir failed ({err}); worktree left in place");
    }
    e.status = JStatus::Quarantined;
    let mut stripped = 0u64;
    for rel in strip {
        let p = tree.join(&rel);
        if no_mounts_below(&p).is_ok() && fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false) {
            stripped += dir_size(&p);
            if fs::remove_dir_all(&p).is_err() {
                e.reasons.push(format!("could not strip {rel}; left in quarantine"));
            }
        }
    }
    e.reasons.push(format!("stripped {} of build artifacts", fmt_bytes(Some(stripped))));
    Ok(())
}

fn prune_meta(ctx: &Ctx, j: &Journal, item: &Item, e: &mut JEntry) -> Result<()> {
    let repo = item.repo.as_ref().ok_or_else(|| anyhow!("no repo"))?;
    let admin = item.admin_dir.as_ref().ok_or_else(|| anyhow!("no admin dir"))?;
    if !admin.join("gitdir").is_file() || admin.parent().and_then(|p| p.file_name()) != Some("worktrees".as_ref()) {
        bail!("{} does not look like a worktree admin dir", admin.display());
    }
    if item.path.symlink_metadata().is_ok() {
        bail!("{} exists again", item.path.display());
    }
    let qroot = ctx.quarantine_root(admin, None).ok_or_else(|| anyhow!("no same-filesystem quarantine"))?;
    if item.branch.is_none() {
        if let Some(h) = &item.head {
            e.archive_ref = Some(archive_head(ctx, repo, admin, h)?);
        }
    }
    let qdir = make_qdir(&qroot, item)?;
    e.qdir = Some(qdir.clone());
    write_manifest(&qdir, e)?;
    j.append(e)?;
    rename_noreplace(admin, &qdir.join("admin"))?;
    e.status = JStatus::Quarantined;
    Ok(())
}

// ---------------------------------------------------------------- purge / restore

/// A per-item quarantine dir: a *direct child* of the global quarantine or of
/// a `.tree-gc-quarantine-*` fallback dir. Never a quarantine root itself.
fn qdir_is_ours(cfg: &Config, q: &Path) -> bool {
    let Some(parent) = q.parent() else { return false };
    let direct_child = parent == cfg.quarantine_dir || parent.file_name().is_some_and(is_quarantine_name);
    direct_child && q.components().count() >= 4 && !has_parent_components(q) && q.file_name().is_some_and(|n| !is_quarantine_name(n))
}

#[cfg(test)]
mod throttle_tests {
    use super::parse_io_psi;
    #[test]
    fn parses_psi() {
        let s = "some avg10=12.34 avg60=1.00 avg300=0.50 total=123\nfull avg10=3.00 avg60=0.00 avg300=0.00 total=9\n";
        assert_eq!(parse_io_psi(s), Some(12.34));
        assert_eq!(parse_io_psi("garbage"), None);
    }
}

#[derive(Debug, Default)]
pub struct PurgeReport {
    pub purged: Vec<JEntry>,
    pub errors: Vec<(String, String)>,
}

/// Purge expired quarantine. One bad entry never blocks the others.
pub fn purge(cfg: &Config, now: i64) -> Result<PurgeReport> {
    if !cfg.enforce {
        bail!("enforce = false; refusing to purge quarantine");
    }
    let _lock = RunLock::acquire(&cfg.state_dir)?;
    let clock = crate::clock::ActivityClock::load(&cfg.state_dir);
    if clock.went_backwards(now) {
        bail!("system clock is earlier than the last tree-gc run; refusing to purge until it is correct");
    }
    let j = Journal::open(&cfg.state_dir)?;
    let mut rep = PurgeReport::default();
    for e in j.load()? {
        // The restore window is counted in in-use days (time away or a clock
        // jump never silently expires it), and at least the calendar TTL.
        let expired = now - e.ts >= cfg.quarantine_days as i64 * DAY
            && clock.idle_days(e.ts, now) >= cfg.quarantine_days as i64;
        if e.status != JStatus::Quarantined || !expired || e.qdir.is_none() {
            continue;
        }
        let jid = e.jid.clone();
        match purge_entry(cfg, &j, e, now, None) {
            Ok(e) => rep.purged.push(e),
            Err(err) => {
                crate::log_error!("purge.failed", "{jid}: {err:#}");
                rep.errors.push((jid, format!("{err:#}")))
            }
        }
    }
    Ok(rep)
}

/// Permanently delete one quarantined entry (caller holds the run lock).
/// `early` records why it was purged before its TTL (disk pressure).
pub fn purge_entry(cfg: &Config, j: &Journal, mut e: JEntry, now: i64, early: Option<&str>) -> Result<JEntry> {
    let q = e.qdir.clone().ok_or_else(|| anyhow!("no quarantine dir"))?;
    if !qdir_is_ours(cfg, &q) {
        bail!("{} is not inside a tree-gc quarantine", q.display());
    }
    if fs::symlink_metadata(&q).is_ok() {
        no_mounts_below(&q)?;
        fs::remove_dir_all(&q)?;
    }
    e.status = JStatus::Purged;
    e.ts = now;
    if let Some(why) = early {
        e.reasons.push(format!("purged early: {why}"));
    }
    j.append(&e)?;
    crate::log::emit(
        crate::log::Level::Info,
        "purge.done",
        format!("{} ({}){}", display_path(&e.path), e.jid, early.map(|w| format!(" early: {w}")).unwrap_or_default()),
        serde_json::json!({"jid": e.jid, "kind": e.kind.label(), "qdir": q}),
    );
    Ok(e)
}

fn find_entry(entries: Vec<JEntry>, id: &str) -> Result<JEntry> {
    if let Some(e) = entries.iter().find(|e| e.jid == id) {
        return Ok(e.clone());
    }
    let m: Vec<JEntry> = entries.into_iter().filter(|e| e.jid.ends_with(id)).collect();
    match m.len() {
        0 => bail!("no journal entry {id}"),
        1 => Ok(m.into_iter().next().unwrap()),
        n => bail!("{id} matches {n} entries; use the full id: {}", m.iter().map(|e| e.jid.as_str()).collect::<Vec<_>>().join(", ")),
    }
}

fn move_back(from: &Path, to: &Path) -> Result<()> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?; // e.g. .git/worktrees removed by `git worktree prune`
    }
    rename_noreplace(from, to).with_context(|| format!("restoring {} -> {}", from.display(), to.display()))
}

pub fn restore(cfg: &Config, jid: &str) -> Result<JEntry> {
    let _lock = RunLock::acquire(&cfg.state_dir)?;
    let j = Journal::open(&cfg.state_dir)?;
    let mut e = find_entry(j.load()?, jid)?;
    // Pending = tree-gc stopped mid-action; Failed = e.g. a rollback that
    // itself failed. Either way, restore whatever is sitting in the qdir.
    let has_payload = e.qdir.as_ref().is_some_and(|q| {
        qdir_is_ours(cfg, q) && ["payload", "tree", "admin"].iter().any(|n| q.join(n).symlink_metadata().is_ok())
    });
    let quarantined = e.status == JStatus::Quarantined
        || (matches!(e.status, JStatus::Pending | JStatus::Failed) && has_payload);
    match e.action {
        Action::ArchiveBranch if matches!(e.status, JStatus::Archived | JStatus::Pending) => {
            let repo = e.repo.as_ref().ok_or_else(|| anyhow!("no repo"))?;
            let name = e.branch.as_ref().ok_or_else(|| anyhow!("no branch"))?;
            let sha = e.sha.as_ref().ok_or_else(|| anyhow!("no sha"))?;
            git::update_refs(repo, &[format!("create refs/heads/{name} {sha}")])
                .with_context(|| format!("branch {name} already exists?"))?;
        }
        Action::QuarantinePath if quarantined => {
            let q = e.qdir.as_ref().unwrap();
            if q.join("payload").symlink_metadata().is_err() {
                bail!(
                    "quarantined copy {} no longer exists (tmpfs cleared at reboot, or removed by systemd-tmpfiles/another cleaner)",
                    q.display()
                );
            }
            move_back(&q.join("payload"), &e.path)?;
            let _ = fs::remove_file(q.join("manifest.json"));
            let _ = fs::remove_dir(q);
        }
        Action::QuarantineWorktree if quarantined => {
            let q = e.qdir.as_ref().unwrap();
            let admin = e.admin_dir.as_ref().ok_or_else(|| anyhow!("no admin dir"))?;
            if q.join("admin").exists() {
                move_back(&q.join("admin"), admin)?;
            }
            if q.join("tree").exists() {
                if let Err(err) = move_back(&q.join("tree"), &e.path) {
                    let _ = rename_noreplace(admin, &q.join("admin"));
                    return Err(err);
                }
            }
            let _ = fs::remove_file(q.join("manifest.json"));
            let _ = fs::remove_dir(q);
        }
        Action::PruneWorktreeMeta if quarantined => {
            let q = e.qdir.as_ref().unwrap();
            let admin = e.admin_dir.as_ref().ok_or_else(|| anyhow!("no admin dir"))?;
            move_back(&q.join("admin"), admin)?;
            let _ = fs::remove_file(q.join("manifest.json"));
            let _ = fs::remove_dir(q);
        }
        Action::DeleteArtifact if quarantined => {
            // Put preserved release binaries back (the rest is rebuilt by cargo).
            let q = e.qdir.as_ref().unwrap().clone();
            let payload = q.join("payload");
            for f in walkdir::WalkDir::new(&payload).follow_links(false).into_iter().flatten() {
                if f.file_type().is_file() {
                    let rel = f.path().strip_prefix(&payload).unwrap();
                    move_back(f.path(), &e.path.join(rel))?;
                }
            }
            let _ = fs::remove_dir_all(&payload);
            let _ = fs::remove_file(q.join("manifest.json"));
            let _ = fs::remove_dir(&q);
        }
        Action::DeleteArtifact | Action::DeletePath if e.status == JStatus::Done => {
            bail!("{} was deleted (regenerable output); rebuild it instead", e.path.display())
        }
        _ => bail!("entry is {:?}; nothing to restore", e.status),
    }
    e.status = JStatus::Restored;
    e.ts = now_epoch();
    j.append(&e)?;
    crate::log_info!("restore.done", "{} ({:?}, {})", display_path(&e.path), e.action, e.jid);
    Ok(e)
}
