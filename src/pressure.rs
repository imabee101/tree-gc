//! Disk-pressure relief: proactive, lowest-risk first, measured.
//!
//! Levels (per filesystem):
//!   Soft     free < soft_free_percent, or *predicted* to get there within
//!            predict_horizon_hours at the recent fill rate
//!   Hard     free < low_free_percent / low_free_gib, or predicted to
//!   Critical free < critical_free_percent (alert after all tiers)
//!
//! Tiers, in order of risk. Soft runs 1-3; Hard and Critical run 1-6.
//!   1. docker build cache unused >= pressure_build_cache_hours
//!   2. build output that is already eligible (stale)
//!   3. build output untouched >= min_age_days, least recently used first
//!   4. `cargo sweep --time min_age_days` inside targets still being worked on
//!   5. quarantine purged early: worktrees (rebuildable from git) first
//!   6. docker images no container uses, created >= pressure_image_days ago
//!
//! Free space is re-measured after every single action and relief stops as
//! soon as every pressured filesystem is back at target_free_percent. Never
//! touched: protected items, anything in use, anything touched within
//! min_age_days.
use crate::config::{Config, PressureCfg};
use crate::exec::{act_one, purge_entry, InteropLocks, ItemResult, JStatus, Journal, RunLock};
use crate::model::{Action, Item, Kind, Verdict};
use crate::scan::{build_plan, Ctx};
use crate::util::*;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    Soft,
    Hard,
    Critical,
}

fn pct(total: u64, avail: u64) -> f64 {
    if total == 0 { 100.0 } else { avail as f64 * 100.0 / total as f64 }
}

/// Absolute free-space floor (a big build can eat tens of GiB at once, so 10%
/// of a medium disk is too little headroom). Not applied to small
/// filesystems (tmpfs, /boot), and capped at 15% of the filesystem so it
/// never dominates on modest disks.
fn abs_floor(p: &PressureCfg, total: u64) -> f64 {
    if (total as f64) < 64.0 * GIB {
        return 0.0;
    }
    (p.low_free_gib * GIB).min(0.15 * total as f64)
}

pub fn level_now(p: &PressureCfg, total: u64, avail: u64) -> Level {
    let f = pct(total, avail);
    if total == 0 {
        Level::None
    } else if f < p.critical_free_percent {
        Level::Critical
    } else if f < p.low_free_percent || (avail as f64) < abs_floor(p, total) {
        Level::Hard
    } else if f < p.soft_free_percent {
        Level::Soft
    } else {
        Level::None
    }
}

/// Free space is low enough that relief may act (soft or worse), right now.
pub fn under_pressure(p: &PressureCfg, total: u64, avail: u64) -> bool {
    level_now(p, total, avail) >= Level::Soft
}

/// Bytes available at which relief stops.
pub fn target_avail(p: &PressureCfg, total: u64) -> u64 {
    ((p.target_free_percent / 100.0) * total as f64).max(abs_floor(p, total)) as u64
}

// ---------------------------------------------------------------- history / trend

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub ts: i64,
    pub dev: u64,
    pub total: u64,
    pub avail: u64,
}

const HISTORY: &str = "disk-history.jsonl";

pub fn record_sample(state_dir: &Path, s: &Sample) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join(HISTORY);
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{}", serde_json::to_string(s)?)?;
    // Keep the file small: compact to the last 7 days now and then.
    if fs::metadata(&path).map(|m| m.len() > 4 << 20).unwrap_or(false) {
        let keep: Vec<Sample> = load_samples(state_dir).into_iter().filter(|x| x.ts >= s.ts - 7 * DAY).collect();
        let tmp = state_dir.join(format!("{HISTORY}.tmp"));
        let mut out = String::new();
        for x in keep {
            out.push_str(&serde_json::to_string(&x)?);
            out.push('\n');
        }
        fs::write(&tmp, out)?;
        fs::rename(tmp, path)?;
    }
    Ok(())
}

pub fn load_samples(state_dir: &Path) -> Vec<Sample> {
    fs::read_to_string(state_dir.join(HISTORY))
        .map(|s| s.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
        .unwrap_or_default()
}

/// Bytes consumed per hour (positive = filling), by least squares over
/// `(ts, avail)` samples. Needs 3+ samples spanning at least 20 minutes.
pub fn fill_rate(samples: &[(i64, u64)]) -> Option<f64> {
    if samples.len() < 3 {
        return None;
    }
    let (t0, t1) = (samples.iter().map(|s| s.0).min()?, samples.iter().map(|s| s.0).max()?);
    if t1 - t0 < 20 * 60 {
        return None;
    }
    let n = samples.len() as f64;
    let mx = samples.iter().map(|s| (s.0 - t0) as f64).sum::<f64>() / n;
    let my = samples.iter().map(|s| s.1 as f64).sum::<f64>() / n;
    let (mut num, mut den) = (0.0, 0.0);
    for s in samples {
        let dx = (s.0 - t0) as f64 - mx;
        num += dx * (s.1 as f64 - my);
        den += dx * dx;
    }
    (den > 0.0).then(|| -(num / den) * 3600.0)
}

/// The level the trend says we'll reach within the horizon, with a reason.
pub fn predicted_level(p: &PressureCfg, total: u64, avail: u64, rate_per_hour: Option<f64>) -> (Level, Option<String>) {
    let Some(rate) = rate_per_hour.filter(|r| *r > 0.0) else { return (Level::None, None) };
    let hard_at = ((p.low_free_percent / 100.0) * total as f64).max(abs_floor(p, total));
    let soft_at = (p.soft_free_percent / 100.0) * total as f64;
    for (lvl, at, name) in [(Level::Hard, hard_at, "low"), (Level::Soft, soft_at, "soft")] {
        if (avail as f64) > at {
            let hours = (avail as f64 - at) / rate;
            if hours <= p.predict_horizon_hours {
                return (
                    lvl,
                    Some(format!(
                        "filling at {}/h: reaches the {name} threshold in {hours:.1}h",
                        fmt_bytes(Some(rate as u64))
                    )),
                );
            }
        }
    }
    (Level::None, None)
}

#[derive(Debug, Clone)]
pub struct FsStatus {
    pub probe: PathBuf,
    pub dev: u64,
    pub total: u64,
    pub avail: u64,
    pub level: Level,
    pub why: String,
}

impl FsStatus {
    pub fn describe(&self) -> String {
        format!(
            "{}: {:.1}% free ({}) -> {:?}{}",
            display_path(&self.probe),
            pct(self.total, self.avail),
            fmt_bytes(Some(self.avail)),
            self.level,
            if self.why.is_empty() { String::new() } else { format!(" ({})", self.why) }
        )
    }
}

/// Filesystems worth watching: every root, the quarantine, docker's data root.
pub fn probes(cfg: &Config) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = cfg.roots.iter().map(|r| r.path.clone()).filter(|p| p.exists()).collect();
    if let Some(q) = cfg.quarantine_dir.ancestors().find(|a| a.exists()) {
        v.push(q.to_path_buf());
    }
    if let Some(root) = crate::docker::snapshot_root(cfg) {
        v.push(root);
    }
    v
}

/// Current status of each watched filesystem; optionally records a sample
/// for the trend (the guard does, every tick).
pub fn status(cfg: &Config, now: i64, record: bool) -> Vec<FsStatus> {
    let p = &cfg.pressure;
    let samples = load_samples(&cfg.state_dir);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mt = mounts();
    for probe in probes(cfg) {
        // Group by filesystem, not device: btrfs subvolumes share space.
        let Some(dev) = fs_key(&mt, &probe) else { continue };
        if !seen.insert(dev) {
            continue;
        }
        let Some((total, avail)) = fs_usage(&probe) else { continue };
        if record {
            let _ = record_sample(&cfg.state_dir, &Sample { ts: now, dev, total, avail });
        }
        let window = (p.trend_window_hours * 3600.0) as i64;
        let mut pts: Vec<(i64, u64)> = samples
            .iter()
            .filter(|s| s.dev == dev && s.ts >= now - window && s.ts <= now)
            .map(|s| (s.ts, s.avail))
            .collect();
        pts.push((now, avail));
        let now_lvl = level_now(p, total, avail);
        let (pred_lvl, pred_why) = predicted_level(p, total, avail, fill_rate(&pts));
        let (level, why) = if pred_lvl > now_lvl {
            (pred_lvl, pred_why.unwrap_or_default())
        } else {
            (now_lvl, String::new())
        };
        out.push(FsStatus { probe, dev, total, avail, level, why });
    }
    out
}

// ---------------------------------------------------------------- relief

#[derive(Debug, Default)]
pub struct ReliefReport {
    pub before: Vec<String>,
    pub steps: Vec<String>,
    pub after: Vec<String>,
    pub reached: bool,
    pub shadow: bool,
    pub critical_after: bool,
    pub failed: usize,
    /// Deletions stopped freeing space (snapshot / shared extents).
    pub stalled: bool,
    /// Stopped at max_gib_per_relief for this pass.
    pub capped: bool,
    /// Relief skipped because an earlier run stalled and nothing changed since.
    pub paused: bool,
}

/// After a stall, relief waits for free space to rise, or this long.
pub const PAUSE_HOURS: i64 = 24;
const PAUSE_FILE: &str = "relief-paused.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pause {
    pub ts: i64,
    /// Total available bytes (pressured filesystems) when relief stalled.
    pub avail: u64,
}

pub fn read_pause(state_dir: &Path) -> Option<Pause> {
    serde_json::from_slice(&fs::read(state_dir.join(PAUSE_FILE)).ok()?).ok()
}

fn write_pause(state_dir: &Path, p: &Pause) -> Result<()> {
    fs::write(state_dir.join(PAUSE_FILE), serde_json::to_vec(p)?)?;
    Ok(())
}

/// Still paused if less than PAUSE_HOURS passed and free space hasn't risen
/// by at least 1% of `total` (or 5 GiB) since the stall.
pub fn pause_holds(p: &Pause, now: i64, avail: u64, total: u64) -> bool {
    let rose = avail.saturating_sub(p.avail) >= (total / 100).min(5 << 30);
    now - p.ts < PAUSE_HOURS * 3600 && !rose
}

fn kind_allowed(cfg: &Config, k: Kind) -> bool {
    cfg.enforce_kinds.contains(&k)
}

/// Relieve disk pressure if any watched filesystem needs it.
pub fn relieve(cfg: &Config, now: i64) -> Result<ReliefReport> {
    let mut rep = ReliefReport::default();
    let statuses = status(cfg, now, true);
    rep.before = statuses.iter().map(FsStatus::describe).collect();
    for s in &statuses {
        let lvl = if s.level >= Level::Soft { crate::log::Level::Info } else { crate::log::Level::Debug };
        crate::log::emit(
            lvl,
            "pressure.level",
            s.describe(),
            serde_json::json!({"probe": s.probe, "free_pct": pct(s.total, s.avail), "avail": s.avail, "level": format!("{:?}", s.level)}),
        );
    }
    let pressured: BTreeMap<u64, &FsStatus> =
        statuses.iter().filter(|s| s.level >= Level::Soft).map(|s| (s.dev, s)).collect();
    if pressured.is_empty() || !cfg.pressure.enabled {
        rep.reached = true;
        return Ok(rep);
    }
    let hard = pressured.values().any(|s| s.level >= Level::Hard);
    if !cfg.enforce {
        rep.shadow = true;
        rep.steps.push(format!(
            "shadow mode: would run tiers 1-{} until {}% free",
            if hard { 6 } else { 3 },
            cfg.pressure.target_free_percent
        ));
        crate::log_info!("pressure.shadow", "{}", rep.steps[0]);
        return Ok(rep);
    }
    if let Some(p) = read_pause(&cfg.state_dir) {
        let avail: u64 = pressured.values().map(|s| s.avail).sum();
        let total: u64 = pressured.values().map(|s| s.total).sum();
        if pause_holds(&p, now, avail, total) {
            rep.paused = true;
            rep.reached = false;
            rep.steps.push(format!(
                "paused: earlier deletions freed nothing (snapshot?); resumes when free space rises or {}h after {}",
                PAUSE_HOURS,
                fmt_ts(p.ts)
            ));
            crate::log_info!("pressure.paused", "{}", rep.steps[0]);
            if pressured.values().any(|s| s.level == Level::Critical) {
                rep.critical_after = true;
                crate::log_error!(
                    "pressure.critical",
                    "disk critically low and relief is paused because deletions aren't freeing space: {}",
                    rep.before.join("; ")
                );
            }
            return Ok(rep);
        }
        let _ = fs::remove_file(cfg.state_dir.join(PAUSE_FILE));
        crate::log_info!("pressure.resumed", "free space changed or {PAUSE_HOURS}h passed since the stall; relief resumes");
    }
    crate::log_info!(
        "pressure.relief_start",
        "{} relief (tiers 1-{}) until {}% free",
        if hard { "hard" } else { "soft" },
        if hard { 6 } else { 3 },
        cfg.pressure.target_free_percent
    );

    let _lock = RunLock::acquire(&cfg.state_dir)?;
    let interop = InteropLocks::acquire(cfg);
    let journal = Journal::open(&cfg.state_dir)?;
    let mut ctx = Ctx::new(cfg, now);
    if ctx.clock.went_backwards(now) {
        bail!("system clock is earlier than the last tree-gc run; refusing to act until it is correct");
    }
    ctx.pressure_active = true;
    let devs: HashSet<u64> = pressured.keys().copied().collect();
    let hard_devs: HashSet<u64> = pressured.values().filter(|s| s.level >= Level::Hard).map(|s| s.dev).collect();
    let probes: Vec<PathBuf> = pressured.values().map(|s| s.probe.clone()).collect();
    let target_met = || probes.iter().all(|p| fs_usage(p).is_some_and(|(t, a)| a >= target_avail(&cfg.pressure, t)));
    let avail_sum = || probes.iter().filter_map(|p| fs_usage(p).map(|x| x.1)).sum::<u64>();
    // No-progress brake: deletions that free nothing (a btrfs snapshot or
    // shared extents keep the data alive) must not continue down the list.
    let start_avail = avail_sum();
    let reported = std::cell::Cell::new(0u64);
    let stalled = std::cell::Cell::new(false);
    let capped = std::cell::Cell::new(false);
    let deferred = std::cell::Cell::new(false);
    let cap = (cfg.pressure.max_gib_per_relief * GIB) as u64;
    let satisfied = || {
        if target_met() {
            return true;
        }
        if deferred.get() {
            return true; // sustained I/O pressure: stop, next tick continues
        }
        if reported.get() >= cap {
            capped.set(true);
            return true; // gentle: the next guard tick continues
        }
        let r = reported.get();
        let gained = avail_sum().saturating_sub(start_avail);
        if r >= (cfg.pressure.stall_min_gib * GIB) as u64 && gained.saturating_mul(10) < r {
            stalled.set(true);
            return true;
        }
        false
    };
    let mt = mounts();
    let on = |set: &HashSet<u64>, p: &Path| fs_key(&mt, p).is_some_and(|d| set.contains(&d));

    let run_item = |ctx: &mut Ctx, item: Item, tier: &str, rep: &mut ReliefReport| -> Result<()> {
        match act_one(ctx, &journal, &item)? {
            ItemResult::Done(e) => {
                reported.set(reported.get() + e.bytes.unwrap_or(0));
                rep.steps.push(format!("tier {tier}: {:?} {} ({})", e.action, display_path(&e.path), fmt_bytes(e.bytes)))
            }
            ItemResult::Skipped(i, why) => rep.steps.push(format!("tier {tier}: skipped {} ({why})", display_path(&i.path))),
            ItemResult::Failed(i, why) => {
                rep.failed += 1;
                rep.steps.push(format!("tier {tier}: FAILED {} ({why})", display_path(&i.path)))
            }
            ItemResult::Deferred(_, why) => {
                deferred.set(true);
                rep.steps.push(format!("tier {tier}: stopped: {why}"))
            }
        }
        Ok(())
    };
    let docker_item = |path: &str, action: Action| {
        let mut it = Item::new(Kind::Docker, PathBuf::from(path));
        it.verdict = Verdict::Eligible;
        it.action = Some(action);
        it.compute_id();
        it
    };
    let docker_root = crate::docker::snapshot_root(cfg);
    let docker_pressured = |set: &HashSet<u64>| docker_root.as_deref().is_some_and(|r| on(set, r));

    // Tier 1: docker build cache.
    if cfg.docker.enabled && kind_allowed(cfg, Kind::Docker) && docker_pressured(&devs) {
        run_item(&mut ctx, docker_item("docker:build-cache", Action::DockerBuildCache), "1", &mut rep)?;
    }
    // Tiers 2-3: build output, least recently used first.
    if !satisfied() && kind_allowed(cfg, Kind::Artifact) {
        if !interop.all_held {
            rep.steps.push(format!("tiers 2-4 skipped: another cleaner holds {}", interop.busy.join(", ")));
        } else {
            let plan = build_plan(cfg, now)?;
            let mut arts: Vec<&Item> = plan
                .items
                .iter()
                .filter(|i| i.kind == Kind::Artifact && i.verdict != Verdict::Protected && on(&devs, &i.path))
                .collect();
            arts.sort_by_key(|i| (i.verdict != Verdict::Eligible, i.last_activity.unwrap_or(i64::MAX)));
            for a in arts {
                if satisfied() {
                    break;
                }
                // "Normally eligible" = stale on its own merits, not merely
                // promoted by the plan's pressure preview.
                let eligible = a.verdict == Verdict::Eligible && !a.pressure;
                if !eligible && !ctx.is_stale_calendar(a.last_activity, cfg.pressure.min_age_days) {
                    continue; // actively worked on: never evicted
                }
                let mut it = a.clone();
                it.pressure = !eligible;
                it.verdict = Verdict::Eligible;
                it.action = Some(Action::DeleteArtifact);
                run_item(&mut ctx, it, if eligible { "2" } else { "3" }, &mut rep)?;
            }
            // Tier 4: trim old files inside targets still being worked on.
            if hard && !satisfied() && cfg.pressure.sweep_active_targets && cargo_sweep_available() {
                for a in plan.items.iter().filter(|i| {
                    i.kind == Kind::Artifact
                        && i.verdict == Verdict::Active
                        && i.path.file_name().is_some_and(|n| n == "target")
                        && i.path.exists()
                        && on(&hard_devs, &i.path)
                }) {
                    if satisfied() {
                        break;
                    }
                    ctx.refresh();
                    if let Some(u) = ctx.in_use(&a.path) {
                        rep.steps.push(format!("tier 4: skipped {} ({u})", display_path(&a.path)));
                        continue;
                    }
                    let project = a.path.parent().unwrap_or(&a.path);
                    rep.steps.push(match cargo_sweep(project, cfg.pressure.min_age_days) {
                        Ok(()) => {
                            crate::log_info!("pressure.cargo_sweep", "--time {} {}", cfg.pressure.min_age_days, display_path(project));
                            format!("tier 4: cargo sweep --time {} {}", cfg.pressure.min_age_days, display_path(project))
                        }
                        Err(e) => {
                            rep.failed += 1;
                            crate::log_warn!("pressure.cargo_sweep_failed", "{}: {e:#}", display_path(project));
                            format!("tier 4: cargo sweep failed in {}: {e:#}", display_path(project))
                        }
                    });
                }
            }
        }
    }
    // Tier 5: purge quarantine early, most reproducible first, oldest first.
    if hard && !satisfied() && cfg.pressure.purge_quarantine_early {
        let rank = |k: Kind| match k {
            Kind::Worktree => 0,
            Kind::StaleWorktreeMeta => 1,
            Kind::Artifact => 2,
            Kind::Scratch => 3,
            _ => 4,
        };
        let mut q: Vec<_> = journal
            .load()?
            .into_iter()
            .filter(|e| e.status == JStatus::Quarantined)
            .filter(|e| e.qdir.as_deref().is_some_and(|q| on(&hard_devs, q)))
            .collect();
        q.sort_by_key(|e| (rank(e.kind), e.ts));
        for e in q {
            if satisfied() {
                break;
            }
            let (jid, path) = (e.jid.clone(), e.path.clone());
            rep.steps.push(match purge_entry(cfg, &journal, e, now, Some("disk pressure")) {
                Ok(p) => {
                    reported.set(reported.get() + p.bytes.unwrap_or(0));
                    format!("tier 5: purged quarantine of {} ({jid})", display_path(&path))
                }
                Err(err) => {
                    rep.failed += 1;
                    crate::log_error!("purge.failed", "early purge of {jid}: {err:#}");
                    format!("tier 5: purge of {jid} failed: {err:#}")
                }
            });
        }
    }
    // Tier 6: unused docker images.
    if hard && !satisfied() && cfg.docker.enabled && kind_allowed(cfg, Kind::Docker) && docker_pressured(&hard_devs) {
        run_item(&mut ctx, docker_item("docker:images", Action::DockerImages), "6", &mut rep)?;
    }

    let after = status(cfg, now_epoch().max(now), false);
    rep.after = after.iter().map(FsStatus::describe).collect();
    rep.reached = target_met();
    if capped.get() && !rep.reached {
        rep.capped = true;
        crate::log_info!(
            "pressure.capped",
            "deleted {} this pass (cap {} GiB); the next guard tick continues",
            fmt_bytes(Some(reported.get())),
            cfg.pressure.max_gib_per_relief
        );
    }
    if stalled.get() {
        rep.stalled = true;
        let gained = avail_sum().saturating_sub(start_avail);
        crate::log::emit(
            crate::log::Level::Warn,
            "pressure.no_progress",
            format!(
                "deletions reported {} but free space rose only {}: something still holds the data \
                 (btrfs snapshot, e.g. /.snapshots, or shared extents). Relief paused until free space \
                 rises or {}h pass.",
                fmt_bytes(Some(reported.get())),
                fmt_bytes(Some(gained)),
                PAUSE_HOURS
            ),
            serde_json::json!({"reported": reported.get(), "gained": gained, "start_avail": start_avail}),
        );
        let _ = write_pause(&cfg.state_dir, &Pause { ts: now, avail: avail_sum() });
    }
    rep.critical_after = after.iter().any(|s| level_now(&cfg.pressure, s.total, s.avail) == Level::Critical);
    let summary = format!("reached={} steps={} failed={} now: {}", rep.reached, rep.steps.len(), rep.failed, rep.after.join("; "));
    if rep.reached {
        crate::log_info!("pressure.relief_end", "{summary}");
    } else {
        crate::log_warn!("pressure.relief_end", "target not reached with safe actions: {summary}");
    }
    if rep.critical_after {
        let msg = format!("disk critically low after all safe relief: {}", rep.after.join("; "));
        crate::log_error!("pressure.critical", "{msg}");
        if cfg.pressure.notify {
            let _ = std::process::Command::new("notify-send")
                .args(["-u", "critical", "tree-gc: disk almost full", &msg])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    Ok(rep)
}

fn cargo_sweep_available() -> bool {
    let mut c = std::process::Command::new("cargo");
    c.args(["sweep", "--version"]);
    output_with_timeout(c, None, std::time::Duration::from_secs(30)).is_ok_and(|o| o.status.success())
}

fn cargo_sweep(project: &Path, days: u64) -> Result<()> {
    let mut c = std::process::Command::new("cargo");
    c.args(["sweep", "--time", &days.max(1).to_string()]).arg(project);
    let out = output_with_timeout(c, None, std::time::Duration::from_secs(1800))?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const G: u64 = 1 << 30;

    fn p() -> PressureCfg {
        PressureCfg::default()
    }

    #[test]
    fn levels() {
        let total = 1000 * G;
        assert_eq!(level_now(&p(), total, 300 * G), Level::None);
        assert_eq!(level_now(&p(), total, 190 * G), Level::Soft);
        assert_eq!(level_now(&p(), total, 90 * G), Level::Hard);
        assert_eq!(level_now(&p(), total, 40 * G), Level::Critical);
        // medium disk: 12.5% free is above low_free_percent, but 25G < the
        // 30 GiB floor (a single big build) -> Hard
        assert_eq!(level_now(&p(), 200 * G, 25 * G), Level::Hard);
        // modest disk: floor capped at 15% (15G of 100G), so 18G free is only Soft
        assert_eq!(level_now(&p(), 100 * G, 18 * G), Level::Soft);
        // small fs (8G tmpfs): no absolute floor; 95% free is fine
        assert_eq!(level_now(&p(), 8 * G, 7 * G), Level::None);
        assert_eq!(level_now(&p(), 8 * G, G / 2), Level::Hard);
        assert_eq!(target_avail(&p(), total), 250 * G);
    }

    #[test]
    fn pause_lifts_when_space_returns_or_time_passes() {
        let total = 1000 * G;
        let p = Pause { ts: 0, avail: 300 * G };
        assert!(pause_holds(&p, 3600, 300 * G, total)); // nothing changed
        assert!(pause_holds(&p, 3600, 302 * G, total)); // noise
        assert!(!pause_holds(&p, 3600, 310 * G, total)); // snapshot released
        assert!(!pause_holds(&p, PAUSE_HOURS * 3600 + 1, 300 * G, total)); // timed out
    }

    #[test]
    fn trend_predicts_before_threshold() {
        let total = 1000 * G;
        // 300G free, losing 10G/hour over the last 3 hours
        let now = 1_000_000;
        let pts: Vec<(i64, u64)> = (0..=6).map(|i| (now - 3 * 3600 + i * 1800, 330 * G - (i as u64) * 5 * G)).collect();
        let rate = fill_rate(&pts).unwrap();
        assert!((rate - 10.0 * G as f64).abs() < G as f64 * 0.01, "{rate}");
        // soft (200G) is 10h away, hard (100G) 20h away.
        // 12h horizon: only soft is within reach -> Soft now.
        let mut q = p();
        q.predict_horizon_hours = 12.0;
        let (lvl, why) = predicted_level(&q, total, 300 * G, Some(rate));
        assert_eq!(lvl, Level::Soft, "{why:?}");
        // default 24h horizon: hard is within reach too -> Hard takes precedence.
        assert_eq!(predicted_level(&p(), total, 300 * G, Some(rate)).0, Level::Hard);
        // draining slowly or freeing space: no prediction
        assert_eq!(predicted_level(&p(), total, 300 * G, Some(0.1 * G as f64)).0, Level::None);
        assert_eq!(predicted_level(&p(), total, 300 * G, Some(-5.0 * G as f64)).0, Level::None);
        // too few / too close samples: no rate
        assert!(fill_rate(&pts[..2]).is_none());
        assert!(fill_rate(&[(0, 1), (60, 1), (120, 1)]).is_none());
    }
}
