//! Docker: collect what has not been touched in a long time.
//!
//!   - build cache unused for `build_cache_days`  (regenerable)
//!   - images used by no container, created `image_days` ago (re-pullable/rebuildable)
//!   - stopped containers finished `container_days` ago whose own writable
//!     layer is small (a big writable layer may be data someone cares about)
//!   - volumes: NEVER removed, only reported (they hold databases)
//!
//! Reads go through `docker ... --format`; every call has a timeout.
use crate::config::Config;
use crate::model::{Action, Item, Kind, Verdict};
use crate::scan::{Ctx, Eval};
use crate::util::{fmt_bytes, output_with_timeout};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    /// exited / created / dead
    pub status: String,
    pub finished: Option<i64>,
    pub created: Option<i64>,
    pub size_rw: u64,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct DockerSnapshot {
    pub root_dir: Option<PathBuf>,
    pub build_cache_reclaimable: Option<u64>,
    pub images_reclaimable: Option<u64>,
    pub volumes_reclaimable: Option<u64>,
    pub containers: Vec<ContainerInfo>,
}

fn run(cfg: &Config, args: &[&str]) -> Result<String> {
    let mut c = Command::new("docker");
    c.args(args);
    let out = output_with_timeout(c, None, Duration::from_secs(cfg.docker.timeout_secs.max(10)))
        .with_context(|| format!("docker {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("docker {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Docker's human sizes ("56.05GB", "758.3MB (6%)", "12.3kB", "0B") use SI units.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.split_whitespace().next()?.trim();
    let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().ok()?;
    let mult = match unit.to_ascii_lowercase().as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => return None,
    };
    Some((n * mult) as u64)
}

/// RFC 3339 timestamps; docker's zero time ("0001-01-01T00:00:00Z") is None.
pub fn parse_time(s: &str) -> Option<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(s.trim()).ok()?.timestamp();
    (t > 0).then_some(t)
}

/// Docker's data root (to know which filesystem its objects live on).
pub fn snapshot_root(cfg: &Config) -> Option<PathBuf> {
    if !cfg.docker.enabled {
        return None;
    }
    let mut c = Command::new("docker");
    c.args(["info", "--format", "{{.DockerRootDir}}"]);
    let out = output_with_timeout(c, None, Duration::from_secs(15)).ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && s.starts_with('/')).then(|| PathBuf::from(s))
}

/// Read-only snapshot. None if docker is disabled or not reachable.
pub fn snapshot(cfg: &Config) -> Option<DockerSnapshot> {
    if !cfg.docker.enabled || run(cfg, &["version", "--format", "{{.Server.Version}}"]).is_err() {
        return None;
    }
    let mut snap = DockerSnapshot {
        root_dir: run(cfg, &["info", "--format", "{{.DockerRootDir}}"]).ok().map(|s| PathBuf::from(s.trim())),
        ..Default::default()
    };
    if let Ok(df) = run(cfg, &["system", "df", "--format", "{{json .}}"]) {
        for l in df.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
            let rec = v["Reclaimable"].as_str().and_then(parse_size);
            match v["Type"].as_str() {
                Some("Build Cache") => snap.build_cache_reclaimable = rec,
                Some("Images") => snap.images_reclaimable = rec,
                Some("Local Volumes") => snap.volumes_reclaimable = rec,
                _ => {}
            }
        }
    }
    // Stopped containers with their writable-layer size.
    let ps = run(
        cfg,
        &["ps", "-a", "--size", "--no-trunc", "--filter", "status=exited", "--filter", "status=created",
          "--filter", "status=dead", "--format", "{{.ID}}\t{{.Names}}\t{{.Size}}"],
    )
    .unwrap_or_default();
    let mut sizes = HashMap::new();
    for l in ps.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() == 3 {
            sizes.insert(f[0].to_string(), (f[1].to_string(), parse_size(f[2]).unwrap_or(u64::MAX)));
        }
    }
    if !sizes.is_empty() {
        let mut args = vec!["inspect", "--format", "{{.Id}}\t{{.State.Status}}\t{{.State.FinishedAt}}\t{{.Created}}\t{{json .Config.Labels}}"];
        let ids: Vec<String> = sizes.keys().cloned().collect();
        args.extend(ids.iter().map(String::as_str));
        for l in run(cfg, &args).unwrap_or_default().lines() {
            let f: Vec<&str> = l.splitn(5, '\t').collect();
            if f.len() < 5 {
                continue;
            }
            let (name, size_rw) = sizes.get(f[0]).cloned().unwrap_or_default();
            snap.containers.push(ContainerInfo {
                id: f[0].to_string(),
                name,
                status: f[1].to_string(),
                finished: parse_time(f[2]),
                created: parse_time(f[3]),
                size_rw,
                labels: serde_json::from_str(f[4]).unwrap_or_default(),
            });
        }
    }
    Some(snap)
}

/// Plan items from a snapshot (pure: unit-testable without a daemon).
pub fn items(ctx: &Ctx, snap: &DockerSnapshot) -> Vec<Item> {
    let d = &ctx.cfg.docker;
    let mut out = Vec::new();
    let mut aggregate = |path: &str, action: Option<Action>, verdict: Verdict, bytes: Option<u64>, why: String| {
        let mut it = Item::new(Kind::Docker, PathBuf::from(path));
        it.root = snap.root_dir.clone();
        it.verdict = verdict;
        it.action = action;
        it.bytes = bytes;
        it.reasons = vec![why];
        it.compute_id();
        out.push(it);
    };
    if snap.build_cache_reclaimable.unwrap_or(0) > 0 {
        aggregate(
            "docker:build-cache",
            Some(Action::DockerBuildCache),
            Verdict::Eligible,
            None,
            format!(
                "prune build cache unused for >= {}d (docker decides per entry; {} reclaimable at any age)",
                d.build_cache_days,
                fmt_bytes(snap.build_cache_reclaimable)
            ),
        );
    }
    if snap.images_reclaimable.unwrap_or(0) > 0 {
        aggregate(
            "docker:images",
            Some(Action::DockerImages),
            Verdict::Eligible,
            None,
            format!(
                "remove images no container uses, created >= {}d ago ({} reclaimable at any age)",
                d.image_days,
                fmt_bytes(snap.images_reclaimable)
            ),
        );
    }
    if snap.volumes_reclaimable.unwrap_or(0) > 0 {
        aggregate(
            "docker:volumes",
            None,
            Verdict::Protected,
            snap.volumes_reclaimable,
            "volumes are never removed automatically (they may hold databases); review with `docker volume ls`".into(),
        );
    }
    for c in &snap.containers {
        let mut e = Eval::new(Kind::Docker, PathBuf::from(format!("docker:container/{}", c.name)));
        e.item.head = Some(c.id.clone());
        e.item.branch = Some(c.name.clone());
        e.item.root = snap.root_dir.clone();
        e.item.bytes = (c.size_rw != u64::MAX).then_some(c.size_rw);
        e.touch(c.finished.or(c.created));
        if c.labels.contains_key(&d.keep_label) {
            e.protect(format!("label {}", d.keep_label));
        }
        if c.size_rw > d.max_container_rw_mb * 1_000_000 {
            e.protect(format!(
                "its own writable layer holds {} (may be data; `docker cp`/`docker commit` it or add label {})",
                if c.size_rw == u64::MAX { "an unknown amount".into() } else { fmt_bytes(Some(c.size_rw)) },
                d.keep_label
            ));
        }
        if let Some(p) = c.labels.get("com.docker.compose.project") {
            e.note(format!("compose project {p}; `docker compose up` recreates it"));
        }
        e.note("removed without -v: its volumes are kept");
        out.push(e.finish(ctx, d.container_days, Action::DockerContainer));
    }
    out
}

fn reclaimed(out: &str) -> Option<u64> {
    out.lines()
        .find_map(|l| l.strip_prefix("Total reclaimed space:").or_else(|| l.strip_prefix("Total:")))
        .and_then(|s| parse_size(s.trim()))
}

pub fn prune_build_cache(cfg: &Config, hours: u64) -> Result<Option<u64>> {
    let until = format!("until={hours}h");
    Ok(reclaimed(&run(cfg, &["builder", "prune", "-f", "--filter", &until])?))
}

pub fn prune_images(cfg: &Config, hours: u64) -> Result<Option<u64>> {
    let until = format!("until={hours}h");
    Ok(reclaimed(&run(cfg, &["image", "prune", "-a", "-f", "--filter", &until])?))
}

/// Remove one stopped container, re-checking its state first. Never `-v`.
pub fn remove_container(cfg: &Config, id: &str, expect_finished: Option<i64>) -> Result<()> {
    let state = run(cfg, &["inspect", "--format", "{{.State.Status}}\t{{.State.FinishedAt}}\t{{json .Config.Labels}}", id])?;
    let f: Vec<&str> = state.trim().splitn(3, '\t').collect();
    if f.len() < 3 || !matches!(f[0], "exited" | "created" | "dead") {
        bail!("container {id} is no longer stopped ({})", f.first().unwrap_or(&"?"));
    }
    if let (Some(now_f), Some(exp)) = (parse_time(f[1]), expect_finished) {
        if now_f > exp {
            bail!("container {id} ran again since the plan");
        }
    }
    let labels: HashMap<String, String> = serde_json::from_str(f[2]).unwrap_or_default();
    if labels.contains_key(&cfg.docker.keep_label) {
        bail!("container {id} now has label {}", cfg.docker.keep_label);
    }
    run(cfg, &["rm", id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times() {
        assert_eq!(parse_size("56.05GB"), Some(56_050_000_000));
        assert_eq!(parse_size("758.3MB (6%)"), Some(758_300_000));
        assert_eq!(parse_size("0B (virtual 78MB)"), Some(0));
        assert_eq!(parse_size("12.3kB"), Some(12_300));
        assert_eq!(parse_size("n/a"), None);
        assert_eq!(parse_time("0001-01-01T00:00:00Z"), None);
        let t = parse_time("2026-11-20T03:55:25.74197687Z").unwrap();
        assert_eq!(parse_time("2026-11-20T03:55:26Z"), Some(t + 1));
        assert!((1_790_000_000..1_800_000_000).contains(&t), "{t}");
        assert_eq!(reclaimed("Deleted: x\nTotal reclaimed space: 1.5GB\n"), Some(1_500_000_000));
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        c.state_dir = std::env::temp_dir().join("tree-gc-docker-unit-nonexistent");
        c
    }

    #[test]
    fn container_policy() {
        let cfg = cfg();
        let now = 1_800_000_000;
        let ctx = Ctx::new(&cfg, now);
        let day = 86_400;
        let c = |name: &str, finished_days_ago: i64, rw: u64, keep: bool| ContainerInfo {
            id: format!("id-{name}"),
            name: name.into(),
            status: "exited".into(),
            finished: Some(now - finished_days_ago * day),
            created: Some(now - 400 * day),
            size_rw: rw,
            labels: if keep { [("tree-gc.keep".to_string(), String::new())].into() } else { HashMap::new() },
        };
        let snap = DockerSnapshot {
            containers: vec![
                c("old-small", 120, 10_000, false),
                c("recent", 5, 10_000, false),
                c("old-big", 120, 2_000_000_000, false),
                c("old-kept", 120, 10, true),
            ],
            volumes_reclaimable: Some(21_000_000_000),
            ..Default::default()
        };
        let items = items(&ctx, &snap);
        let v = |n: &str| items.iter().find(|i| i.branch.as_deref() == Some(n)).unwrap().verdict;
        assert_eq!(v("old-small"), Verdict::Eligible);
        assert_eq!(v("recent"), Verdict::Active);
        assert_eq!(v("old-big"), Verdict::Protected);
        assert_eq!(v("old-kept"), Verdict::Protected);
        let vol = items.iter().find(|i| i.path == PathBuf::from("docker:volumes")).unwrap();
        assert_eq!(vol.verdict, Verdict::Protected);
        assert!(vol.action.is_none());
    }
}
