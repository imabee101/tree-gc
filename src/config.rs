use crate::model::Kind;
use crate::util::{expand_tilde, uid};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const EXAMPLE_CONFIG: &str = include_str!("../packaging/config.example.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Master switch. false = shadow mode: plan/log only, never mutate.
    pub enforce: bool,
    /// Kinds that may be acted on when enforce = true (staged rollout).
    pub enforce_kinds: Vec<Kind>,
    pub state_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    /// Quarantined items are purged after this many days.
    pub quarantine_days: u64,
    /// Global floor: nothing touched within this many days is ever eligible.
    pub active_days: u64,
    pub max_actions_per_run: usize,
    pub max_gib_per_run: f64,
    /// A file with this name in a directory (or any ancestor) protects it.
    pub keep_marker: String,
    pub protect_paths: Vec<PathBuf>,
    /// Files/dirs scanned for literal mentions of a path (systemd units, shell
    /// rc, agent/MCP configs...). A mentioned path is never touched.
    pub reference_files: Vec<PathBuf>,
    /// Also scan `crontab -l` output for references.
    pub reference_crontab: bool,
    /// Dirs holding per-cwd agent session data named after the encoded path
    /// (Claude: /home/u/x -> -home-u-x). Recent sessions count as activity.
    pub agent_session_dirs: Vec<PathBuf>,
    /// Files whose modification marks "the user was here" (shell and agent
    /// histories, recently-used list). Staleness counts only days with
    /// activity, so time away (or powered off) does not age anything.
    pub user_activity_files: Vec<PathBuf>,
    /// Commits that exist only in HEAD/branch reflogs (amended or reset away)
    /// protect a repo for this many days after the reflog entry.
    pub reflog_protect_days: u64,
    /// A missing worktree under these prefixes is assumed unmounted, not deleted.
    pub removable_prefixes: Vec<PathBuf>,
    pub roots: Vec<Root>,
    pub scratch: Vec<ScratchRule>,
    pub worktrees: WorktreeCfg,
    pub branches: BranchCfg,
    pub artifacts: ArtifactCfg,
    pub tmp: TmpCfg,
    pub pressure: PressureCfg,
    pub docker: DockerCfg,
    /// Lock files of other cleaners to hold while deleting build output, so
    /// two tools never sweep the same `target/` at once (e.g. build-hygiene).
    pub interop_locks: Vec<PathBuf>,
    /// How long to wait for another cleaner to release its lock.
    pub interop_wait_secs: u64,
    /// debug | info | warn | error (env TREE_GC_LOG overrides).
    pub log_level: String,
    /// Pause after each deletion: this many seconds per GiB deleted
    /// (min 0.2s, max throttle_max_secs), so btrfs commits in small steps.
    pub throttle_secs_per_gib: f64,
    pub throttle_max_secs: f64,
    /// Before each deletion, wait while the kernel's I/O pressure
    /// (/proc/pressure/io "some avg10", %) is above this; give up for this
    /// run after 60s of sustained pressure.
    pub throttle_max_io_psi: f64,
    /// How long to wait for I/O pressure to ease before deferring the run.
    pub throttle_io_wait_secs: u64,
}

/// Disk-pressure relief: when free space is low, act on the lowest-risk
/// things first, re-measuring real free space after each step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PressureCfg {
    pub enabled: bool,
    /// Proactive relief starts below this % free, with the lowest-risk tiers
    /// only (docker build cache, stale build output, LRU build output).
    pub soft_free_percent: f64,
    /// Below this % free (or low_free_gib), every tier may run.
    pub low_free_percent: f64,
    pub low_free_gib: f64,
    /// Relief continues until this % free is reached (and low_free_gib is met).
    pub target_free_percent: f64,
    /// Act *before* a threshold is crossed: if the recent fill rate would
    /// cross soft/low within this many hours, treat it as crossed now.
    pub predict_horizon_hours: f64,
    /// Fill rate is fitted over free-space samples from this many hours.
    pub trend_window_hours: f64,
    /// Below this, after all tiers, raise an alert (journal + desktop notification).
    pub critical_free_percent: f64,
    /// Nothing touched within this many calendar days is ever evicted,
    /// even under pressure ("actively worked on").
    pub min_age_days: u64,
    /// Run `cargo sweep --time min_age_days` on targets still in use.
    pub sweep_active_targets: bool,
    /// Purge quarantine (oldest, most reproducible first) before its TTL.
    pub purge_quarantine_early: bool,
    /// No-progress brake: once deletions report this much, free space must
    /// have risen by at least a tenth of it, or relief stops and pauses.
    pub stall_min_gib: f64,
    /// At most this much is deleted per relief pass (the guard runs every
    /// 5 minutes, so relief proceeds in steps rather than one burst).
    pub max_gib_per_relief: f64,
    pub notify: bool,
}

/// Docker objects untouched for a long time. Volumes are never removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerCfg {
    pub enabled: bool,
    /// Build cache entries not used for this many days.
    pub build_cache_days: u64,
    /// Images used by no container (running or stopped), created this long ago.
    pub image_days: u64,
    /// Stopped containers that finished this long ago...
    pub container_days: u64,
    /// ...and whose own writable layer holds at most this much (more may be data).
    pub max_container_rw_mb: u64,
    /// Containers with this label are never removed.
    pub keep_label: String,
    /// Under disk pressure: build cache unused for this many hours.
    pub pressure_build_cache_hours: u64,
    /// Under disk pressure: unused images created this many days ago.
    pub pressure_image_days: u64,
    pub timeout_secs: u64,
}

impl Default for PressureCfg {
    fn default() -> Self {
        PressureCfg {
            enabled: true,
            soft_free_percent: 20.0,
            low_free_percent: 10.0,
            low_free_gib: 30.0,
            target_free_percent: 25.0,
            predict_horizon_hours: 24.0,
            trend_window_hours: 6.0,
            critical_free_percent: 5.0,
            min_age_days: 2,
            sweep_active_targets: true,
            purge_quarantine_early: true,
            stall_min_gib: 20.0,
            max_gib_per_relief: 50.0,
            notify: true,
        }
    }
}

impl Default for DockerCfg {
    fn default() -> Self {
        DockerCfg {
            enabled: true,
            build_cache_days: 30,
            image_days: 60,
            container_days: 90,
            max_container_rw_mb: 50,
            keep_label: "tree-gc.keep".into(),
            pressure_build_cache_hours: 48,
            pressure_image_days: 7,
            timeout_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RootKind {
    /// Walk for git repos, worktrees and build artifacts.
    #[default]
    Tree,
    /// Age out top-level entries (like /tmp).
    Tmp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub path: PathBuf,
    #[serde(default)]
    pub kind: RootKind,
    #[serde(default = "default_depth")]
    pub max_depth: usize,
}

fn default_depth() -> usize {
    6
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScratchAction {
    /// Move to quarantine; restorable until purged.
    #[default]
    Quarantine,
    /// Delete outright. Only for pure caches.
    Delete,
}

/// A directory owned by an agent/tool whose *children* are disposable scratch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchRule {
    pub name: String,
    pub path: PathBuf,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub stale_days: u64,
    /// Always keep the N most recently active children (FIFO window).
    #[serde(default)]
    pub keep_newest: usize,
    #[serde(default)]
    pub action: ScratchAction,
    /// Glob patterns on child names that are never touched.
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorktreeCfg {
    pub enabled: bool,
    pub stale_days: u64,
    pub honor_locks: bool,
    /// Treat locks whose reason names a dead pid (e.g. Claude agents) as stale.
    pub break_dead_pid_locks: bool,
    /// Delete regenerable artifacts inside a worktree before quarantining it.
    pub strip_artifacts: bool,
    /// Ignored-file globs that don't block collection (besides artifacts).
    pub disposable_ignored: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BranchCfg {
    pub enabled: bool,
    pub stale_days: u64,
    pub protected: Vec<String>,
    pub include_squash_merged: bool,
    pub archive_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactCfg {
    pub enabled: bool,
    pub stale_days: u64,
    /// Directory name -> sibling file that must exist ("" = none required).
    pub markers: BTreeMap<String, String>,
    /// Any directory with a valid CACHEDIR.TAG is a cache.
    pub respect_cachedir_tag: bool,
    /// Before deleting a Cargo `target/`, move its release executables
    /// (`target/release/*`, `target/<triple>/release/*`) into quarantine so
    /// tools you run by absolute path can be restored instantly.
    pub preserve_release_binaries: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TmpCfg {
    pub enabled: bool,
    pub stale_days: u64,
    pub only_own: bool,
    pub exclude: Vec<String>,
    /// Entries with more files than this are kept (can't verify cheaply).
    pub max_walk_entries: usize,
}

impl Default for Config {
    /// Minimal, empty-scope defaults (used to fill fields missing from a file).
    /// The recommended configuration is [`Config::builtin`].
    fn default() -> Self {
        Config {
            enforce: false,
            enforce_kinds: Kind::ALL.to_vec(),
            state_dir: "~/.local/state/tree-gc".into(),
            quarantine_dir: "~/.local/share/tree-gc/quarantine".into(),
            quarantine_days: 14,
            active_days: 2,
            max_actions_per_run: 200,
            max_gib_per_run: 200.0,
            keep_marker: ".tree-gc-keep".into(),
            protect_paths: vec![],
            reference_files: [
                "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.zprofile", "~/.zshenv",
                "~/.config/fish/config.fish", "~/.config/fish/conf.d", "~/.config/environment.d",
                "~/.config/systemd/user", "/etc/systemd/system", "/etc/systemd/user",
                "~/.local/share/applications", "~/.config/autostart",
                "~/.claude.json", "~/.claude/settings.json", "~/.claude/settings.local.json",
                "~/.codex/config.toml", "~/.grok/config.toml", "~/.gemini/settings.json",
                "~/.config/Code/User/settings.json", "~/.config/Code/User/mcp.json", "~/.cargo/config.toml",
                "~/.gitconfig", "~/.config/Claude/claude_desktop_config.json", "~/.cursor/mcp.json",
                "~/.config/Cursor/User/settings.json", "~/.config/zed/settings.json", "~/.mcp.json",
                "/etc/fstab", "/etc/exports", "~/.ssh/config", "/etc/cron.d", "/etc/crontab",
            ]
            .map(PathBuf::from)
            .to_vec(),
            reference_crontab: true,
            reflog_protect_days: 14,
            user_activity_files: [
                "~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history",
                "~/.claude/history.jsonl", "~/.codex/history.jsonl", "~/.grok/slash-mru.json",
                "~/.local/share/recently-used.xbel", "~/.viminfo", "~/.local/state/nvim/shada/main.shada",
            ]
            .map(PathBuf::from)
            .to_vec(),
            agent_session_dirs: ["~/.claude/projects", "/tmp/claude-{uid}"].map(PathBuf::from).to_vec(),
            removable_prefixes: ["/run/media", "/media", "/mnt", "/net", "/Volumes"].map(PathBuf::from).to_vec(),
            roots: vec![],
            scratch: vec![],
            worktrees: Default::default(),
            branches: Default::default(),
            artifacts: Default::default(),
            tmp: Default::default(),
            pressure: Default::default(),
            docker: Default::default(),
            interop_locks: vec!["/tmp/build-hygiene.lock".into()],
            interop_wait_secs: 60,
            log_level: "info".into(),
            throttle_secs_per_gib: 1.0,
            throttle_max_secs: 30.0,
            throttle_max_io_psi: 25.0,
            throttle_io_wait_secs: 60,
        }
    }
}

impl Default for WorktreeCfg {
    fn default() -> Self {
        WorktreeCfg {
            enabled: true,
            stale_days: 7,
            honor_locks: true,
            break_dead_pid_locks: true,
            strip_artifacts: true,
            disposable_ignored: [
                // Not .idea (JetBrains keeps shelved changes in .idea/shelf),
                // not .vscode, not *.swp (editor crash recovery).
                "*.log", "*.tmp", "*.pyc", ".DS_Store", "*.profraw", ".coverage", "coverage",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

impl Default for BranchCfg {
    fn default() -> Self {
        BranchCfg {
            enabled: true,
            stale_days: 30,
            protected: ["main", "master", "develop", "dev", "trunk", "release*", "stable*"]
                .map(String::from)
                .to_vec(),
            include_squash_merged: true,
            archive_prefix: "refs/tree-gc/archive/".into(),
        }
    }
}

impl Default for ArtifactCfg {
    fn default() -> Self {
        let m: BTreeMap<String, String> = [
            ("target", "Cargo.toml"),
            ("node_modules", "package.json"),
            (".next", "package.json"),
            (".turbo", "package.json"),
            (".parcel-cache", "package.json"),
            (".zig-cache", "build.zig"),
            ("__pycache__", ""),
            (".pytest_cache", ""),
            (".mypy_cache", ""),
            (".ruff_cache", ""),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        ArtifactCfg {
            enabled: true,
            stale_days: 14,
            markers: m,
            respect_cachedir_tag: false,
            preserve_release_binaries: true,
        }
    }
}

impl Default for TmpCfg {
    fn default() -> Self {
        TmpCfg {
            enabled: true,
            stale_days: 7,
            only_own: true,
            exclude: [
                "systemd-private-*", ".X*-unix", ".ICE-unix", ".font-unix", ".XIM-unix", "ssh-*",
                "tmux-*", "krb5*", "pulse-*", ".tree-gc-quarantine*", ".tree-gc-deleting-*",
            ]
            .map(String::from)
            .to_vec(),
            max_walk_entries: 100_000,
        }
    }
}

impl Config {
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| expand_tilde(Path::new("~/.config")));
        base.join("tree-gc/config.toml")
    }

    /// The shipped recommended configuration (packaging/config.example.toml).
    pub fn builtin() -> Config {
        Config::from_toml(EXAMPLE_CONFIG).expect("bundled example config must parse")
    }

    /// Load from `path`, or the default path, or the builtin configuration.
    pub fn load(path: Option<&Path>) -> Result<(Config, Option<PathBuf>)> {
        let p = path.map(Path::to_path_buf).unwrap_or_else(Self::default_path);
        let (cfg, used) = if p.exists() {
            let s = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            let c: Config = toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))?;
            (c, Some(p))
        } else if path.is_some() {
            anyhow::bail!("config file {} not found", p.display());
        } else {
            return Ok((Config::builtin(), None));
        };
        Ok((cfg.normalized(), used))
    }

    pub fn from_toml(s: &str) -> Result<Config> {
        Ok(toml::from_str::<Config>(s)?.normalized())
    }

    /// Expand `~` and `{uid}`, drop nonsensical values.
    pub fn normalized(mut self) -> Self {
        let fix = |p: &Path| -> PathBuf {
            let s = p.to_string_lossy().replace("{uid}", &uid().to_string());
            expand_tilde(Path::new(&s))
        };
        self.state_dir = fix(&self.state_dir);
        self.quarantine_dir = fix(&self.quarantine_dir);
        for r in &mut self.roots {
            r.path = fix(&r.path);
        }
        for s in &mut self.scratch {
            s.path = fix(&s.path);
        }
        self.protect_paths = self.protect_paths.iter().map(|p| fix(p)).collect();
        self.reference_files = self.reference_files.iter().map(|p| fix(p)).collect();
        self.agent_session_dirs = self.agent_session_dirs.iter().map(|p| fix(p)).collect();
        self.user_activity_files = self.user_activity_files.iter().map(|p| fix(p)).collect();
        if self.keep_marker.is_empty() {
            self.keep_marker = ".tree-gc-keep".into();
        }
        self
    }

    pub fn max_bytes_per_run(&self) -> u64 {
        (self.max_gib_per_run.max(0.0) * 1024.0 * 1024.0 * 1024.0) as u64
    }
}
