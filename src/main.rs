use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tree_gc::config::{Config, EXAMPLE_CONFIG};
use tree_gc::exec::{self, ApplyOpts, Journal};
use tree_gc::model::{Kind, Plan, Verdict};
use tree_gc::util::{fmt_bytes, now_epoch, DAY};
use tree_gc::{report, scan};

#[derive(Parser)]
#[command(name = "tree-gc", version, about = "Plan and clean up stale Git worktrees, branches and build output on Linux")]
struct Cli {
    /// Config file (default: ~/.config/tree-gc/config.toml, else built-in)
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the recommended config to ~/.config/tree-gc/config.toml
    InitConfig {
        #[arg(long)]
        force: bool,
    },
    /// Read-only summary: what exists, what is reclaimable, why things are protected
    Survey {
        #[arg(long)]
        json: bool,
        /// Evaluate as if N days had passed (simulate the future)
        #[arg(long, default_value_t = 0)]
        days: i64,
    },
    /// Read-only detailed plan of what would be done
    Plan {
        #[arg(long)]
        json: bool,
        /// Also list kept and protected items individually
        #[arg(long)]
        all: bool,
        /// Evaluate as if N days had passed (simulate the future)
        #[arg(long, default_value_t = 0)]
        days: i64,
        /// Save the plan for review / `apply --plan`
        #[arg(long)]
        save: Option<PathBuf>,
    },
    /// Execute a plan (requires enforce=true in config AND --yes)
    Apply {
        #[arg(long)]
        yes: bool,
        /// Apply a previously saved plan (every item is re-verified first)
        #[arg(long)]
        plan: Option<PathBuf>,
        /// Only these kinds (e.g. --kind branch --kind wt-meta)
        #[arg(long = "kind", value_parser = parse_kind)]
        kinds: Vec<Kind>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// One cycle for the systemd timer: plan, record, and act only if enforce=true
    Run,
    /// Cheap disk check for a frequent timer: records free space for the
    /// trend and starts pressure relief if a threshold is reached or predicted
    Guard,
    /// Show disk pressure status and fill-rate prediction (read-only)
    Pressure,
    /// Loop `run` forever (for systems without systemd timers)
    Daemon {
        #[arg(long, default_value_t = 60)]
        interval_mins: u64,
    },
    /// Permanently delete quarantined items older than quarantine_days
    Purge {
        #[arg(long)]
        yes: bool,
    },
    /// Undo a quarantine or branch archive by journal id (suffix ok)
    Restore { id: String },
    /// Show journal (default: restorable entries only)
    Journal {
        #[arg(long)]
        all: bool,
    },
    /// Show the structured log (~/.local/state/tree-gc/tree-gc.log)
    Log {
        /// Minimum level: debug, info, warn, error
        #[arg(long, default_value = "info")]
        level: String,
        /// Only the last N records
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Only records from this run id
        #[arg(long)]
        run: Option<String>,
        /// Only records newer than this many hours
        #[arg(long)]
        since_hours: Option<u64>,
    },
}

/// Exit codes: 0 ok, 1 error, 2 some actions failed, 3 disk still critical.
const EXIT_ERROR: i32 = 1;
const EXIT_ACTIONS_FAILED: i32 = 2;
const EXIT_CRITICAL: i32 = 3;

fn parse_kind(s: &str) -> Result<Kind, String> {
    Kind::ALL
        .into_iter()
        .find(|k| k.label() == s || format!("{k:?}").eq_ignore_ascii_case(&s.replace(['-', '_'], "")))
        .ok_or_else(|| format!("unknown kind {s}; one of: wt-meta branch artifact scratch worktree tmp"))
}

fn main() {
    let started = std::time::Instant::now();
    let code = match real_main() {
        Ok(code) => code,
        Err(e) => {
            tree_gc::log_error!("run.error", "{e:#}");
            EXIT_ERROR
        }
    };
    if tree_gc::log::run_id().is_some() {
        let lvl = if code == 0 { tree_gc::log::Level::Info } else { tree_gc::log::Level::Warn };
        tree_gc::log::emit(
            lvl,
            "run.end",
            format!("exit {code} after {:.1}s", started.elapsed().as_secs_f64()),
            serde_json::json!({"exit": code, "ms": started.elapsed().as_millis() as u64}),
        );
    }
    std::process::exit(code);
}

fn cmd_name(c: &Cmd) -> &'static str {
    match c {
        Cmd::InitConfig { .. } => "init-config",
        Cmd::Survey { .. } => "survey",
        Cmd::Plan { .. } => "plan",
        Cmd::Apply { .. } => "apply",
        Cmd::Run => "run",
        Cmd::Guard => "guard",
        Cmd::Pressure => "pressure",
        Cmd::Daemon { .. } => "daemon",
        Cmd::Purge { .. } => "purge",
        Cmd::Restore { .. } => "restore",
        Cmd::Journal { .. } => "journal",
        Cmd::Log { .. } => "log",
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    if let Cmd::InitConfig { force } = &cli.cmd {
        let p = cli.config.clone().unwrap_or_else(Config::default_path);
        if p.exists() && !force {
            bail!("{} exists (use --force to overwrite)", p.display());
        }
        std::fs::create_dir_all(p.parent().unwrap())?;
        std::fs::write(&p, EXAMPLE_CONFIG)?;
        println!("wrote {}", p.display());
        return Ok(0);
    }
    let (cfg, used) = Config::load(cli.config.as_deref())?;
    let level = std::env::var("TREE_GC_LOG")
        .ok()
        .and_then(|s| tree_gc::log::Level::parse(&s))
        .or_else(|| tree_gc::log::Level::parse(&cfg.log_level))
        .unwrap_or(tree_gc::log::Level::Info);
    // Reading the log must not add to it.
    if !matches!(cli.cmd, Cmd::Log { .. }) {
        tree_gc::log::init(&cfg.state_dir, level);
        tree_gc::log::emit(
            tree_gc::log::Level::Info,
            "run.start",
            format!("{} (v{}, enforce={})", cmd_name(&cli.cmd), env!("CARGO_PKG_VERSION"), cfg.enforce),
            serde_json::json!({
                "cmd": cmd_name(&cli.cmd),
                "config": used.as_ref().map(|p| p.display().to_string()),
                "enforce": cfg.enforce,
                "enforce_kinds": cfg.enforce_kinds,
                "pid": std::process::id(),
            }),
        );
    }
    if used.is_none() {
        tree_gc::log_warn!("config.default", "no config file; using built-in defaults (enforce=false). `tree-gc init-config` to customise");
    }
    let now = now_epoch();
    let mut code = 0;
    match cli.cmd {
        Cmd::InitConfig { .. } => unreachable!(),
        Cmd::Survey { json, days } => {
            let plan = scan::build_plan(&cfg, now + days * DAY)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                report::print_survey(&plan);
            }
        }
        Cmd::Plan { json, all, days, save } => {
            let plan = scan::build_plan(&cfg, now + days * DAY)?;
            if let Some(p) = save {
                std::fs::write(&p, serde_json::to_vec_pretty(&plan)?)?;
                eprintln!("saved plan to {}", p.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                report::print_plan(&plan, all);
            }
        }
        Cmd::Apply { yes, plan, kinds, limit } => {
            if !cfg.enforce {
                bail!("enforce = false in config: shadow mode. Review `tree-gc plan`, then set enforce = true.");
            }
            let plan: Plan = match plan {
                Some(p) => serde_json::from_slice(&std::fs::read(&p)?).context("reading plan")?,
                None => scan::build_plan(&cfg, now)?,
            };
            if plan.simulated {
                bail!("refusing to apply a plan made with a simulated clock (--days)");
            }
            if !yes {
                report::print_plan(&plan, false);
                bail!("re-run with --yes to execute the WOULD ACT list above");
            }
            let opts = ApplyOpts {
                now,
                max_actions: limit.unwrap_or(cfg.max_actions_per_run).min(cfg.max_actions_per_run),
                max_bytes: cfg.max_bytes_per_run(),
                kinds: (!kinds.is_empty()).then_some(kinds),
            };
            let o = exec::apply(&cfg, &plan, &opts)?;
            report::print_outcome(&o);
            if !o.failed.is_empty() {
                code = EXIT_ACTIONS_FAILED;
            }
        }
        Cmd::Run => code = run_once(&cfg)?,
        Cmd::Daemon { interval_mins } => loop {
            if let Err(e) = run_once(&cfg) {
                tree_gc::log_error!("run.error", "{e:#}");
            }
            std::thread::sleep(std::time::Duration::from_secs(interval_mins.max(5) * 60));
        },
        Cmd::Purge { yes } => {
            if !yes {
                bail!("purge permanently deletes expired quarantine; re-run with --yes");
            }
            let p = exec::purge(&cfg, now)?;
            println!("purged {} quarantined item(s)", p.purged.len());
            for (id, err) in &p.errors {
                eprintln!("purge {id}: {err}");
            }
            if !p.errors.is_empty() {
                code = EXIT_ACTIONS_FAILED;
            }
        }
        Cmd::Restore { id } => {
            let e = exec::restore(&cfg, &id)?;
            println!("restored {} ({:?})", e.path.display(), e.action);
        }
        Cmd::Journal { all } => report::print_journal(&Journal::open(&cfg.state_dir)?.load()?, all),
        Cmd::Guard => {
            record_activity(&cfg, now, None)?;
            let r = tree_gc::pressure::relieve(&cfg, now)?;
            print_relief(&r);
            code = relief_code(&r);
        }
        Cmd::Log { level, lines, run, since_hours } => {
            let min = tree_gc::log::Level::parse(&level).unwrap_or(tree_gc::log::Level::Info);
            let cutoff = since_hours.map(|h| now - h as i64 * 3600);
            let recs: Vec<_> = tree_gc::log::read(&cfg.state_dir)
                .into_iter()
                .filter(|r| r.level >= min)
                .filter(|r| run.as_deref().is_none_or(|id| r.run == id))
                .filter(|r| cutoff.is_none_or(|c| r.ts >= c))
                .collect();
            for r in &recs[recs.len().saturating_sub(lines)..] {
                println!("{}", tree_gc::log::format_human(r));
            }
        }
        Cmd::Pressure => {
            for s in tree_gc::pressure::status(&cfg, now, false) {
                println!("{}", s.describe());
            }
        }
    }
    Ok(code)
}

fn relief_code(r: &tree_gc::pressure::ReliefReport) -> i32 {
    if r.critical_after {
        EXIT_CRITICAL
    } else if r.failed > 0 {
        EXIT_ACTIONS_FAILED
    } else {
        0
    }
}

/// Record "the user was here" signals for the in-use-days clock.
fn record_activity(cfg: &Config, now: i64, extra: Option<i64>) -> Result<()> {
    let mut clock = tree_gc::clock::ActivityClock::load(&cfg.state_dir);
    if clock.went_backwards(now) {
        tree_gc::log_error!("clock.backwards", "system clock is earlier than the last run; nothing will be acted on until it is correct");
        return Ok(());
    }
    let mut seen: Vec<i64> = tree_gc::clock::user_activity(&cfg.user_activity_files).into_iter().collect();
    seen.extend(extra);
    clock.record(now, &seen);
    clock.save(&cfg.state_dir)
}

fn print_relief(r: &tree_gc::pressure::ReliefReport) {
    if r.steps.is_empty() && r.reached {
        return;
    }
    for s in &r.before {
        println!("disk: {s}");
    }
    for s in &r.steps {
        println!("relief: {s}");
    }
    for s in &r.after {
        println!("disk after: {s}");
    }
    if !r.shadow && !r.reached {
        println!("relief: target not reached with safe actions");
    }
}

/// Plan, persist for review, and (only if enforcing) apply + purge + relieve.
/// Returns the exit code.
fn run_once(cfg: &Config) -> Result<i32> {
    let mut code = 0;
    let now = now_epoch();
    record_activity(cfg, now, None)?;
    let plan = scan::build_plan(cfg, now)?;
    // Newest project activity seen by the plan also marks today as in use.
    let newest = plan.items.iter().filter_map(|i| i.last_activity).filter(|t| *t <= now).max();
    record_activity(cfg, now, newest)?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    std::fs::write(cfg.state_dir.join("last-plan.json"), serde_json::to_vec_pretty(&plan)?)?;
    let elig: Vec<_> = plan.eligible().collect();
    let bytes: u64 = elig.iter().filter_map(|i| i.bytes).sum();
    let prot = plan.items.iter().filter(|i| i.verdict == Verdict::Protected).count();
    let mut summary = serde_json::json!({
        "ts": now, "enforce": cfg.enforce, "eligible": elig.len(), "eligible_bytes": bytes,
        "protected": prot, "total": plan.items.len(),
    });
    tree_gc::log::emit(
        tree_gc::log::Level::Info,
        "plan.summary",
        format!(
            "{} eligible ({}), {} protected, {} total{}",
            elig.len(),
            fmt_bytes(Some(bytes)),
            prot,
            plan.items.len(),
            if cfg.enforce { "" } else { " [shadow mode: no changes]" }
        ),
        summary.clone(),
    );
    for n in &plan.notes {
        tree_gc::log_info!("plan.note", "{n}");
    }
    if cfg.enforce {
        let opts = ApplyOpts { now, max_actions: cfg.max_actions_per_run, max_bytes: cfg.max_bytes_per_run(), kinds: None };
        let o = exec::apply(cfg, &plan, &opts)?;
        report::print_outcome(&o);
        let purged = exec::purge(cfg, now)?;
        summary["done"] = o.done.len().into();
        summary["failed"] = o.failed.len().into();
        summary["purged"] = purged.purged.len().into();
        summary["purge_errors"] = purged.errors.len().into();
        let freed: u64 = o.done.iter().filter_map(|e| e.bytes).sum();
        let lvl = if o.failed.is_empty() && purged.errors.is_empty() { tree_gc::log::Level::Info } else { tree_gc::log::Level::Warn };
        tree_gc::log::emit(
            lvl,
            "apply.summary",
            format!(
                "{} done ({}), {} skipped, {} failed, {} purged, {} purge errors{}",
                o.done.len(),
                fmt_bytes(Some(freed)),
                o.skipped.len(),
                o.failed.len(),
                purged.purged.len(),
                purged.errors.len(),
                o.stopped_early.as_ref().map(|s| format!("; stopped early: {s}")).unwrap_or_default()
            ),
            summary.clone(),
        );
        if !o.failed.is_empty() || !purged.errors.is_empty() {
            code = EXIT_ACTIONS_FAILED;
        }
        // Finish deletions interrupted earlier (renamed-aside dirs).
        let parents: Vec<std::path::PathBuf> = Journal::open(&cfg.state_dir)?
            .load()?
            .iter()
            .filter(|e| matches!(e.action, tree_gc::model::Action::DeleteArtifact | tree_gc::model::Action::DeletePath))
            .filter_map(|e| e.path.parent().map(|p| p.to_path_buf()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for err in exec::sweep_deleting(&parents) {
            tree_gc::log_warn!("delete.leftover", "could not finish an interrupted deletion: {err}");
        }
    }
    let relief = tree_gc::pressure::relieve(cfg, now)?;
    print_relief(&relief);
    summary["pressure_steps"] = relief.steps.len().into();
    summary["pressure_reached"] = relief.reached.into();
    code = code.max(relief_code(&relief));
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(cfg.state_dir.join("history.jsonl"))?;
    writeln!(f, "{summary}")?;
    Ok(code)
}
