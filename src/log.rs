//! Logging: every line has a level, an event name and the run id.
//!
//! Two sinks:
//!   - stderr: under systemd (JOURNAL_STREAM set) each line carries a
//!     `<N>` priority prefix, so `journalctl -p warning` filters problems;
//!     on a terminal it's human-readable with a timestamp.
//!   - `<state_dir>/tree-gc.log`: JSON lines (ts, level, run, event, msg,
//!     fields), rotated at 10 MiB, 5 files kept. `tree-gc log` reads it.
//!
//! Before `init` (e.g. in tests) nothing is written to the file, and only
//! warnings and errors go to stderr.
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }
    fn journal_priority(self) -> u8 {
        match self {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug => 7,
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub ts: i64,
    pub level: Level,
    pub run: String,
    pub event: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub fields: serde_json::Value,
}

struct Logger {
    level: Level,
    run: String,
    journal: bool,
    file: Mutex<Option<fs::File>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub const FILE: &str = "tree-gc.log";
const MAX_BYTES: u64 = 10 << 20;
const KEEP: usize = 5;

/// Rotate `<dir>/tree-gc.log` -> `.1` -> ... -> `.KEEP` when it's too big.
pub fn rotate(dir: &Path, max_bytes: u64) {
    let cur = dir.join(FILE);
    if fs::metadata(&cur).map(|m| m.len() < max_bytes).unwrap_or(true) {
        return;
    }
    for i in (1..KEEP).rev() {
        let _ = fs::rename(dir.join(format!("{FILE}.{i}")), dir.join(format!("{FILE}.{}", i + 1)));
    }
    let _ = fs::rename(&cur, dir.join(format!("{FILE}.1")));
}

/// Initialise once per process. Returns the run id.
pub fn init(state_dir: &Path, level: Level) -> String {
    let run = crate::util::short_hash(&[&crate::util::now_epoch().to_string(), &std::process::id().to_string()])[..8].to_string();
    let _ = fs::create_dir_all(state_dir);
    rotate(state_dir, MAX_BYTES);
    let file = fs::OpenOptions::new().create(true).append(true).open(state_dir.join(FILE)).ok();
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    let _ = LOGGER.set(Logger { level, run: run.clone(), journal, file: Mutex::new(file) });
    // Panics are bugs: make sure they land in the log too (the default hook
    // still prints them as usual).
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        emit(Level::Error, "panic", format!("{info}"), serde_json::Value::Null);
        prev(info);
    }));
    run
}

pub fn run_id() -> Option<String> {
    LOGGER.get().map(|l| l.run.clone())
}

pub fn emit(level: Level, event: &str, msg: String, fields: serde_json::Value) {
    let Some(l) = LOGGER.get() else {
        if level >= Level::Warn {
            eprintln!("tree-gc {} {event}: {msg}", level.tag().trim());
        }
        return;
    };
    if level < l.level {
        return;
    }
    let rec = Record { ts: crate::util::now_epoch(), level, run: l.run.clone(), event: event.to_string(), msg, fields };
    if let Ok(mut f) = l.file.lock() {
        if let Some(f) = f.as_mut() {
            if let Ok(line) = serde_json::to_string(&rec) {
                let _ = writeln!(f, "{line}");
            }
        }
    }
    let extra = if rec.fields.is_null() { String::new() } else { format!(" {}", rec.fields) };
    if l.journal {
        eprintln!("<{}>[{}] {}: {}{}", level.journal_priority(), rec.run, rec.event, rec.msg, extra);
    } else if level >= Level::Info {
        eprintln!("{} {} [{}] {}: {}{}", crate::util::fmt_ts(rec.ts), level.tag(), rec.run, rec.event, rec.msg, extra);
    }
}

#[macro_export]
macro_rules! log_debug { ($ev:expr, $($a:tt)+) => { $crate::log::emit($crate::log::Level::Debug, $ev, format!($($a)+), serde_json::Value::Null) }; }
#[macro_export]
macro_rules! log_info { ($ev:expr, $($a:tt)+) => { $crate::log::emit($crate::log::Level::Info, $ev, format!($($a)+), serde_json::Value::Null) }; }
#[macro_export]
macro_rules! log_warn { ($ev:expr, $($a:tt)+) => { $crate::log::emit($crate::log::Level::Warn, $ev, format!($($a)+), serde_json::Value::Null) }; }
#[macro_export]
macro_rules! log_error { ($ev:expr, $($a:tt)+) => { $crate::log::emit($crate::log::Level::Error, $ev, format!($($a)+), serde_json::Value::Null) }; }

/// Read records from the log file and its rotations (oldest first).
pub fn read(state_dir: &Path) -> Vec<Record> {
    let mut files: Vec<PathBuf> = (1..=KEEP).rev().map(|i| state_dir.join(format!("{FILE}.{i}"))).collect();
    files.push(state_dir.join(FILE));
    files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .flat_map(|s| s.lines().filter_map(|l| serde_json::from_str::<Record>(l).ok()).collect::<Vec<_>>())
        .collect()
}

pub fn format_human(r: &Record) -> String {
    let extra = if r.fields.is_null() { String::new() } else { format!("  {}", r.fields) };
    format!("{} {} [{}] {}: {}{}", crate::util::fmt_ts(r.ts), r.level.tag(), r.run, r.event, r.msg, extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_keeps_bounded_history() {
        let d = std::env::temp_dir().join(format!("tree-gc-logtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for round in 0..8 {
            fs::write(d.join(FILE), format!("round {round}\n").repeat(50)).unwrap();
            rotate(&d, 100);
        }
        assert!(!d.join(FILE).exists());
        assert!(d.join(format!("{FILE}.1")).exists());
        assert!(d.join(format!("{FILE}.{KEEP}")).exists());
        assert!(!d.join(format!("{FILE}.{}", KEEP + 1)).exists());
        assert!(fs::read_to_string(d.join(format!("{FILE}.1"))).unwrap().starts_with("round 7"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn records_roundtrip_and_parse_levels() {
        let r = Record {
            ts: 1,
            level: Level::Warn,
            run: "abc".into(),
            event: "git.timeout".into(),
            msg: "x".into(),
            fields: serde_json::json!({"dir": "/r"}),
        };
        let back: Record = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.level, Level::Warn);
        assert_eq!(back.fields["dir"], "/r");
        assert_eq!(Level::parse("WARNING"), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
        assert!(Level::Error > Level::Info);
    }
}
