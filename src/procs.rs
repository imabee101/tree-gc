//! Who is using what: a snapshot of process cwd / exe / open files.
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProcRef {
    pub pid: i32,
    pub comm: String,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Procs {
    pub refs: Vec<ProcRef>,
    /// File names of every bound, non-abstract unix socket (paths may be
    /// relative to the binder's cwd at bind time, so names are what we can match).
    pub socket_names: std::collections::HashSet<String>,
}

impl Procs {
    /// Snapshot every process we can inspect (our own user's, or all as root).
    pub fn snapshot() -> Self {
        let me = std::process::id() as i32;
        let mut refs = Vec::new();
        let mut socket_names = std::collections::HashSet::new();
        let Ok(rd) = fs::read_dir("/proc") else { return Procs { refs, socket_names } };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            if pid == me {
                continue;
            }
            let base = e.path();
            let comm = fs::read_to_string(base.join("comm")).unwrap_or_default().trim().to_string();
            let mut push = |p: PathBuf| {
                if p.is_absolute() {
                    refs.push(ProcRef { pid, comm: comm.clone(), path: p });
                }
            };
            for l in ["cwd", "exe"] {
                if let Ok(p) = fs::read_link(base.join(l)) {
                    push(p);
                }
            }
            if let Ok(fds) = fs::read_dir(base.join("fd")) {
                for fd in fds.flatten() {
                    if let Ok(p) = fs::read_link(fd.path()) {
                        push(p);
                    }
                }
            }
            // Memory-mapped files (shared libraries, mmap'd data, venv extensions).
            if let Ok(maps) = fs::read_to_string(base.join("maps")) {
                let mut seen = std::collections::HashSet::new();
                for l in maps.lines() {
                    if let Some(i) = l.find(" /") {
                        let p = l[i + 1..].trim_end_matches(" (deleted)");
                        if seen.insert(p.to_string()) {
                            push(PathBuf::from(p));
                        }
                    }
                }
            }
            // Absolute paths on the command line (scripts, --manifest-path, -C dir...).
            if let Ok(cmd) = fs::read(base.join("cmdline")) {
                for arg in cmd.split(|b| *b == 0) {
                    let a = String::from_utf8_lossy(arg);
                    let a = a.split_once('=').map(|(_, v)| v).unwrap_or(&a);
                    if a.starts_with('/') && a.len() > 1 {
                        push(PathBuf::from(a));
                    }
                }
            }
        }
        // Bound unix sockets are listed by path here, not under /proc/PID/fd.
        if let Ok(unix) = fs::read_to_string("/proc/net/unix") {
            for l in unix.lines().skip(1) {
                let Some(p) = l.split_whitespace().nth(7).filter(|p| !p.starts_with('@')) else { continue };
                if let Some(n) = Path::new(p).file_name() {
                    socket_names.insert(n.to_string_lossy().into_owned());
                }
                if p.starts_with('/') {
                    refs.push(ProcRef { pid: 0, comm: "unix-socket".into(), path: PathBuf::from(p) });
                }
            }
        }
        Procs { refs, socket_names }
    }

    /// First process whose cwd/exe/open file lies inside `target`.
    pub fn user_of(&self, target: &Path) -> Option<&ProcRef> {
        let t = crate::util::canon(target);
        self.refs.iter().find(|r| r.path.starts_with(&t) || r.path.starts_with(target))
    }
}

/// Process start time in clock ticks since boot (field 22 of /proc/PID/stat).
pub fn pid_start_ticks(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &s[s.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Is the process alive (and, if a start time is known, the *same* process)?
pub fn pid_alive(pid: i32, start: Option<u64>) -> bool {
    match pid_start_ticks(pid) {
        None => false,
        Some(s) => start.map_or(true, |want| want == s),
    }
}

/// Parse lock reasons like `claude agent X (pid 1318800 start 649864)`.
pub fn parse_pid_lock(reason: &str) -> Option<(i32, Option<u64>)> {
    let idx = reason.find("pid ")?;
    let rest = &reason[idx + 4..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let pid: i32 = digits.parse().ok()?;
    let start = rest.find("start ").and_then(|i| {
        let d: String = rest[i + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
        d.parse().ok()
    });
    Some((pid, start))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_claude_lock() {
        assert_eq!(
            parse_pid_lock("claude agent agent-a05 (pid 1318800 start 649864)"),
            Some((1318800, Some(649864)))
        );
        assert_eq!(parse_pid_lock("pid 42"), Some((42, None)));
        assert_eq!(parse_pid_lock("on usb disk"), None);
    }
    #[test]
    fn self_is_alive() {
        let me = std::process::id() as i32;
        let st = pid_start_ticks(me);
        assert!(st.is_some());
        assert!(pid_alive(me, st));
        assert!(!pid_alive(me, Some(st.unwrap() + 1)));
    }
}
