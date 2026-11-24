use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DAY: i64 = 86_400;
/// Prefix of per-filesystem fallback quarantine dirs (`<root>/.tree-gc-quarantine-<uid>`).
pub const QUARANTINE_NAME: &str = ".tree-gc-quarantine";

pub fn fallback_quarantine_name() -> String {
    format!("{QUARANTINE_NAME}-{}", uid())
}

pub fn is_quarantine_name(n: &std::ffi::OsStr) -> bool {
    n.to_str().is_some_and(|s| s.starts_with(QUARANTINE_NAME))
}

fn unescape_mount(s: &str) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

#[derive(Debug, Clone)]
pub struct MountEntry {
    pub point: PathBuf,
    pub fstype: String,
    /// Mount source (e.g. /dev/mapper/cryptroot, tmpfs).
    pub source: String,
}

/// Current mounts from /proc/self/mountinfo.
pub fn mounts() -> Vec<MountEntry> {
    let Ok(s) = fs::read_to_string("/proc/self/mountinfo") else { return vec![] };
    s.lines()
        .filter_map(|l| {
            let point = unescape_mount(l.split(' ').nth(4)?);
            let mut tail = l.split(" - ").nth(1)?.split(' ');
            let fstype = tail.next()?.to_string();
            let source = tail.next().unwrap_or("").to_string();
            Some(MountEntry { point, fstype, source })
        })
        .collect()
}

/// Identity of the filesystem holding `p`, for grouping free space: the
/// mount source device (btrfs subvolumes and bind mounts of one disk share
/// it); for virtual filesystems (tmpfs...) the mount point itself.
pub fn fs_key(mounts: &[MountEntry], p: &Path) -> Option<u64> {
    let c = canon(p.ancestors().find(|a| a.exists())?);
    let m = mounts.iter().filter(|m| c.starts_with(&m.point)).max_by_key(|m| m.point.components().count())?;
    let key = if m.source.starts_with('/') {
        format!("{}:{}", m.fstype, m.source)
    } else {
        format!("{}:{}", m.fstype, m.point.display())
    };
    u64::from_str_radix(&short_hash(&[&key]), 16).ok()
}

/// A mount point at or below `p` (deleting or moving `p` would reach into
/// another filesystem, or a bind mount of data that lives elsewhere).
pub fn mount_at_or_below(mounts: &[MountEntry], p: &Path) -> Option<PathBuf> {
    let c = canon(p);
    mounts.iter().find(|m| m.point.starts_with(p) || m.point.starts_with(&c)).map(|m| m.point.clone())
}

/// Mount points whose contents can legitimately "disappear": network, FUSE,
/// automount, removable (fstab noauto / x-systemd.automount).
pub fn volatile_mount_prefixes(mounts: &[MountEntry]) -> Vec<PathBuf> {
    let volatile = |t: &str| {
        matches!(t, "autofs" | "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "9p" | "ecryptfs") || t.starts_with("fuse")
    };
    let mut v: Vec<PathBuf> = mounts.iter().filter(|m| volatile(&m.fstype)).map(|m| m.point.clone()).collect();
    if let Ok(fstab) = fs::read_to_string("/etc/fstab") {
        for l in fstab.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 4 && f[1] != "/" && f[1] != "none" && f[1] != "swap" {
                if volatile(f[2]) || f[3].contains("noauto") || f[3].contains("x-systemd.automount") {
                    v.push(unescape_mount(f[1]));
                }
            }
        }
    }
    v
}

/// rename(2) that never replaces an existing destination.
pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let a = CString::new(from.as_os_str().as_bytes())?;
    let b = CString::new(to.as_os_str().as_bytes())?;
    let r = unsafe { libc::renameat2(libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), libc::RENAME_NOREPLACE) };
    if r == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EINVAL) {
        // Filesystem without RENAME_NOREPLACE support: best-effort check.
        if to.symlink_metadata().is_ok() {
            return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
        }
        return fs::rename(from, to);
    }
    Err(err)
}

/// Run a command with a hard timeout (a hung git on a dead mount, a stuck
/// docker daemon, ... must never hang the service). Output is collected on
/// threads so large outputs can't deadlock the pipes.
pub fn output_with_timeout(
    mut cmd: std::process::Command,
    stdin: Option<Vec<u8>>,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::io::{Read as _, Write as _};
    use std::process::Stdio;
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    Ok(std::process::Output { status, stdout: t_out.join().unwrap_or_default(), stderr: t_err.join().unwrap_or_default() })
}

/// A bare repository: HEAD file + objects/ + refs/ (no worktree).
pub fn is_bare_repo(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir()
        && dir.file_name().is_some_and(|n| n != ".git")
}
pub const CACHEDIR_SIG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute())
}

pub fn expand_tilde(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        if let Some(h) = home() {
            return h.join(rest);
        }
    }
    p.to_path_buf()
}

/// Shorten for display only.
pub fn display_path(p: &Path) -> String {
    if let Some(h) = home() {
        if let Ok(rest) = p.strip_prefix(&h) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}

pub fn canon(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

pub fn has_parent_components(p: &Path) -> bool {
    p.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

/// max(mtime, ctime): ctime cannot be faked by tools that preserve mtime.
pub fn mctime(m: &fs::Metadata) -> i64 {
    m.mtime().max(m.ctime())
}

pub fn mtime(p: &Path) -> Option<i64> {
    fs::symlink_metadata(p).ok().map(|m| mctime(&m))
}

pub fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

pub fn fmt_age(now: i64, t: Option<i64>) -> String {
    match t {
        None => "?".into(),
        Some(t) => {
            let s = (now - t).max(0);
            if s < 3600 {
                format!("{}m", s / 60)
            } else if s < 2 * DAY {
                format!("{}h", s / 3600)
            } else {
                format!("{}d", s / DAY)
            }
        }
    }
}

pub fn fmt_bytes(b: Option<u64>) -> String {
    match b {
        None => "-".into(),
        Some(b) => {
            let units = ["B", "K", "M", "G", "T"];
            let mut v = b as f64;
            let mut i = 0;
            while v >= 1024.0 && i < units.len() - 1 {
                v /= 1024.0;
                i += 1;
            }
            if i == 0 {
                format!("{b}B")
            } else {
                format!("{v:.1}{}", units[i])
            }
        }
    }
}

pub fn fmt_ts(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| t.to_string())
}

pub fn stamp(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y%m%dT%H%M%S").to_string())
        .unwrap_or_else(|| t.to_string())
}

/// Shell-style glob supporting `*` and `?`.
pub fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn short_hash(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for b in part.bytes().chain(std::iter::once(0u8)) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    format!("{:010x}", h & 0xff_ffff_ffff)
}

/// Timestamp of the last entry of a git reflog file (reads only the tail).
pub fn reflog_last_ts(path: &Path) -> Option<i64> {
    let mut f = fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(4096);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    let line = buf.lines().rev().find(|l| !l.trim().is_empty())?;
    let head = line.split('\t').next()?;
    let fields: Vec<&str> = head.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    fields[fields.len() - 2].parse().ok()
}

pub fn is_cachedir_tag(dir: &Path) -> bool {
    let mut buf = [0u8; 43];
    match fs::File::open(dir.join("CACHEDIR.TAG")) {
        Ok(mut f) => f.read_exact(&mut buf).is_ok() && buf == CACHEDIR_SIG,
        Err(_) => false,
    }
}

#[derive(Debug, Default, Clone)]
pub struct DirScan {
    pub bytes: u64,
    /// `.git` entries (repos, worktrees, submodules) at depth >= 1.
    pub nested_git: Vec<PathBuf>,
    /// Bare repositories found inside.
    pub bare: Vec<PathBuf>,
    pub sockets: Vec<PathBuf>,
    pub keep_marker: Option<PathBuf>,
}

fn inside_git_dir(top: &Path, p: &Path) -> bool {
    p.strip_prefix(top).map(|r| r.components().any(|c| c.as_os_str() == ".git")).unwrap_or(false)
}

/// Disk usage (allocated blocks) plus anything that signals irreplaceable
/// content. Never follows symlinks or crosses device boundaries.
pub fn dir_scan(p: &Path, keep_marker: &str) -> DirScan {
    let mut seen = HashSet::new();
    let mut ds = DirScan::default();
    let mut it = walkdir::WalkDir::new(p).follow_links(false).same_file_system(true).into_iter();
    while let Some(e) = it.next() {
        let Ok(e) = e else { continue };
        if e.depth() > 0 {
            let name = e.file_name();
            if name == ".git" {
                ds.nested_git.push(e.path().to_path_buf());
            } else if name == keep_marker && ds.keep_marker.is_none() {
                ds.keep_marker = Some(e.path().to_path_buf());
            } else if e.file_type().is_dir() && is_bare_repo(e.path()) && !inside_git_dir(p, e.path()) {
                ds.bare.push(e.path().to_path_buf());
            } else if e.file_type().is_socket() {
                ds.sockets.push(e.path().to_path_buf());
            }
        }
        let Ok(m) = e.metadata() else { continue };
        if m.nlink() > 1 && !m.is_dir() && !seen.insert((m.dev(), m.ino())) {
            continue;
        }
        ds.bytes += m.blocks() * 512;
    }
    ds
}

pub fn dir_size(p: &Path) -> u64 {
    dir_scan(p, "\0").bytes
}

#[derive(Debug, Default)]
pub struct WalkStat {
    pub newest: Option<i64>,
    pub entries: usize,
    pub truncated: bool,
    /// Directories containing a `.git` directory (independent repos).
    pub repos: Vec<PathBuf>,
    /// Directories containing a `.git` file (linked worktrees / submodules).
    pub linked: Vec<PathBuf>,
    pub bare: Vec<PathBuf>,
    pub sockets: Vec<PathBuf>,
    pub keep_marker: Option<PathBuf>,
}

/// Bounded walk collecting newest timestamp and anything that signals value.
pub fn walk_stat(p: &Path, cap: usize, keep_marker: &str) -> WalkStat {
    let mut ws = WalkStat::default();
    let mut it = walkdir::WalkDir::new(p).follow_links(false).same_file_system(true).into_iter();
    while let Some(e) = it.next() {
        let Ok(e) = e else { continue };
        ws.entries += 1;
        if ws.entries > cap {
            ws.truncated = true;
            break;
        }
        let Ok(m) = e.metadata() else { continue };
        ws.newest = max_opt(ws.newest, Some(mctime(&m)));
        let name = e.file_name();
        if name == ".git" {
            if let Some(parent) = e.path().parent() {
                if m.is_dir() {
                    ws.repos.push(parent.to_path_buf());
                    it.skip_current_dir();
                } else {
                    ws.linked.push(parent.to_path_buf());
                }
            }
        } else if name == keep_marker && ws.keep_marker.is_none() {
            ws.keep_marker = Some(e.path().to_path_buf());
        } else if m.is_dir() && is_bare_repo(e.path()) && !inside_git_dir(p, e.path()) {
            ws.bare.push(e.path().to_path_buf());
            it.skip_current_dir();
        } else if m.file_type().is_socket() {
            ws.sockets.push(e.path().to_path_buf());
        }
    }
    ws
}

pub fn dev_of(p: &Path) -> Option<u64> {
    fs::symlink_metadata(p).ok().map(|m| m.dev())
}

/// Device of the path or of its nearest existing ancestor.
pub fn dev_of_nearest(p: &Path) -> Option<u64> {
    p.ancestors().find_map(dev_of)
}

pub fn is_special_file(m: &fs::Metadata) -> bool {
    let ft = m.file_type();
    ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device()
}

/// (total bytes, available bytes) of the filesystem containing `p`.
pub fn fs_usage(p: &Path) -> Option<(u64, u64)> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let f = s.f_frsize as u64;
    Some((s.f_blocks as u64 * f, s.f_bavail as u64 * f))
}
