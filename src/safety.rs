//! Last line of defence: structural checks on any path about to be moved or
//! deleted, independent of the policy that selected it.
use crate::model::{Item, Kind};
use crate::scan::Ctx;
use crate::util::{canon, has_parent_components, home};
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;

pub fn check_target(ctx: &Ctx, item: &Item) -> Result<()> {
    let p = &item.path;
    if item.kind == Kind::Docker {
        // Not a filesystem path: docker actions go through the docker CLI and
        // are rebuilt from a live snapshot in reverify (plan fields untrusted).
        if !p.to_string_lossy().starts_with("docker:") {
            bail!("refusing docker item with non-docker path {}", p.display());
        }
        return Ok(());
    }
    if !p.is_absolute() || has_parent_components(p) {
        bail!("refusing non-normalized path {}", p.display());
    }
    if p.components().count() < 3 {
        bail!("refusing shallow path {}", p.display());
    }
    if item.kind == Kind::Branch {
        return Ok(()); // ref-only operation; path is the repo
    }
    if let Some(h) = home() {
        if h.starts_with(p) {
            bail!("refusing {}: contains $HOME", p.display());
        }
    }
    let cfg = ctx.cfg;
    for r in &cfg.roots {
        if r.path.starts_with(p) {
            bail!("refusing {}: is or contains a configured root", p.display());
        }
    }
    for s in &cfg.scratch {
        if s.path.starts_with(p) {
            bail!("refusing {}: is or contains a scratch directory", p.display());
        }
    }
    for internal in [&cfg.state_dir, &cfg.quarantine_dir] {
        if internal.starts_with(p) || p.starts_with(internal) {
            bail!("refusing {}: overlaps tree-gc state/quarantine", p.display());
        }
    }
    if item.kind == Kind::StaleWorktreeMeta {
        return Ok(()); // the dir is gone; we only move the admin dir (checked in exec)
    }
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() && item.kind != Kind::TmpEntry && item.kind != Kind::Scratch {
        bail!("refusing symlink {}", p.display());
    }
    // The real location must agree with the recorded one (no symlinked parents).
    let parent = p.parent().unwrap_or(p);
    if canon(parent) != parent {
        bail!("refusing {}: parent directory resolves elsewhere ({})", p.display(), canon(parent).display());
    }
    match item.kind {
        Kind::Worktree => {
            if !p.join(".git").is_file() {
                bail!("refusing {}: not a linked worktree (.git is not a file)", p.display());
            }
            if let Some(repo) = &item.repo {
                if repo.starts_with(p) {
                    bail!("refusing {}: contains the main repository", p.display());
                }
            }
        }
        Kind::Artifact | Kind::TmpEntry | Kind::Scratch => {
            let root = item.root.as_deref().unwrap_or(Path::new("/"));
            if !p.starts_with(root) || p == root {
                bail!("refusing {}: not strictly inside its root {}", p.display(), root.display());
            }
        }
        _ => {}
    }
    Ok(())
}
