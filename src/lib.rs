//! Plan and clean up stale developer workspaces on Linux.
//!
//! Shadow mode previews cleanup. Enforced runs can archive branches, quarantine
//! worktrees and delete recognized build output. Disk pressure can shorten
//! quarantine retention.

// First, so its macros are in scope for every module below.
#[macro_use]
pub mod log;

pub mod clock;
pub mod config;
pub mod docker;
pub mod exec;
pub mod git;
pub mod model;
pub mod pressure;
pub mod procs;
pub mod report;
pub mod safety;
pub mod scan;
pub mod util;
