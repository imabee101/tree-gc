use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What kind of thing an item is. The declaration order is also the
/// "tier" order used when acting: cheapest / most lossless first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// `.git/worktrees/<id>` admin entry whose working directory is gone.
    StaleWorktreeMeta,
    /// Local branch (refs/heads/*).
    Branch,
    /// Docker build cache / unused images / long-stopped containers.
    Docker,
    /// Regenerable build output (target/, node_modules/, caches...).
    Artifact,
    /// Child of an agent/tool scratch directory (see [[scratch]] rules).
    Scratch,
    /// Linked git worktree directory.
    Worktree,
    /// Top-level entry of a tmp root.
    TmpEntry,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::StaleWorktreeMeta,
        Kind::Branch,
        Kind::Docker,
        Kind::Artifact,
        Kind::Scratch,
        Kind::Worktree,
        Kind::TmpEntry,
    ];
    pub fn label(&self) -> &'static str {
        match self {
            Kind::StaleWorktreeMeta => "wt-meta",
            Kind::Branch => "branch",
            Kind::Docker => "docker",
            Kind::Artifact => "artifact",
            Kind::Scratch => "scratch",
            Kind::Worktree => "worktree",
            Kind::TmpEntry => "tmp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Stale and passed every safety check: would be acted on.
    Eligible,
    /// Safe to collect eventually, but used too recently.
    Active,
    /// Holds (or may hold) irreplaceable state. Never touched.
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Move the admin dir to quarantine (detached HEAD archived as a ref first).
    PruneWorktreeMeta,
    /// Move refs/heads/X to refs/tree-gc/archive/... (lossless, instant undo).
    ArchiveBranch,
    /// rm -rf a positively identified, git-ignored build output directory.
    DeleteArtifact,
    /// Move worktree dir + admin dir to quarantine (undo with `restore`).
    QuarantineWorktree,
    /// Move a tmp/scratch entry to quarantine (undo with `restore`).
    QuarantinePath,
    /// rm -rf a scratch entry whose rule says action = "delete" (pure caches).
    DeletePath,
    /// `docker builder prune --filter until=<age>` (cache unused that long).
    DockerBuildCache,
    /// `docker image prune -a --filter until=<age>` (images no container uses).
    DockerImages,
    /// `docker rm <id>` without -v (volumes are kept).
    DockerContainer,
}

impl Action {
    pub fn label(&self) -> &'static str {
        match self {
            Action::PruneWorktreeMeta => "prune-meta",
            Action::ArchiveBranch => "archive-ref",
            Action::DeleteArtifact => "delete",
            Action::QuarantineWorktree => "quarantine",
            Action::QuarantinePath => "quarantine",
            Action::DeletePath => "delete",
            Action::DockerBuildCache | Action::DockerImages => "prune",
            Action::DockerContainer => "docker-rm",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub kind: Kind,
    pub verdict: Verdict,
    pub action: Option<Action>,
    /// Worktree dir, artifact dir, tmp entry; for branches the repo handle.
    pub path: PathBuf,
    /// Configured root the item was found under (if any).
    pub root: Option<PathBuf>,
    /// Repo handle (main worktree or bare dir) for git items.
    pub repo: Option<PathBuf>,
    pub branch: Option<String>,
    pub head: Option<String>,
    pub admin_dir: Option<PathBuf>,
    /// Unix seconds of the most recent sign of activity we could find.
    pub last_activity: Option<i64>,
    pub bytes: Option<u64>,
    /// Promoted to Eligible only because of disk pressure.
    pub pressure: bool,
    /// Name of the scratch rule that produced this item.
    pub rule: Option<String>,
    pub reasons: Vec<String>,
}

impl Item {
    pub fn new(kind: Kind, path: PathBuf) -> Self {
        Item {
            id: String::new(),
            kind,
            verdict: Verdict::Protected,
            action: None,
            path,
            root: None,
            repo: None,
            branch: None,
            head: None,
            admin_dir: None,
            last_activity: None,
            bytes: None,
            pressure: false,
            rule: None,
            reasons: vec![],
        }
    }

    pub fn compute_id(&mut self) {
        self.id = crate::util::short_hash(&[
            self.kind.label(),
            &self.path.to_string_lossy(),
            self.branch.as_deref().unwrap_or(""),
        ]);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub generated_at: i64,
    /// Evaluation time; differs from generated_at when simulating the future.
    pub now: i64,
    pub simulated: bool,
    pub enforce: bool,
    pub items: Vec<Item>,
    pub notes: Vec<String>,
}

impl Plan {
    pub fn eligible(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.verdict == Verdict::Eligible)
    }
}
