#!/usr/bin/env bash
# Run from a checkout with Bash, Git and Cargo installed.
set -euo pipefail
project=$(cd "$(dirname "$0")/.." && pwd)
demo=$(mktemp -d)
trap 'rm -rf -- "$demo"' EXIT
mkdir -p "$demo/projects"
repo="$demo/projects/atlas"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q -b main "$repo"
echo '.env' > "$repo/.gitignore"
git -C "$repo" add .gitignore
git -C "$repo" -c user.name=Demo -c user.email=demo@example.invalid commit -qm 'Initial commit'
git -C "$repo" worktree add -q -b finished "$demo/projects/atlas-finished"
git -C "$repo" worktree add -q -b experiment "$demo/projects/atlas-experiment"
echo 'LOCAL_SETTING=demo' > "$demo/projects/atlas-experiment/.env"

cat > "$demo/config.toml" <<CONFIG
enforce = false
state_dir = "$demo/state"
quarantine_dir = "$demo/quarantine"
scratch = []
[[roots]]
path = "$demo/projects"
[branches]
enabled = false
[docker]
enabled = false
[pressure]
enabled = false
CONFIG
cargo run --locked --quiet --manifest-path "$project/Cargo.toml" -- \
  --config "$demo/config.toml" plan --all --days 30
