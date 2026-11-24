#!/usr/bin/env bash
# Installs tree-gc as a *user* service. A fresh config starts in shadow mode
# (enforce = false); an existing config is kept as is.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --release --manifest-path "$here/Cargo.toml"
install -Dm755 "$here/target/release/tree-gc" "$HOME/.local/bin/tree-gc"
install -Dm644 "$here/packaging/tree-gc.service" "$HOME/.config/systemd/user/tree-gc.service"
install -Dm644 "$here/packaging/tree-gc.timer"   "$HOME/.config/systemd/user/tree-gc.timer"
install -Dm644 "$here/packaging/tree-gc-guard.service" "$HOME/.config/systemd/user/tree-gc-guard.service"
install -Dm644 "$here/packaging/tree-gc-guard.timer"   "$HOME/.config/systemd/user/tree-gc-guard.timer"
[ -f "$HOME/.config/tree-gc/config.toml" ] || "$HOME/.local/bin/tree-gc" init-config
systemctl --user daemon-reload
systemctl --user enable --now tree-gc.timer tree-gc-guard.timer
if grep -Eq '^[[:space:]]*enforce[[:space:]]*=[[:space:]]*true' "$HOME/.config/tree-gc/config.toml"; then
  echo "Installed in REAL mode (enforce = true in ~/.config/tree-gc/config.toml)."
else
  echo "Installed in SHADOW mode (enforce = false): scheduled runs report candidates without applying cleanup."
fi
echo "Review with: tree-gc survey / tree-gc plan / tree-gc pressure / tree-gc log --level warn"
echo "Logs: journalctl --user -u tree-gc -u tree-gc-guard   History: ~/.local/state/tree-gc/history.jsonl"
