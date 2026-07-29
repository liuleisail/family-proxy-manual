#!/usr/bin/env bash
# Upgrade uses the same installer and retains timestamped backups.
set -Eeuo pipefail
REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $EUID -eq 0 ]]; then
  "$REPO_DIR/scripts/install-server.sh" --start
  python3 /opt/family-proxy-ui/family-mihomo-sub-import.py --apply-current
  "$REPO_DIR/scripts/verify-server.sh"
else
  sudo "$REPO_DIR/scripts/install-server.sh" --start
  sudo python3 /opt/family-proxy-ui/family-mihomo-sub-import.py --apply-current
  sudo "$REPO_DIR/scripts/verify-server.sh"
fi
