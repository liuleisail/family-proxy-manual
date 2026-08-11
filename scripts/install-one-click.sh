#!/usr/bin/env bash
# One-click first install: bootstrap the host, then finish in the LAN web wizard.
set -Eeuo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec "$repo_dir/scripts/bootstrap-interactive.sh" --web-setup "$@"
