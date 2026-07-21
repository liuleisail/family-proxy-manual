#!/usr/bin/env bash
# Explicit Docker step. It never replaces an existing container of the same name.
set -Eeuo pipefail
CONFIG=/etc/family-proxy-ui/router.env
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -r $CONFIG ]] || { echo "run install-server.sh first" >&2; exit 1; }
root=$(awk -F= '$1=="FAMILY_DOCKER_ROOT" {print substr($0,index($0,"=")+1)}' "$CONFIG")
[[ -n $root ]] || { echo "FAMILY_DOCKER_ROOT is missing" >&2; exit 1; }
if docker inspect family-mihomo-fallback >/dev/null 2>&1; then
  echo "family-mihomo-fallback already exists; refusing to replace it" >&2
  exit 1
fi
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dir="$root/family-mihomo-fallback"
install -d -m 700 "$dir"
install -m 640 "$repo/deploy/mihomo-config.base.yaml" "$dir/config.yaml"
install -m 640 "$repo/deploy/mihomo-compose.yml" "$dir/docker-compose.yml"
docker compose -f "$dir/docker-compose.yml" up -d
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:9091/version >/dev/null && break; sleep 2; done
curl -fsS http://127.0.0.1:9091/version >/dev/null || { echo "Mihomo controller did not become ready" >&2; exit 1; }
echo "Mihomo is ready. Import subscriptions in the management UI before adding a client device."
