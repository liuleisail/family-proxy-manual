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
if [[ ! -s "$dir/config.yaml" ]]; then
  install -m 640 "$repo/deploy/mihomo-config.base.yaml" "$dir/config.yaml"
  echo "Initialized Mihomo baseline configuration."
else
  echo "Preserving existing Mihomo config.yaml and its current rule state."
fi
if [[ ! -s "$dir/docker-compose.yml" ]]; then
  install -m 640 "$repo/deploy/mihomo-compose.yml" "$dir/docker-compose.yml"
else
  echo "Preserving existing Mihomo Compose configuration."
fi
if [[ ! -e "$dir/cache.db" ]]; then
  install -m 640 /dev/null "$dir/cache.db"
elif [[ ! -f "$dir/cache.db" ]]; then
  echo "$dir/cache.db exists but is not a regular file; move it aside and retry" >&2
  exit 1
fi
docker compose -f "$dir/docker-compose.yml" up -d
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:9091/version >/dev/null && break; sleep 2; done
curl -fsS http://127.0.0.1:9091/version >/dev/null || { echo "Mihomo controller did not become ready" >&2; exit 1; }
echo "Mihomo is ready. Import one native subscription in the management UI; the first import creates a usable bootstrap pool before any optional speed test."
