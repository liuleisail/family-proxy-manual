#!/usr/bin/env bash
# Install the optional MosDNS dashboard and restricted maintenance API.
set -Eeuo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_DIR=""
CORE_API="http://172.31.53.2:9099"
DNS_SERVER=""
SOCKS5="172.31.53.1:7890"

usage() {
  cat <<'EOF'
Usage:
  sudo scripts/install-mosdns-management.sh \
    --compose-dir /path/to/family-mosdns-t \
    --dns-server 192.0.2.10 \
    [--core-api http://172.31.53.2:9099] \
    [--socks5 172.31.53.1:7890]

This installs only the MosDNS management UI and maintenance API. It does not
restart the MosDNS core, change upstreams, modify RouterOS, or redirect DNS.
EOF
}

while (($#)); do
  case "$1" in
    --compose-dir) COMPOSE_DIR=${2:-}; shift 2 ;;
    --core-api) CORE_API=${2:-}; shift 2 ;;
    --dns-server) DNS_SERVER=${2:-}; shift 2 ;;
    --socks5) SOCKS5=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -n $COMPOSE_DIR && -n $DNS_SERVER ]] || { usage >&2; exit 2; }
for value in "$COMPOSE_DIR" "$CORE_API" "$DNS_SERVER" "$SOCKS5"; do
  [[ $value != *$'\n'* && $value != *'"'* ]] || { echo "invalid parameter" >&2; exit 2; }
done
COMPOSE_DIR=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$COMPOSE_DIR")
[[ -f $COMPOSE_DIR/compose.yml ]] || { echo "compose.yml not found in $COMPOSE_DIR" >&2; exit 1; }
[[ -f $COMPOSE_DIR/web/index.html ]] || { echo "web/index.html not found in $COMPOSE_DIR" >&2; exit 1; }
[[ -f $COMPOSE_DIR/data/webinfo/upstream_overrides.json ]] || { echo "upstream_overrides.json not found; refusing to guess the MosDNS data path" >&2; exit 1; }
[[ -s /etc/family-proxy-ui/gateway.secret ]] || { echo "gateway.secret is missing; install the unified gateway first" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v dig >/dev/null || { echo "dig is required" >&2; exit 1; }
docker compose -f "$COMPOSE_DIR/compose.yml" config -q

stamp=$(date +%Y%m%d-%H%M%S)
backup=/var/backups/family-proxy/$stamp/mosdns-management
install -d -m 700 "$backup" /opt/family-mosdns-updater
[[ -f /opt/family-mosdns-updater/app.py ]] && cp -a /opt/family-mosdns-updater/app.py "$backup/"
[[ -f /etc/systemd/system/family-mosdns-updater.service ]] && cp -a /etc/systemd/system/family-mosdns-updater.service "$backup/"
cp -a "$COMPOSE_DIR/web/index.html" "$backup/dashboard.html"
cp -a "$COMPOSE_DIR/data/webinfo/upstream_overrides.json" "$backup/upstream_overrides.json"

install -m 0755 "$REPO_DIR/runtime/mosdns/updater.py" /opt/family-mosdns-updater/app.py
install -m 0644 "$REPO_DIR/runtime/mosdns/dashboard.html" "$COMPOSE_DIR/web/index.html"
python3 - "$REPO_DIR/systemd/family-mosdns-updater.service.in" /etc/systemd/system/family-mosdns-updater.service "$COMPOSE_DIR" "$CORE_API" "$DNS_SERVER" "$SOCKS5" <<'PY'
from pathlib import Path
import sys

source, target, compose_dir, core_api, dns_server, socks5 = sys.argv[1:]
text = Path(source).read_text(encoding="utf-8")
for marker, value in {
    "__COMPOSE_DIR__": compose_dir,
    "__CORE_API__": core_api.rstrip("/"),
    "__DNS_SERVER__": dns_server,
    "__SOCKS5__": socks5,
}.items():
    text = text.replace(marker, value)
Path(target).write_text(text, encoding="utf-8")
PY

python3 -m py_compile /opt/family-mosdns-updater/app.py
systemctl daemon-reload
systemctl enable family-mosdns-updater.service
systemctl restart family-mosdns-updater.service

# dashboard.html is a single-file bind mount. Recreate only the UI service so
# Nginx receives the new inode; the MosDNS core and port 53 stay untouched.
docker compose -f "$COMPOSE_DIR/compose.yml" up -d --no-deps --force-recreate ui
ui_container=$(docker compose -f "$COMPOSE_DIR/compose.yml" ps -q ui)
[[ -n $ui_container ]] || { echo "MosDNS UI container did not start" >&2; exit 1; }
docker exec "$ui_container" test -r /usr/share/nginx/html/index.html
systemctl is-active --quiet family-mosdns-updater.service
secret=$(cat /etc/family-proxy-ui/gateway.secret)
curl --fail --silent --show-error -H "X-Family-Gateway: $secret" http://127.0.0.1:18102/upstreams >/dev/null
curl --fail --silent --show-error -H "X-Family-Gateway: $secret" http://127.0.0.1:18102/adblock/status >/dev/null

echo "MosDNS management installed. Backup: $backup"
echo "The MosDNS core, RouterOS, DHCP DNS, and current upstream configuration were not changed."
