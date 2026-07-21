#!/usr/bin/env bash
# Idempotent control-plane installer. It never writes RouterOS configuration.
set -Eeuo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG=/etc/family-proxy-ui/router.env
START=0
if [[ ${1:-} == "--config" ]]; then CONFIG=$2; shift 2; fi
[[ ${1:-} == "--start" ]] && START=1
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker must be installed first; installer will not replace NAS Docker" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || {
  command -v apt-get >/dev/null || { echo "install python3-yaml, then retry" >&2; exit 1; }
  apt-get update && apt-get install -y python3-yaml
}
if [[ ! -f $CONFIG ]]; then
  install -d -m 700 /etc/family-proxy-ui
  install -m 600 "$REPO_DIR/config/router.env.example" "$CONFIG"
  echo "Created $CONFIG. Fill the sensitive values, then rerun this command." >&2
  exit 2
fi
python3 "$REPO_DIR/scripts/prepare-config.py" "$CONFIG"
stamp=$(date +%Y%m%d-%H%M%S)
backup=/var/backups/family-proxy/$stamp
install -d -m 700 "$backup" /opt/family-proxy-ui /var/lib/family-proxy/docker
for item in /opt/family-proxy-ui /etc/family-proxy-ui /etc/systemd/system/family-proxy-ui.service /etc/systemd/system/family-mihomo-sub-import.service /etc/systemd/system/family-proxy-gateway.service /etc/systemd/system/family-mihomo-tproxy-auto.service; do
  [[ -e $item ]] && cp -a "$item" "$backup/" || true
done
install -d -m 700 /opt/family-proxy-ui/rendered
python3 "$REPO_DIR/scripts/render-runtime.py" "$CONFIG" "$REPO_DIR/runtime" /opt/family-proxy-ui/rendered
python3 -m py_compile /opt/family-proxy-ui/rendered/*.py
install -m 755 /opt/family-proxy-ui/rendered/family-proxy-ui.py /opt/family-proxy-ui/family-proxy-ui.py
install -m 755 /opt/family-proxy-ui/rendered/family-mihomo-sub-import.py /opt/family-proxy-ui/family-mihomo-sub-import.py
install -m 755 /opt/family-proxy-ui/rendered/family-proxy-gateway.py /opt/family-proxy-ui/family-proxy-gateway.py
install -m 755 "$REPO_DIR/scripts/family-mihomo-tproxy-auto" /usr/local/sbin/family-mihomo-tproxy-auto
install -d -m 700 /etc/family-proxy-ui /var/lib/family-proxy/docker/family-mihomo-sub-import/providers
install -m 600 /dev/null /etc/family-proxy-ui/managed-ips 2>/dev/null || true
[[ -s /etc/family-proxy-ui/gateway.secret ]] || { umask 077; head -c 48 /dev/urandom | base64 > /etc/family-proxy-ui/gateway.secret; }
for unit in "$REPO_DIR"/systemd/*.service; do install -m 644 "$unit" /etc/systemd/system/; done
systemctl daemon-reload
systemctl enable family-proxy-ui family-mihomo-sub-import family-proxy-gateway family-mihomo-tproxy-auto
echo "Installed control plane. Backup: $backup"
if (( START )); then
  systemctl restart family-proxy-ui family-mihomo-sub-import family-proxy-gateway
  systemctl --no-pager --full status family-proxy-ui family-mihomo-sub-import family-proxy-gateway
else
  echo "No services started. After Mihomo and DNS are ready, run: sudo $REPO_DIR/scripts/verify-server.sh"
fi
