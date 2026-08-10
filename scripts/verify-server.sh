#!/usr/bin/env bash
set -Eeuo pipefail
for unit in family-proxy-ui family-mihomo-sub-import family-proxy-gateway; do
  systemctl is-active --quiet "$unit" || { echo "$unit is not active" >&2; exit 1; }
done
for executable in /usr/local/sbin/sync-routeros-cn-ipv4 /usr/local/sbin/refresh-mihomo-geodata /usr/local/sbin/family-mihomo-upgrade /usr/local/sbin/homekit-direct-routes /usr/local/sbin/apply-family-proxy-mode; do
  [[ -x $executable ]] || { echo "$executable is missing" >&2; exit 1; }
done
systemctl is-enabled --quiet family-cn-ipv4-refresh.timer || { echo "CN refresh timer is disabled" >&2; exit 1; }
systemctl is-enabled --quiet family-platform-update-check.timer || { echo "platform update check timer is disabled" >&2; exit 1; }
router_mode=$(awk -F= '$1 == "ROUTER_MODE" { print tolower($2); exit }' /etc/family-proxy-ui/router.env)
if [[ ${router_mode:-routeros} == routeros ]]; then
  systemctl is-enabled --quiet homekit-direct-routes.timer || { echo "HomeKit direct route timer is disabled" >&2; exit 1; }
else
  [[ ${router_mode:-} == standalone ]] || { echo "Router mode is unresolved: ${router_mode:-missing}" >&2; exit 1; }
  systemctl is-enabled --quiet homekit-direct-routes.timer && { echo "HomeKit timer must be disabled in standalone mode" >&2; exit 1; } || true
fi
if grep -qx 'MIHOMO_GEODATA_AUTO_UPDATE=true' /etc/family-proxy-ui/router.env; then
  systemctl is-enabled --quiet family-mihomo-geodata-refresh.timer || { echo "Mihomo geodata auto-update is configured but its timer is disabled" >&2; exit 1; }
fi
python3 - <<'PY'
import json
import importlib.util
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

secret = Path('/etc/family-proxy-ui/gateway.secret').read_text().strip()
checks = (
    (18093, '/api/health'),
    (18093, '/api/system/status'),
    (18093, '/api/wireguard/status'),
    (18093, '/api/captures'),
    (18090, '/api/state'),
)
responses = {}
for port, path in checks:
    request = Request(
        f'http://127.0.0.1:{port}{path}',
        headers={'X-Family-Gateway': secret},
    )
    response = None
    for attempt in range(20):
        try:
            response = urlopen(request, timeout=8)
            break
        except URLError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    with response:
        if response.status != 200:
            raise SystemExit(f'{port}{path}: HTTP {response.status}')
        payload = json.load(response)
        responses[(port, path)] = payload
        if path == '/api/system/status' and not {'cpu', 'memory', 'disk', 'docker'} <= payload.keys():
            raise SystemExit('system status payload is incomplete')
        if path == '/api/wireguard/status':
            if not {'updated_at', 'interfaces', 'events'} <= payload.keys():
                raise SystemExit('WireGuard status payload is incomplete')
            forbidden = {'public-key', 'private-key', 'preshared-key'}
            for interface in payload['interfaces']:
                if forbidden & interface.keys() or any(forbidden & peer.keys() for peer in interface.get('peers', [])):
                    raise SystemExit('WireGuard status exposes key material')
        if path == '/api/captures':
            expected = {'file_bytes': 50_000_000, 'total_bytes': 200_000_000,
                        'retention_seconds': 86_400}
            if payload.get('limits') != expected:
                raise SystemExit(f'capture limits are unexpected: {payload.get("limits")}')
            if 'live' not in payload:
                raise SystemExit('capture live-view payload is missing')

env_values = {}
for raw in Path('/etc/family-proxy-ui/router.env').read_text().splitlines():
    if '=' in raw and not raw.lstrip().startswith('#'):
        key, value = raw.split('=', 1)
        env_values[key] = value
provider_root = Path(env_values['FAMILY_DOCKER_ROOT']) / 'family-mihomo-sub-import' / 'providers'
candidate_file = provider_root / 'candidates.json'
if candidate_file.is_file():
    disk_pools = json.loads(candidate_file.read_text())
    api_pools = responses[(18090, '/api/state')].get('pools', {})
    disk_count = sum(len(items) for items in disk_pools.values() if isinstance(items, list))
    api_count = sum(len(items) for items in api_pools.values() if isinstance(items, list))
    if disk_count and api_count != disk_count:
        raise SystemExit(
            f'candidate pool visibility mismatch: disk={disk_count}, api={api_count}; '
            'check PrivateTmp and FAMILY_DOCKER_ROOT'
        )

capture_dir = Path('/run/family-proxy-captures')
if not capture_dir.is_dir():
    raise SystemExit('capture runtime directory is missing')

gateway_path = Path('/opt/family-proxy-ui/family-proxy-gateway.py')
spec = importlib.util.spec_from_file_location('family_proxy_gateway_verify', gateway_path)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
handler = gateway.Handler.__new__(gateway.Handler)
handler.headers = {}
legacy_routes = {
    '/dns/maintenance-api/metrics': 18102,
    '/api/v1/system/health': 18091,
    '/api/v2/audit/stats': 18091,
    '/plugins/geosite_cn/config': 18091,
    '/maintenance-api/metrics': 18102,
}
for path, expected_port in legacy_routes.items():
    target = handler.target(path, '')
    if target[0] != 'backend' or target[2] != expected_port:
        raise SystemExit(f'legacy DNS route failed: {path} -> {target}')
print('control-plane local checks passed')
PY
echo "Next: verify Mihomo/DNS in the LAN UI, then apply RouterOS preparation commands."
