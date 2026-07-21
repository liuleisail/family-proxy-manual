#!/usr/bin/env bash
set -Eeuo pipefail
for unit in family-proxy-ui family-mihomo-sub-import family-proxy-gateway; do
  systemctl is-active --quiet "$unit" || { echo "$unit is not active" >&2; exit 1; }
done
python3 - <<'PY'
import json
import importlib.util
from pathlib import Path
from urllib.request import Request, urlopen

secret = Path('/etc/family-proxy-ui/gateway.secret').read_text().strip()
checks = ((18093, '/api/health'), (18093, '/api/system/status'), (18090, '/api/state'))
for port, path in checks:
    request = Request(
        f'http://127.0.0.1:{port}{path}',
        headers={'X-Family-Gateway': secret},
    )
    with urlopen(request, timeout=8) as response:
        if response.status != 200:
            raise SystemExit(f'{port}{path}: HTTP {response.status}')
        payload = json.load(response)
        if path == '/api/system/status' and not {'cpu', 'memory', 'disk', 'docker'} <= payload.keys():
            raise SystemExit('system status payload is incomplete')

gateway_path = Path('/opt/family-proxy-ui/family-proxy-gateway.py')
spec = importlib.util.spec_from_file_location('family_proxy_gateway_verify', gateway_path)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
handler = gateway.Handler.__new__(gateway.Handler)
handler.headers = {'Referer': 'http://gateway/dns/#data'}
legacy_routes = {
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
