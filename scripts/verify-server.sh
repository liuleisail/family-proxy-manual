#!/usr/bin/env bash
set -Eeuo pipefail
for unit in family-proxy-ui family-mihomo-sub-import family-proxy-gateway; do
  systemctl is-active --quiet "$unit" || { echo "$unit is not active" >&2; exit 1; }
done
python3 - <<'PY'
from urllib.request import urlopen
for port, path in ((18093, '/api/health'), (18090, '/api/state')):
    with urlopen(f'http://127.0.0.1:{port}{path}', timeout=5) as response:
        if response.status != 200:
            raise SystemExit(f'{port}{path}: HTTP {response.status}')
print('control-plane local checks passed')
PY
echo "Next: verify Mihomo/DNS in the LAN UI, then apply RouterOS preparation commands."
