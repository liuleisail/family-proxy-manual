#!/usr/bin/env bash
# Keep online rule-provider caches writable while subscription providers stay read-only.
set -Eeuo pipefail

CONFIG=/etc/family-proxy-ui/router.env
SERVICE=family-mihomo-fallback
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -r $CONFIG ]] || { echo "missing $CONFIG" >&2; exit 1; }

root=$(awk -F= '$1=="FAMILY_DOCKER_ROOT" {print substr($0,index($0,"=")+1); exit}' "$CONFIG")
compose="$root/family-mihomo-fallback/docker-compose.yml"
provider_root="$root/family-mihomo-docker/providers"
[[ -n $root && $root == /* && -f $compose ]] || { echo "Mihomo Compose path is unavailable" >&2; exit 1; }
install -d -m 700 "$provider_root/rule-sets"

stamp=$(date +%Y%m%d-%H%M%S)
backup="$compose.before-rule-provider-storage-$stamp"
cp -a "$compose" "$backup"

changed=$(python3 - "$compose" <<'PY'
import os, sys, yaml

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = yaml.safe_load(handle)
service = document.get("services", {}).get("family-mihomo-fallback")
if not isinstance(service, dict):
    raise SystemExit("Mihomo Compose service is unavailable")
volumes = service.setdefault("volumes", [])
if not isinstance(volumes, list):
    raise SystemExit("Mihomo Compose volumes are invalid")

destination = "/root/.config/mihomo/providers"
replacement = "../family-mihomo-docker/providers:" + destination + ":rw"
updated = []
found = False
changed = False
for entry in volumes:
    if isinstance(entry, str):
        parts = entry.rsplit(":", 2)
        entry_destination = parts[-2] if len(parts) == 3 else parts[-1]
        if entry_destination == destination:
            found = True
            if entry != replacement:
                changed = True
            updated.append(replacement)
            continue
    elif isinstance(entry, dict) and entry.get("target") == destination:
        found = True
        normalized = {"type": "bind", "source": "../family-mihomo-docker/providers",
                      "target": destination, "read_only": False}
        if entry != normalized:
            changed = True
        updated.append(normalized)
        continue
    updated.append(entry)
if not found:
    updated.append(replacement)
    changed = True
service["volumes"] = updated
if changed:
    temporary = path + ".new"
    with open(temporary, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, allow_unicode=True, sort_keys=False)
    os.chmod(temporary, os.stat(path).st_mode & 0o777)
    os.replace(temporary, path)
print("yes" if changed else "no")
PY
)

if [[ $changed == no ]]; then
  rm -f "$backup"
  echo "Mihomo rule-provider storage is already writable"
  exit 0
fi

rollback() {
  cp -a "$backup" "$compose"
  docker compose -f "$compose" up -d --no-deps --force-recreate "$SERVICE" >/dev/null 2>&1 || true
}
trap rollback ERR
docker compose -f "$compose" config --quiet
docker compose -f "$compose" up -d --no-deps --force-recreate "$SERVICE"
for _ in $(seq 1 30); do
  curl -fsS --max-time 3 http://127.0.0.1:9091/version >/dev/null && break
  sleep 1
done
curl -fsS --max-time 3 http://127.0.0.1:9091/version >/dev/null
trap - ERR
echo "Mihomo rule-provider storage changed to writable. Backup: $backup"
