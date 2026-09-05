#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"

[[ -s VERSION ]] || { echo "VERSION is missing" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || {
  echo "PyYAML is required for release verification; install it or set PYTHONPATH to an isolated dependency directory" >&2
  exit 1
}
git diff --check
python3 -m py_compile runtime/*.py scripts/*.py
python3 -m unittest discover -s tests -p 'test_*.py' -v

frontend_dir=${FAMILY_FRONTEND_BUILD_DIR:-$REPO_DIR/frontend}
if [[ -d "$frontend_dir/node_modules" ]]; then
  if [[ "$frontend_dir" != "$REPO_DIR/frontend" ]]; then
    diff -qr frontend/src "$frontend_dir/src"
    for file in package.json package-lock.json index.html tsconfig.json vite.config.ts; do
      cmp "frontend/$file" "$frontend_dir/$file"
    done
  fi
  (cd "$frontend_dir" && npm run typecheck && npm run build)
  if [[ "$frontend_dir" != "$REPO_DIR/frontend" ]]; then
    rsync -a --delete "$frontend_dir/dist/" frontend/dist/
  fi
else
  echo "frontend/node_modules is missing; run npm install before release verification" >&2
  exit 1
fi

grep -q 'HEALTH_PORT = 18088' runtime/family-proxy-gateway.py
grep -q 'HEALTH_BACKEND_PATH = "/api/health/gated"' runtime/family-proxy-gateway.py
grep -q 'port=18088' routeros/04-health-netwatch.rsc
[[ -s frontend/dist/index.html ]] || { echo "frontend build is missing" >&2; exit 1; }
echo "release checks passed: version=$(< VERSION)"
