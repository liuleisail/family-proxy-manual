#!/usr/bin/env python3
"""Render repository runtime templates with values from a local env file."""

import os
import shutil
import sys
from pathlib import Path


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: render-runtime.py ENV TEMPLATE_DIR OUTPUT_DIR")
    env_path, template_dir, output_dir = map(Path, sys.argv[1:])
    values = read_env(env_path)
    required = {
        "FAMILY_LAN_CIDR", "FAMILY_LAN_PREFIX", "FAMILY_PROXY_IP",
        "FAMILY_ROUTER_IP", "FAMILY_DOCKER_ROOT",
    }
    missing = sorted(key for key in required if not values.get(key))
    if missing:
        raise SystemExit("missing required configuration: " + ", ".join(missing))
    if not values["FAMILY_LAN_PREFIX"].endswith("."):
        raise SystemExit("FAMILY_LAN_PREFIX must end with a dot")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    replacements = {f"__{key}__": value for key, value in values.items()}
    for source in template_dir.glob("*.py"):
        content = source.read_text(encoding="utf-8")
        for marker, value in replacements.items():
            content = content.replace(marker, value)
        unresolved = [token for token in content.split() if token.startswith("__FAMILY_")]
        if unresolved:
            raise SystemExit(f"unresolved network placeholder in {source.name}")
        target = output_dir / source.name
        target.write_text(content, encoding="utf-8")
        os.chmod(target, 0o755)


if __name__ == "__main__":
    main()
