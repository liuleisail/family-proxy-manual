#!/usr/bin/env python3
"""Validate local configuration and hash the initial UI password."""

import hashlib
import os
import secrets
import sys
from pathlib import Path


REQUIRED = {
    "FAMILY_LAN_CIDR", "FAMILY_LAN_PREFIX", "FAMILY_PROXY_IP", "FAMILY_ROUTER_IP",
    "FAMILY_DOCKER_ROOT", "ROUTER_HOST", "ROUTER_USER", "ROUTER_PASSWORD", "UI_USERNAME",
}


def parse(path: Path):
    pairs = []
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1)
            pairs.append((key, value))
            values[key] = value
    return pairs, values


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: prepare-config.py /etc/family-proxy-ui/router.env")
    path = Path(sys.argv[1])
    pairs, values = parse(path)
    setup_pending = values.get("SETUP_PENDING", "false").lower() == "true"
    required = set(REQUIRED)
    if setup_pending:
        # The browser wizard supplies RouterOS credentials and the final UI account.
        # Network identity and a temporary UI hash are still required to start safely.
        required -= {"ROUTER_HOST", "ROUTER_USER", "ROUTER_PASSWORD"}
    missing = sorted(name for name in required if not values.get(name))
    placeholders = sorted(name for name, value in values.items() if "replace_with" in value or value == "change_me")
    if missing or placeholders:
        message = []
        if missing:
            message.append("missing: " + ", ".join(missing))
        if placeholders:
            message.append("replace template values: " + ", ".join(placeholders))
        raise SystemExit("; ".join(message))
    if "UI_PASSWORD" in values:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", values["UI_PASSWORD"].encode(), salt, 210000).hex()
        pairs = [(key, value) for key, value in pairs if key != "UI_PASSWORD"]
        pairs.extend([("UI_PASSWORD_SALT", salt.hex()), ("UI_PASSWORD_HASH", digest)])
        temporary = path.with_suffix(".new")
        temporary.write_text("".join(f"{key}={value}\n" for key, value in pairs), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        print("UI password hashed locally")
    elif not values.get("UI_PASSWORD_SALT") or not values.get("UI_PASSWORD_HASH"):
        raise SystemExit("set UI_PASSWORD once, or provide UI_PASSWORD_SALT and UI_PASSWORD_HASH")


if __name__ == "__main__":
    main()
