#!/usr/bin/env python3
"""Transactionally synchronize only RouterOS family_cn_ipv4 entries."""

import argparse
import importlib.util
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

LIST_NAME = "family_cn_ipv4"
SOURCE = Path("/etc/family-proxy-ui/cn-ipv4.txt")
CONTROLLER = Path("/opt/family-proxy-ui/family-proxy-ui.py")
BACKUP_DIR = Path("/var/backups/family-proxy/routeros-cn")
STATUS = Path("/etc/family-proxy-ui/routeros-cn-sync-status.json")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def load_controller():
    spec = importlib.util.spec_from_file_location("family_proxy_controller", CONTROLLER)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {CONTROLLER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def desired_networks():
    networks = []
    for raw in SOURCE.read_text(encoding="ascii").splitlines():
        raw = raw.strip()
        if raw and not raw.startswith("#"):
            networks.append(ipaddress.ip_network(raw, strict=True))
    collapsed = {str(item) for item in ipaddress.collapse_addresses(networks)}
    if not 1000 <= len(collapsed) <= 10000:
        raise RuntimeError(f"CN IPv4 source count rejected: {len(collapsed)}")
    return collapsed


def current_entries(api):
    entries = {}
    for item in api.print("/ip/firewall/address-list"):
        if item.get("list") != LIST_NAME or item.get("dynamic") == "true":
            continue
        try:
            network = str(ipaddress.ip_network(item.get("address", ""), strict=False))
        except ValueError:
            continue
        entries.setdefault(network, []).append(item[".id"])
    return entries


def rollback(api, added_ids, removed):
    errors = []
    for item_id in reversed(added_ids):
        try:
            api.remove("/ip/firewall/address-list", item_id)
        except Exception as exc:
            errors.append(f"remove {item_id}: {exc}")
    for network in removed:
        try:
            api.add("/ip/firewall/address-list", list=LIST_NAME, address=network,
                    comment="family-cn-auto")
        except Exception as exc:
            errors.append(f"restore {network}: {exc}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="read-only comparison")
    args = parser.parse_args()
    wanted = desired_networks()
    controller = load_controller()
    with controller.RouterOS() as api:
        existing = current_entries(api)
        current = set(existing)
        if not 1000 <= len(current) <= 10000:
            raise RuntimeError(f"RouterOS current list count rejected: {len(current)}")
        additions = sorted(wanted - current)
        removals = sorted(current - wanted)
        change_ratio = (len(additions) + len(removals)) / max(len(current), len(wanted), 1)
        result = {
            "phase": "checked" if args.check else "syncing",
            "checked_at": now(), "current": len(current), "desired": len(wanted),
            "additions": len(additions), "removals": len(removals),
            "change_ratio": round(change_ratio, 6),
        }
        atomic_json(STATUS, result)
        if args.check or not additions and not removals:
            result["phase"] = "in_sync" if not additions and not removals else "check_only"
            atomic_json(STATUS, result)
            print(json.dumps(result, ensure_ascii=False))
            return
        if change_ratio > 0.20:
            raise RuntimeError(f"RouterOS CN list delta rejected: {change_ratio:.1%}")

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = BACKUP_DIR / f"family-cn-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        atomic_json(backup, {"list": LIST_NAME, "networks": sorted(current), "created_at": now()})
        added_ids = []
        removed = []
        try:
            for network in additions:
                before_ids = set(current_entries(api).get(network, []))
                api.add("/ip/firewall/address-list", list=LIST_NAME, address=network,
                        comment="family-cn-auto")
                new_ids = set(current_entries(api).get(network, [])) - before_ids
                if not new_ids:
                    raise RuntimeError(f"RouterOS did not create {network}")
                added_ids.extend(sorted(new_ids))
            for network in removals:
                for item_id in existing[network]:
                    api.remove("/ip/firewall/address-list", item_id)
                removed.append(network)
            actual = set(current_entries(api))
            if actual != wanted:
                raise RuntimeError(f"post-sync mismatch: actual={len(actual)} desired={len(wanted)}")
        except Exception as exc:
            errors = rollback(api, added_ids, removed)
            result.update({"phase": "rollback_failed" if errors else "rolled_back",
                           "error": str(exc), "rollback_errors": errors, "completed_at": now()})
            atomic_json(STATUS, result)
            raise RuntimeError(f"sync failed and rollback {'failed' if errors else 'completed'}: {exc}") from exc
        result.update({"phase": "updated", "backup": str(backup), "completed_at": now()})
        atomic_json(STATUS, result)
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        try:
            value = json.loads(STATUS.read_text(encoding="utf-8")) if STATUS.exists() else {}
            value.update({"phase": value.get("phase") if value.get("phase") in ("rolled_back", "rollback_failed") else "error",
                          "error": str(exc), "completed_at": now()})
            atomic_json(STATUS, value)
        except Exception:
            pass
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
