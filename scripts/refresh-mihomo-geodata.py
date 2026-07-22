#!/usr/bin/env python3
"""Validate and transactionally refresh official MetaCubeX geodata assets."""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

CONTAINER = "family-mihomo-fallback"
CONFIG = Path("/etc/family-proxy-ui/router.env")
STATUS = Path("/etc/family-proxy-ui/mihomo-geodata-status.json")
ASSETS = {
    "geosite.dat": 1_000_000,
    "geoip.dat": 5_000_000,
    "geoip.metadb": 2_000_000,
}
DATA_BASE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def command(args, timeout=180, check=True):
    environment = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment.pop(name, None)
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=environment)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or f"command failed: {args[0]}")
    return result


def settings():
    result = {}
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.strip().split("=", 1)
            result[key] = value
    return result


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_file(remote, output, proxy):
    common = ["curl", "--fail", "--silent", "--show-error", "--location", "--connect-timeout", "10"]
    direct = command([*common, "--noproxy", "*", "--max-time", "45", remote, "--output", str(output)],
                     timeout=60, check=False)
    if direct.returncode == 0:
        return "direct"
    output.unlink(missing_ok=True)
    if not proxy:
        raise RuntimeError((direct.stderr or direct.stdout).strip() or f"direct download failed: {remote}")
    command([*common, "--proxy", proxy, "--max-time", "300", remote, "--output", str(output)], timeout=330)
    return "local_proxy"


def download(workdir):
    digests = {}
    transports = {}
    proxy = settings().get("FAMILY_GEODATA_PROXY", "http://127.0.0.1:7890").strip()
    for name, minimum in ASSETS.items():
        target = workdir / name
        checksum = workdir / f"{name}.sha256sum"
        for remote, output in ((f"{DATA_BASE_URL}/{name}", target), (f"{DATA_BASE_URL}/{name}.sha256sum", checksum)):
            transport = download_file(remote, output, proxy)
            if transport == "local_proxy" or name not in transports:
                transports[name] = transport
        expected = checksum.read_text(encoding="ascii").split()[0].lower()
        actual = sha256(target)
        if len(expected) != 64 or actual != expected:
            raise RuntimeError(f"checksum mismatch: {name}")
        if target.stat().st_size < minimum:
            raise RuntimeError(f"asset too small: {name}")
        digests[name] = actual
    return digests, transports


def validate(workdir):
    container_dir = "/tmp/family-geodata-check"
    command(["docker", "exec", CONTAINER, "rm", "-rf", container_dir])
    command(["docker", "exec", CONTAINER, "mkdir", "-p", container_dir])
    for name in ASSETS:
        command(["docker", "cp", str(workdir / name), f"{CONTAINER}:{container_dir}/{name}"])
    for mode, filename in (("true", "config-dat.yaml"), ("false", "config-metadb.yaml")):
        config = workdir / filename
        config.write_text(
            f"geodata-mode: {mode}\nlog-level: silent\nrules:\n  - GEOSITE,CN,DIRECT\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n",
            encoding="ascii",
        )
        command(["docker", "cp", str(config), f"{CONTAINER}:{container_dir}/{filename}"])
        command(["docker", "exec", CONTAINER, "/mihomo", "-t", "-d", container_dir,
                 "-f", f"{container_dir}/{filename}"], timeout=90)
    command(["docker", "exec", CONTAINER, "rm", "-rf", container_dir])


def wait_healthy(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        running = command(["docker", "inspect", CONTAINER, "--format", "{{.State.Running}}"], check=False)
        if running.returncode == 0 and running.stdout.strip() == "true":
            for port in (9091, 9090):
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                    connection.close()
                    command(["docker", "exec", CONTAINER, "/mihomo", "-t", "-d", "/root/.config/mihomo",
                             "-f", "/root/.config/mihomo/config.yaml"], timeout=45)
                    return
                except (OSError, RuntimeError):
                    continue
        time.sleep(2)
    raise RuntimeError("Mihomo did not become healthy after geodata update")


def copy_from_container(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in ASSETS:
        command(["docker", "cp", f"{CONTAINER}:/root/.config/mihomo/{name}", str(destination / name)])


def copy_to_container(source):
    for name in ASSETS:
        command(["docker", "cp", str(source / name), f"{CONTAINER}:/root/.config/mihomo/{name}"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="download and validate without applying")
    args = parser.parse_args()
    value = {"phase": "checking", "mode": "check" if args.check else "update", "started_at": now()}
    atomic_json(STATUS, value)
    with tempfile.TemporaryDirectory(prefix="family-geodata-") as temporary:
        workdir = Path(temporary)
        digests, transports = download(workdir)
        validate(workdir)
        current = {}
        for name in ASSETS:
            result = command(["docker", "exec", CONTAINER, "sha256sum", f"/root/.config/mihomo/{name}"], check=False)
            current[name] = result.stdout.split()[0] if result.returncode == 0 and result.stdout.split() else ""
        changed = [name for name in ASSETS if current.get(name) != digests[name]]
        if args.check or not changed:
            value.update({"phase": "update_available" if changed else "up_to_date", "changed": changed,
                          "digests": digests, "transports": transports, "completed_at": now()})
            atomic_json(STATUS, value)
            print(json.dumps(value, ensure_ascii=False))
            return

        root = Path(settings().get("FAMILY_DOCKER_ROOT", "/var/lib/family-proxy/docker"))
        backup_root = root / "family-mihomo-fallback/geodata-backups"
        backup = backup_root / datetime.now().strftime("%Y%m%d-%H%M%S")
        copy_from_container(backup)
        try:
            copy_to_container(workdir)
            command(["docker", "restart", CONTAINER], timeout=90)
            wait_healthy()
        except Exception as exc:
            copy_to_container(backup)
            command(["docker", "restart", CONTAINER], timeout=90)
            wait_healthy()
            value.update({"phase": "rolled_back", "error": str(exc), "backup": str(backup), "completed_at": now()})
            atomic_json(STATUS, value)
            raise RuntimeError(f"geodata update failed; old files restored: {exc}") from exc
        backups = sorted((item for item in backup_root.iterdir() if item.is_dir()), reverse=True)
        for old in backups[3:]:
            shutil.rmtree(old)
        value.update({"phase": "updated", "changed": changed, "digests": digests, "transports": transports,
                      "backup": str(backup), "completed_at": now()})
        atomic_json(STATUS, value)
        print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        current = {}
        try:
            current = json.loads(STATUS.read_text(encoding="utf-8"))
        except Exception:
            pass
        if current.get("phase") != "rolled_back":
            current.update({"phase": "error", "error": str(exc), "completed_at": now()})
            atomic_json(STATUS, current)
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
