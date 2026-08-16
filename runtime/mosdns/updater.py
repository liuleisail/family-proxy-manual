#!/usr/bin/env python3
"""Restricted Docker image updater for the family MosDNS service."""

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

IMAGE = "jasonxtt/mosdns-t:latest"
CONTAINER = "family-mosdns-t"
CRANE = "/opt/family-mosdns-updater/crane"
REGISTRY_PROXY = "http://127.0.0.1:7890"
PROJECT_TAGS_API = "https://api.github.com/repos/jasonxtt/mosdns/tags"
PROJECT_TAGS_URL = "https://github.com/jasonxtt/mosdns/tags"
PROJECT_RELEASE_SOURCE = "MosDNS-T 第三方项目 Tags"
PROJECT_RELEASE_NOTES = "这是 MosDNS-T 第三方整合项目；版本以其 Tags 和 Docker 镜像 digest 为准，不与官方 MosDNS 5.x 版本比较。"
PROJECT_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
COMPOSE_DIR = Path(os.environ.get("FAMILY_MOSDNS_COMPOSE_DIR", "/var/lib/family-proxy/docker/family-mosdns-t"))
STATE_DIR = Path("/etc/family-proxy-ui")
CONFIG_PATH = STATE_DIR / "mosdns-updater.json"
STATUS_PATH = STATE_DIR / "mosdns-updater-status.json"
RULE_STATUS_PATH = STATE_DIR / "mosdns-rule-updater-status.json"
VERIFY_STATUS_PATH = STATE_DIR / "mosdns-verify-status.json"
LOCK_PATH = STATE_DIR / "mosdns-updater.lock"
SECRET_PATH = STATE_DIR / "gateway.secret"
DEFAULT_CONFIG = {
    "auto_enabled": True,
    "interval_hours": 168,
    "last_auto_check": 0,
    "rule_auto_enabled": True,
    "rule_interval_hours": 24,
    "last_rule_check": 0,
    "rule_failure_count": 0,
    "next_rule_retry": 0,
    "adblock_mode": "off",
    "adblock_auto_enabled": True,
    "adblock_interval_hours": 24,
    "last_adblock_check": 0,
    "adblock_failure_count": 0,
    "next_adblock_retry": 0,
}
CORE_API = os.environ.get("FAMILY_MOSDNS_CORE_API", "http://172.31.53.2:9099").rstrip("/")
DNS_SERVER = os.environ.get("FAMILY_MOSDNS_DNS_SERVER", "127.0.0.1")
DEFAULT_SOCKS5 = os.environ.get("FAMILY_MOSDNS_SOCKS5", "172.31.53.1:7890")
LAN_CIDR = os.environ.get("FAMILY_MOSDNS_LAN_CIDR", "192.168.2.0/24")
IMAGE_PULL_TIMEOUT = max(300, int(os.environ.get("FAMILY_MOSDNS_IMAGE_PULL_TIMEOUT", "1800")))
DOCKER_PULL_TIMEOUT = max(120, int(os.environ.get("FAMILY_MOSDNS_DOCKER_PULL_TIMEOUT", "600")))
IMAGE_PULL_ATTEMPTS = max(1, int(os.environ.get("FAMILY_MOSDNS_IMAGE_PULL_ATTEMPTS", "2")))
IMAGE_MIRROR = os.environ.get("FAMILY_MOSDNS_IMAGE_MIRROR", "docker.1ms.run").strip().rstrip("/")
MIRROR_IMAGE = f"{IMAGE_MIRROR}/{IMAGE}"
ADBLOCK_RULES_HOST = os.environ.get("FAMILY_MOSDNS_RULES_HOST", DEFAULT_SOCKS5.rsplit(":", 1)[0])
ADBLOCK_RULES_PORT = int(os.environ.get("FAMILY_MOSDNS_RULES_PORT", "18103"))
RULE_SOURCES = {
    "geosite_cn": {"label": "国内域名", "minimum": 80000, "minimum_ratio": 0.7},
    "geosite_no_cn": {"label": "国外域名", "minimum": 15000, "minimum_ratio": 0.7},
    "geoip_cn": {"label": "国内 IP", "minimum": 4000, "minimum_ratio": 0.25},
}
CACHE_TAGS = (
    "cache_all", "cache_all_noleak", "cache_cn", "cache_google",
    "cache_google_node", "cache_node", "cache_cnmihomo",
)
ROUTE_PROBES = {
    "domestic": (
        "www.baidu.com", "www.taobao.com", "api.m.jd.com",
        "www.douyin.com", "www.qq.com", "apple.com",
    ),
    "foreign": (
        "www.google.com", "www.youtube.com", "api.telegram.org",
        "chatgpt.com", "github.com", "ssl.gstatic.com",
    ),
}
ROUTE_TAGS = {
    "domestic": ("白名单", "记忆直连", "订阅直连"),
    "foreign": ("灰名单", "记忆代理", "订阅代理", "!CN fakeip filter"),
}

ADBLOCK_STATUS_PATH = STATE_DIR / "mosdns-adblock-status.json"
ADBLOCK_PENDING_ALLOWLIST_PATH = STATE_DIR / "mosdns-adblock-allow.pending"
ADBLOCK_ALLOWLIST_PATH = COMPOSE_DIR / "web/family-adblock-allow.txt"
ADBLOCK_SOURCES = {
    "cn_ads": {
        "label": "国内精简广告",
        "name": "family-cn-ads-lite",
        "url": "https://adrules.top/adblock_lite.txt",
        "project": "https://github.com/Cats-Team/AdRules",
        "file": COMPOSE_DIR / "web/family-cn-ads-lite.rules",
        "local_url": f"http://{ADBLOCK_RULES_HOST}:{ADBLOCK_RULES_PORT}/family-cn-ads-lite.rules",
        "minimum": 5000,
        "maximum": 50000,
    },
    "adult": {
        "label": "成人内容",
        "name": "family-adult-filter",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
        "project": "https://github.com/hagezi/dns-blocklists",
        "file": COMPOSE_DIR / "web/family-adult-filter.rules",
        "local_url": f"http://{ADBLOCK_RULES_HOST}:{ADBLOCK_RULES_PORT}/family-adult-filter.rules",
        "minimum": 50000,
        "maximum": 200000,
    },
}
DEFAULT_ADBLOCK_ALLOWLIST = (
    "360buyimg.com", "alipay.com", "alicdn.com", "apple.com", "bilibili.com",
    "byteimg.com", "bytedance.com", "chatgpt.com", "douyin.com", "douyinvod.com",
    "github.com", "google.com", "gstatic.com", "gtimg.cn", "home-assistant.io",
    "icloud.com", "jd.com", "jdcloud.com", "jdpay.com", "jdwl.com", "mi.com",
    "mzstatic.com", "openai.com", "pddpic.com", "pinduoduo.com", "qpic.cn",
    "qq.com", "snssdk.com", "taobao.com", "tbcdn.cn", "telegram.org",
    "tmall.com", "wechat.com", "xiaomi.com", "yangkeduo.com", "youtube.com",
)
ABP_DOMAIN_RULE = re.compile(r"^\|\|([A-Za-z0-9._-]+)\^$")

worker_lock = threading.Lock()
worker_state_lock = threading.Lock()
worker_active = False


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def load_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else dict(default)
    except (OSError, ValueError):
        return dict(default)


def config():
    value = load_json(CONFIG_PATH, DEFAULT_CONFIG)
    adblock_mode = str(value.get("adblock_mode", "off"))
    if adblock_mode not in ("off", "observe", "block"):
        adblock_mode = "off"
    return {
        "auto_enabled": bool(value.get("auto_enabled", True)),
        "interval_hours": max(24, min(720, int(value.get("interval_hours", 168)))),
        "last_auto_check": max(0, int(value.get("last_auto_check", 0))),
        "rule_auto_enabled": bool(value.get("rule_auto_enabled", True)),
        "rule_interval_hours": max(12, min(168, int(value.get("rule_interval_hours", 24)))),
        "last_rule_check": max(0, int(value.get("last_rule_check", 0))),
        "rule_failure_count": max(0, min(3, int(value.get("rule_failure_count", 0)))),
        "next_rule_retry": max(0, int(value.get("next_rule_retry", 0))),
        "adblock_mode": adblock_mode,
        "adblock_auto_enabled": bool(value.get("adblock_auto_enabled", True)),
        "adblock_interval_hours": max(24, min(168, int(value.get("adblock_interval_hours", 24)))),
        "last_adblock_check": max(0, int(value.get("last_adblock_check", 0))),
        "adblock_failure_count": max(0, min(3, int(value.get("adblock_failure_count", 0)))),
        "next_adblock_retry": max(0, int(value.get("next_adblock_retry", 0))),
    }


def save_config(value):
    atomic_json(CONFIG_PATH, value)


def normalize_status_payload(value):
    result = dict(value) if isinstance(value, dict) else {}
    if result.get("release_source") == PROJECT_RELEASE_SOURCE:
        return result
    result["release_source"] = PROJECT_RELEASE_SOURCE
    result["release_url"] = PROJECT_TAGS_URL
    result["release_version"] = ""
    result["release_notes"] = PROJECT_RELEASE_NOTES
    result["latest_published"] = ""
    result["latest_version"] = str(result.get("latest_image") or "未知")
    return result


def status():
    return normalize_status_payload(load_json(STATUS_PATH, {"phase": "idle", "message": "尚未检查软件更新"}))


def rule_status():
    return load_json(RULE_STATUS_PATH, {"phase": "idle", "message": "尚未执行规则更新"})


def verify_status():
    return load_json(VERIFY_STATUS_PATH, {"phase": "idle", "mode": "quick", "message": "尚未执行 DNS 检查"})


def adblock_status_file():
    return load_json(ADBLOCK_STATUS_PATH, {"phase": "idle", "message": "尚未准备精简过滤规则"})


def set_status(phase, message, **extra):
    value = status()
    updated_at = now_iso()
    value.update({"phase": phase, "message": message, "updated_at": updated_at, **extra})
    if phase in ("rolled_back", "error"):
        value["last_failure"] = {
            "phase": phase,
            "message": message,
            "updated_at": updated_at,
            "backup": value.get("backup", ""),
        }
    elif phase in ("updated", "up_to_date"):
        value.pop("last_failure", None)
    atomic_json(STATUS_PATH, value)
    return value


def set_rule_status(phase, message, **extra):
    value = rule_status()
    value.update({"phase": phase, "message": message, "updated_at": now_iso(), **extra})
    atomic_json(RULE_STATUS_PATH, value)
    return value


def set_verify_status(phase, message, **extra):
    value = verify_status()
    value.update({"phase": phase, "message": message, "updated_at": now_iso(), **extra})
    atomic_json(VERIFY_STATUS_PATH, value)
    return value


def set_adblock_status(phase, message, **extra):
    value = adblock_status_file()
    value.update({"phase": phase, "message": message, "updated_at": now_iso(), **extra})
    atomic_json(ADBLOCK_STATUS_PATH, value)
    return value


def core_request(path, method="GET", timeout=15):
    request = urllib.request.Request(CORE_API + path, method=method)
    if method != "GET":
        request.add_header("Content-Length", "0")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        return json.loads(body) if body else {}


def core_json_request(path, payload, timeout=30, method="POST"):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(CORE_API + path, data=body, method=method)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = response.read()
            if not value:
                return {}
            text = value.decode("utf-8", "replace").strip()
            try:
                return json.loads(text)
            except ValueError:
                return {"response": text}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("error", detail)
        except ValueError:
            pass
        raise RuntimeError(str(detail).strip() or f"MosDNS API 返回 {exc.code}") from exc


def core_action(path, method="GET", timeout=15):
    request = urllib.request.Request(CORE_API + path, method=method)
    if method != "GET":
        request.add_header("Content-Length", "0")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def command(args, timeout=180, check=True, env=None):
    result = subprocess.run(args, cwd=COMPOSE_DIR, text=True, capture_output=True, timeout=timeout, env=env)
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "命令执行失败").strip().splitlines()[-1]
        raise RuntimeError(detail)
    return result.stdout.strip()


def running_image_id():
    return command(["docker", "inspect", CONTAINER, "--format", "{{.Image}}"], timeout=10)


def core_version():
    try:
        with urllib.request.urlopen(CORE_API + "/api/v1/system/health", timeout=3) as response:
            return json.load(response).get("version", "未知")
    except (OSError, ValueError):
        return "暂不可用"


def crane_command(args, timeout=180):
    environment = os.environ.copy()
    environment.update({
        "HTTP_PROXY": REGISTRY_PROXY,
        "HTTPS_PROXY": REGISTRY_PROXY,
        "NO_PROXY": f"127.0.0.1,localhost,{LAN_CIDR},172.31.53.0/24",
    })
    return command([CRANE, *args], timeout=timeout, env=environment)


def remote_image_id():
    manifest = json.loads(crane_command(["manifest", IMAGE, "--platform=linux/amd64"], timeout=60))
    digest = manifest.get("config", {}).get("digest")
    if not digest:
        raise RuntimeError("MosDNS-T 第三方镜像清单缺少配置标识")
    return digest


def latest_project_tag(tags):
    candidates = []
    for item in tags if isinstance(tags, list) else []:
        name = str(item.get("name") or "").strip() if isinstance(item, dict) else ""
        match = PROJECT_TAG_RE.fullmatch(name)
        if match:
            candidates.append((tuple(int(value) for value in match.groups()), name))
    return max(candidates)[1] if candidates else "未知"


def third_party_release():
    """Read MosDNS-T tags; never compare them with official MosDNS versions."""
    fallback = {
        "release_source": PROJECT_RELEASE_SOURCE,
        "release_url": PROJECT_TAGS_URL,
        "release_notes": PROJECT_RELEASE_NOTES,
        "release_version": "未知",
        "latest_published": "",
    }
    request = urllib.request.Request(PROJECT_TAGS_API, headers={"User-Agent": "family-proxy-mosdns-updater"})
    openers = [
        urllib.request.build_opener(),
        urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": REGISTRY_PROXY, "https": REGISTRY_PROXY})
        ),
    ]
    for opener in openers:
        try:
            with opener.open(request, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            latest = latest_project_tag(payload)
            if latest == "未知":
                return fallback
            fallback["release_version"] = latest
            return fallback
        except (OSError, ValueError, urllib.error.URLError):
            continue
    return fallback


def download_latest_image():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / ".mosdns-image-download.tar"
    failures = []

    # 1. Prefer the Docker daemon pull: it uses the daemon registry mirrors,
    # which are reachable on networks where Docker Hub's CloudFront CDN is not.
    for attempt in range(1, IMAGE_PULL_ATTEMPTS + 1):
        try:
            command(["docker", "pull", "--platform=linux/amd64", IMAGE], timeout=DOCKER_PULL_TIMEOUT)
            return command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=10)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            failures.append(f"Docker daemon 第 {attempt} 次：{exc}")
            if attempt < IMAGE_PULL_ATTEMPTS:
                time.sleep(8)

    # 2. Explicit mirror fallback: pull from the configured domestic mirror
    # directly (reachable without the airport proxy) and retag to the compose
    # name, so the daemon mirror config failing does not strand the update.
    for attempt in range(1, IMAGE_PULL_ATTEMPTS + 1):
        try:
            command(["docker", "pull", "--platform=linux/amd64", MIRROR_IMAGE], timeout=DOCKER_PULL_TIMEOUT)
            command(["docker", "tag", MIRROR_IMAGE, IMAGE], timeout=15)
            return command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=10)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            failures.append(f"镜像站 {IMAGE_MIRROR} 第 {attempt} 次：{exc}")
            if attempt < IMAGE_PULL_ATTEMPTS:
                time.sleep(8)

    # 3. crane via the local proxy as the last fallback.
    for attempt in range(1, IMAGE_PULL_ATTEMPTS + 1):
        try:
            archive.unlink(missing_ok=True)
            crane_command(
                ["pull", IMAGE, str(archive), "--platform=linux/amd64", "--format=legacy"],
                timeout=IMAGE_PULL_TIMEOUT,
            )
            command(["docker", "load", "--input", str(archive)], timeout=300)
            return command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=10)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            failures.append(f"crane 第 {attempt} 次：{exc}")
            if attempt < IMAGE_PULL_ATTEMPTS:
                time.sleep(8)
        finally:
            archive.unlink(missing_ok=True)
    raise RuntimeError(
        f"MosDNS-T 镜像拉取失败（daemon、镜像站 {IMAGE_MIRROR}、crane 各 {IMAGE_PULL_ATTEMPTS} 次）：{failures[-1]}"
    )


class ImagePreflightError(RuntimeError):
    """New image failed an isolated pre-check; the live container was not touched."""


PREVIEW_CONTAINER = "family-mosdns-upgrade-preview"
PREVIEW_NETWORK = "family-mosdns-net"
PREVIEW_IP_CANDIDATES = ("172.31.53.250", "172.31.53.251", "172.31.53.252")
PREVIEW_API_PORT = 9099


def verify_new_image(new_image):
    """Start the new image against a copy of the live config in an isolated
    container and require a healthy API before the real recreate. This catches
    config-schema or startup incompatibilities without touching the live
    container (no DNS interruption on failure)."""
    test_dir = COMPOSE_DIR / "preview-config"
    preview_ip = None
    started = False
    try:
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)
        shutil.copytree(COMPOSE_DIR / "data", test_dir)
        command(["docker", "rm", "-f", PREVIEW_CONTAINER], timeout=15, check=False)
        for candidate in PREVIEW_IP_CANDIDATES:
            try:
                command(
                    [
                        "docker", "run", "-d", "--name", PREVIEW_CONTAINER,
                        "--network", PREVIEW_NETWORK, "--ip", candidate,
                        "-e", "MOSDNS_AUTO_INIT=false",
                        "-v", f"{test_dir}:/cus/mosdns",
                        new_image,
                    ],
                    timeout=60,
                )
                preview_ip = candidate
                started = True
                break
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                command(["docker", "rm", "-f", PREVIEW_CONTAINER], timeout=15, check=False)
        if not started:
            raise ImagePreflightError("无法在隔离网络中启动预检容器")
        deadline = time.time() + 90
        last_error = "尚未就绪"
        while time.time() < deadline:
            time.sleep(3)
            try:
                with urllib.request.urlopen(
                    f"http://{preview_ip}:{PREVIEW_API_PORT}/api/v1/system/health", timeout=3
                ) as response:
                    data = json.load(response)
                    if data.get("ready"):
                        return
                    last_error = f"API 未就绪：{data.get('version') or '未知'}"
            except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
                last_error = str(exc)
        raise ImagePreflightError(f"新镜像在隔离容器中未通过健康检查（{last_error}）")
    finally:
        if started:
            command(["docker", "rm", "-f", PREVIEW_CONTAINER], timeout=15, check=False)
        shutil.rmtree(test_dir, ignore_errors=True)


def backup_config():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"software-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    candidates = [
        "compose.yml", "compose.override.yml", "nginx/default.conf", "web/index.html", "auth",
        "data/config_custom.yaml", "data/sub_config", "data/rule", "data/srs", "data/webinfo",
    ]
    with tarfile.open(target, "w:gz") as archive:
        for relative in candidates:
            path = COMPOSE_DIR / relative
            if path.exists():
                archive.add(path, arcname=relative, recursive=True)
    return str(target)


def dns_probe(domain, dns_server):
    failure = "无响应"
    for extra in ([], ["+tcp"]):
        try:
            answer = command(
                ["dig", "+tries=2", "+time=3", "+short", *extra, f"@{dns_server}", domain, "A"],
                timeout=12,
            )
            if answer:
                return answer
            failure = "没有返回 IPv4 地址"
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            failure = str(exc)
    raise RuntimeError(f"{domain} DNS 验证失败：{failure}")


def wait_healthy(timeout=180):
    deadline = time.time() + timeout
    last_error = "MosDNS 尚未就绪"
    while time.time() < deadline:
        try:
            if command(["docker", "inspect", CONTAINER, "--format", "{{.State.Running}}"], timeout=5) != "true":
                raise RuntimeError("容器没有运行")
            with urllib.request.urlopen(CORE_API + "/api/v1/system/health", timeout=3) as response:
                if not json.load(response).get("ready"):
                    raise RuntimeError("API 尚未就绪")
            for domain in ("www.baidu.com", "www.google.com"):
                dns_probe(domain, DNS_SERVER)
            return
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc)
            time.sleep(2)
    raise RuntimeError(last_error)


def current_rule_sources():
    result = []
    for tag, metadata in RULE_SOURCES.items():
        values = core_request(f"/plugins/{tag}/config")
        item = (values[0] if isinstance(values, list) and values else values) or {}
        result.append({
            "tag": tag,
            "label": metadata["label"],
            "rule_count": int(item.get("rule_count", 0)),
            "last_updated": item.get("last_updated"),
            "source": item.get("url", ""),
        })
    return result


def direct_download(url, limit=12 * 1024 * 1024):
    environment = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment.pop(name, None)
    result = subprocess.run(
        [
            "curl", "--fail", "--silent", "--show-error", "--location", "--noproxy", "*",
            "--connect-timeout", "10", "--max-time", "60", "--speed-time", "20",
            "--speed-limit", "1024", "--max-filesize", str(limit),
            "--user-agent", "family-mosdns-adblock/1.0", url,
        ],
        capture_output=True,
        timeout=70,
        env=environment,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip() or "直连下载失败"
        raise RuntimeError(detail)
    content = result.stdout
    if len(content) > limit:
        raise RuntimeError("规则文件超过安全大小限制")
    return content.decode("utf-8", "replace")


def direct_download_with_retry(url, limit=12 * 1024 * 1024, attempts=3):
    """Retry transient source failures without ever using the proxy path."""
    failure = None
    for attempt in range(attempts):
        try:
            return direct_download(url, limit=limit)
        except RuntimeError as exc:
            failure = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"直连下载连续 {attempts} 次失败：{failure}")


def update_retry_state(kind, succeeded):
    """Persist bounded retry state so a transient failure never defers updates for a full day."""
    value = config()
    failure_key = f"{kind}_failure_count"
    retry_key = f"next_{kind}_retry"
    if succeeded:
        value[failure_key] = 0
        value[retry_key] = 0
    else:
        failures = min(3, int(value.get(failure_key, 0)) + 1)
        # 15 minutes, 1 hour, then 4 hours; normal interval resumes after success.
        delay = (15 * 60, 60 * 60, 4 * 60 * 60)[failures - 1]
        value[failure_key] = failures
        value[retry_key] = int(time.time() + delay)
    save_config(value)
    return value


def update_due(value, kind, now):
    retry_at = int(value.get(f"next_{kind}_retry", 0))
    if retry_at:
        return now >= retry_at
    return now - int(value[f"last_{kind}_check"]) >= int(value[f"{kind}_interval_hours"]) * 3600


def normalize_domain(value):
    domain = str(value).strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "." not in domain:
        raise ValueError(f"无效域名：{value}")
    try:
        ipaddress.ip_address(domain)
        raise ValueError(f"白名单不能填写 IP：{value}")
    except ValueError as exc:
        if "不能填写 IP" in str(exc):
            raise
    if not re.fullmatch(r"[a-z0-9._-]+", domain) or any(not label or len(label) > 63 for label in domain.split(".")):
        raise ValueError(f"无效域名：{value}")
    return domain


def parse_allowlist(value):
    lines = value.splitlines() if isinstance(value, str) else value
    domains = set()
    for raw in lines:
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        domains.add(normalize_domain(text))
    if len(domains) > 300:
        raise ValueError("放行名单最多 300 个域名")
    return sorted(domains)


def load_adblock_allowlist():
    if not ADBLOCK_ALLOWLIST_PATH.exists():
        ADBLOCK_ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        ADBLOCK_ALLOWLIST_PATH.write_text("\n".join(DEFAULT_ADBLOCK_ALLOWLIST) + "\n", encoding="utf-8")
    return parse_allowlist(ADBLOCK_ALLOWLIST_PATH.read_text(encoding="utf-8"))


def rule_conflicts_with_allowlist(domain, allowlist):
    return any(
        domain == allowed
        or domain.endswith("." + allowed)
        or allowed.endswith("." + domain)
        for allowed in allowlist
    )


def compile_adblock_source(source_key, content, allowlist):
    domains = set()
    for raw in content.splitlines():
        match = ABP_DOMAIN_RULE.fullmatch(raw.strip())
        if not match:
            continue
        try:
            domain = normalize_domain(match.group(1))
        except ValueError:
            continue
        if not rule_conflicts_with_allowlist(domain, allowlist):
            domains.add(domain)
    metadata = ADBLOCK_SOURCES[source_key]
    if not metadata["minimum"] <= len(domains) <= metadata["maximum"]:
        raise RuntimeError(
            f"{metadata['label']}规则数量异常：{len(domains)}，允许范围 "
            f"{metadata['minimum']}–{metadata['maximum']}"
        )
    previous = read_compiled_domains(metadata["file"])
    if previous and not int(len(previous) * 0.7) <= len(domains) <= int(len(previous) * 1.4):
        raise RuntimeError(f"{metadata['label']}相比上一版变化过大：{len(previous)} -> {len(domains)}")
    body = "! Family MosDNS compiled domain list\n" + "\n".join(f"||{domain}^" for domain in sorted(domains)) + "\n"
    return domains, body


def read_compiled_domains(path):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    result = set()
    for line in lines:
        match = ABP_DOMAIN_RULE.fullmatch(line.strip())
        if match:
            result.add(match.group(1).lower())
    return result


def atomic_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


def family_adguard_rules():
    rules = core_request("/plugins/adguard/rules")
    return {
        source_key: next((item for item in rules if item.get("name") == metadata["name"]), None)
        for source_key, metadata in ADBLOCK_SOURCES.items()
    }


def ensure_family_adguard_rules(enabled):
    existing = family_adguard_rules()
    result = {}
    for source_key, metadata in ADBLOCK_SOURCES.items():
        current = existing.get(source_key)
        payload = {
            "name": metadata["name"],
            "url": metadata["local_url"],
            "enabled": bool(enabled),
            "auto_update": False,
            "update_interval_hours": 24,
        }
        if current:
            payload = {**current, **payload}
            result[source_key] = core_json_request(
                f"/plugins/adguard/rules/{current['id']}", payload, method="PUT"
            )
        else:
            result[source_key] = core_json_request("/plugins/adguard/rules", payload)
    if enabled:
        for item in result.values():
            core_action(f"/plugins/adguard/update/{item['id']}", method="POST")
    return result


def wait_family_adguard_rules(expected_counts, enabled, timeout=90):
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        last = family_adguard_rules()
        ready = True
        for source_key, expected in expected_counts.items():
            item = last.get(source_key) or {}
            if bool(item.get("enabled")) != bool(enabled):
                ready = False
            if enabled and int(item.get("rule_count", 0)) != expected:
                ready = False
        if ready:
            return last
        time.sleep(1)
    raise RuntimeError(f"MosDNS 附加规则载入超时：{last}")


def set_adblock_switch(enabled):
    core_json_request("/plugins/switch7/post", {"value": "A" if enabled else "B"})


def backup_adblock():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"adblock-change-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        for relative in ("web/family-cn-ads-lite.rules", "web/family-adult-filter.rules", "web/family-adblock-allow.txt", "data/adguard", "data/rule/switch7.txt"):
            path = COMPOSE_DIR / relative
            if path.exists():
                archive.add(path, arcname=relative, recursive=True)
    return target


def restore_adblock(backup):
    for metadata in ADBLOCK_SOURCES.values():
        metadata["file"].unlink(missing_ok=True)
    with tarfile.open(backup, "r:gz") as archive:
        archive.extractall(COMPOSE_DIR)
    command(["docker", "restart", CONTAINER], timeout=45)
    wait_healthy(60)


def adblock_probe():
    candidates = read_compiled_domains(ADBLOCK_SOURCES["cn_ads"]["file"])
    if not candidates:
        raise RuntimeError("国内广告规则为空，无法验证拦截")
    domain = "doubleclick.net" if "doubleclick.net" in candidates else sorted(candidates)[0]
    baseline = command(["dig", "+tries=1", "+time=3", "+comments", "@223.5.5.5", domain, "A"], timeout=6)
    if "status: NOERROR" not in baseline:
        raise RuntimeError("广告探针在公共 DNS 中没有返回正常基线")
    output = command(["dig", "+tries=1", "+time=3", "+comments", f"@{DNS_SERVER}", domain, "A"], timeout=6)
    if "status: NXDOMAIN" not in output:
        raise RuntimeError("广告域名没有返回 NXDOMAIN")


def apply_adblock_mode(mode, validate=True):
    if mode not in ("off", "observe", "block"):
        raise ValueError("过滤模式无效")
    expected = {key: len(read_compiled_domains(item["file"])) for key, item in ADBLOCK_SOURCES.items()}
    if mode != "off" and any(not count for count in expected.values()):
        raise RuntimeError("请先更新并校验精简过滤规则")
    # Switching blocking off first prevents partially loaded sources from affecting clients.
    set_adblock_switch(False)
    rules_enabled = mode == "block"
    ensure_family_adguard_rules(rules_enabled)
    wait_family_adguard_rules(expected, rules_enabled)
    if rules_enabled:
        # adguard_rule publishes first; domain_mapper rebuilds its aggregate asynchronously.
        time.sleep(6)
    if validate and mode != "off":
        validate_route_matrix()
    if mode == "block":
        set_adblock_switch(True)
        if validate:
            adblock_probe()
            validate_route_matrix()
    value = config()
    value["adblock_mode"] = mode
    save_config(value)
    return mode


def do_adblock_update():
    with worker_lock:
        backup = None
        try:
            value = config()
            value["last_adblock_check"] = int(time.time())
            save_config(value)
            backup = backup_adblock()
            allowlist = (
                parse_allowlist(ADBLOCK_PENDING_ALLOWLIST_PATH.read_text(encoding="utf-8"))
                if ADBLOCK_PENDING_ALLOWLIST_PATH.exists()
                else load_adblock_allowlist()
            )
            set_adblock_status("updating", "正在使用本地网络下载并校验精简过滤规则", backup=str(backup))
            compiled = {}
            sources = []
            for source_key, metadata in ADBLOCK_SOURCES.items():
                content = direct_download_with_retry(metadata["url"])
                domains, body = compile_adblock_source(source_key, content, allowlist)
                compiled[source_key] = (domains, body)
                sources.append({
                    "key": source_key,
                    "label": metadata["label"],
                    "source": metadata["url"],
                    "project": metadata["project"],
                    "rule_count": len(domains),
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                })
            for source_key, (_, body) in compiled.items():
                atomic_text(ADBLOCK_SOURCES[source_key]["file"], body)
            atomic_text(ADBLOCK_ALLOWLIST_PATH, "\n".join(allowlist) + "\n")
            mode = config()["adblock_mode"]
            apply_adblock_mode(mode, validate=mode != "off")
            ADBLOCK_PENDING_ALLOWLIST_PATH.unlink(missing_ok=True)
            update_retry_state("adblock", succeeded=True)
            set_adblock_status(
                "updated",
                "精简过滤规则已更新并通过数量、白名单和分流验证",
                mode=mode,
                sources=sources,
                allowlist_count=len(allowlist),
                backup=str(backup),
                completed_at=now_iso(),
            )
        except Exception as exc:
            failure = str(exc)
            retry = update_retry_state("adblock", succeeded=False)
            retry_at = datetime.fromtimestamp(retry["next_adblock_retry"], timezone.utc).isoformat(timespec="seconds")
            if backup:
                try:
                    set_adblock_status("rolling_back", f"过滤规则校验失败，正在恢复：{failure}", backup=str(backup))
                    restore_adblock(backup)
                    set_adblock_status("rolled_back", f"过滤规则更新失败，已恢复旧配置；将于 {retry_at} 自动重试：{failure}", backup=str(backup), completed_at=now_iso())
                    return
                except Exception as rollback_exc:
                    failure += f"；自动回滚也失败：{rollback_exc}"
            set_adblock_status("error", f"过滤规则更新失败；将于 {retry_at} 自动重试：{failure}", completed_at=now_iso())


def do_adblock_mode(mode):
    with worker_lock:
        previous = config()["adblock_mode"]
        backup = backup_adblock()
        try:
            set_adblock_status("applying", f"正在切换到{ {'off':'关闭', 'observe':'观察', 'block':'拦截'}[mode] }模式", backup=str(backup))
            apply_adblock_mode(mode, validate=mode != "off")
            set_adblock_status(
                "updated",
                {"off": "精简过滤已关闭", "observe": "观察模式已启用，只记录命中而不拦截", "block": "精简过滤已启用并通过拦截与分流验证"}[mode],
                mode=mode,
                backup=str(backup),
                completed_at=now_iso(),
            )
        except Exception as exc:
            failure = str(exc)
            try:
                restore_adblock(backup)
                value = config()
                value["adblock_mode"] = previous
                save_config(value)
                set_adblock_status("rolled_back", f"模式切换失败，已恢复原状态：{failure}", mode=previous, backup=str(backup), completed_at=now_iso())
            except Exception as rollback_exc:
                set_adblock_status("error", f"模式切换失败：{failure}；回滚失败：{rollback_exc}", mode=previous, backup=str(backup), completed_at=now_iso())


def domain_in_set(domain, values):
    labels = domain.lower().rstrip(".").split(".")
    return any(".".join(labels[index:]) in values for index in range(max(0, len(labels) - 10), len(labels)))


def adblock_runtime_status():
    value = adblock_status_file()
    settings = config()
    sets = {key: read_compiled_domains(metadata["file"]) for key, metadata in ADBLOCK_SOURCES.items()}
    logs = core_request("/api/v2/audit/logs?limit=2000").get("logs", [])
    hits = {"cn_ads": 0, "adult": 0}
    domains = {}
    for item in logs:
        domain = str(item.get("query_name", "")).lower().rstrip(".")
        if not domain or domain.startswith(("family-filter-test.", "000123456789.")) or settings["adblock_mode"] == "off":
            continue
        if settings["adblock_mode"] == "block" and "广告屏蔽" not in str(item.get("effective_tag", "")):
            continue
        category = "adult" if domain_in_set(domain, sets["adult"]) else "cn_ads" if domain_in_set(domain, sets["cn_ads"]) else None
        if category:
            hits[category] += 1
            domains[domain] = domains.get(domain, 0) + 1
    rules = family_adguard_rules()
    value.update({
        "mode": settings["adblock_mode"],
        "auto_enabled": settings["adblock_auto_enabled"],
        "interval_hours": settings["adblock_interval_hours"],
        "allowlist": "\n".join(load_adblock_allowlist()) + "\n",
        "allowlist_count": len(load_adblock_allowlist()),
        "hits": {**hits, "total": sum(hits.values())},
        "top_domains": [{"domain": domain, "count": count} for domain, count in sorted(domains.items(), key=lambda item: (-item[1], item[0]))[:8]],
        "sources": [
            {
                "key": key,
                "label": metadata["label"],
                "rule_count": len(sets[key]),
                "loaded_count": int((rules.get(key) or {}).get("rule_count", 0)),
                "enabled": bool((rules.get(key) or {}).get("enabled")),
                "source": metadata["url"],
                "project": metadata["project"],
            }
            for key, metadata in ADBLOCK_SOURCES.items()
        ],
        "busy": worker_busy(),
    })
    return value


def backup_rules():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"rule-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        for relative in ("data/srs", "data/webinfo", "data/sub_config/rule_set.yaml", "data/rule/greylist.txt"):
            path = COMPOSE_DIR / relative
            if path.exists():
                archive.add(path, arcname=relative, recursive=True)
    return target


def restore_rules(backup):
    with tarfile.open(backup, "r:gz") as archive:
        archive.extractall(COMPOSE_DIR)
    command(["docker", "restart", CONTAINER], timeout=45)
    wait_healthy(60)


def flush_route_caches():
    for tag in CACHE_TAGS:
        core_action(f"/plugins/{tag}/flush")


def suspicious_answer(answer):
    if answer.get("type") not in ("A", "AAAA"):
        return False
    try:
        address = ipaddress.ip_address(answer.get("data", ""))
    except ValueError:
        return True
    fake_v4 = ipaddress.ip_network("198.18.0.0/15")
    return (
        address in fake_v4
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


UPSTREAM_PROTOCOLS = {
    "udp": "UDP",
    "tcp": "TCP",
    "tls": "DoT",
    "https": "DoH",
    "quic": "DoQ",
}


def upstream_config():
    groups = core_request("/api/v1/upstream/config")
    result = {}
    for group in ("domestic", "foreign"):
        entries = []
        for item in groups.get(group, []):
            protocol = str(item.get("protocol", "")).lower()
            if not item.get("enabled") or protocol not in UPSTREAM_PROTOCOLS:
                continue
            addr = str(item.get("addr", "")).strip()
            if protocol == "https" and item.get("enable_http3") and addr.startswith("https://"):
                addr = "h3://" + addr[len("https://"):]
            entries.append({
                "tag": str(item.get("tag", "")),
                "addr": addr,
                "dial_addr": str(item.get("dial_addr", "")).strip(),
                "protocol": "h3" if protocol == "https" and item.get("enable_http3") else protocol,
            })
        result[group] = entries
    result["notice"] = "仅影响主动使用 Z4Pro MosDNS 的查询，不修改 RouterOS、DHCP DNS 或设备接管状态。"
    return result


def normalize_upstream_line(raw, group, index):
    parts = [part.strip() for part in raw.split("|")]
    if len(parts) > 2 or not parts[0]:
        raise ValueError(f"第 {index} 行格式错误，应为：服务器地址 | 可选连接 IP")
    addr = parts[0]
    dial_addr = parts[1] if len(parts) == 2 else ""
    if dial_addr:
        try:
            ipaddress.ip_address(dial_addr)
        except ValueError as exc:
            raise ValueError(f"第 {index} 行连接 IP 无效：{dial_addr}") from exc

    if "://" not in addr:
        addr = "udp://" + addr
    parsed = urllib.parse.urlsplit(addr)
    scheme = parsed.scheme.lower()
    enable_http3 = scheme == "h3"
    protocol = "https" if enable_http3 else scheme
    if protocol not in UPSTREAM_PROTOCOLS:
        raise ValueError(f"第 {index} 行协议不支持：{scheme or '未知'}")
    if group == "foreign" and protocol in ("udp", "tcp"):
        raise ValueError(f"第 {index} 行国外上游必须使用 DoT、DoH、DoH3 或 DoQ，避免明文污染")
    if not parsed.hostname:
        raise ValueError(f"第 {index} 行缺少有效服务器地址")
    if enable_http3:
        addr = "https://" + addr[len("h3://"):]
    if protocol == "https" and not urllib.parse.urlsplit(addr).path:
        addr = addr.rstrip("/") + "/dns-query"

    label = "DoH3" if enable_http3 else UPSTREAM_PROTOCOLS[protocol]
    item = {
        "tag": f"{'国内' if group == 'domestic' else '国外'} {label} {index}",
        "enabled": True,
        "protocol": protocol,
        "addr": addr,
        "use_socks_proxy": group == "foreign",
    }
    if dial_addr:
        item["dial_addr"] = dial_addr
    if enable_http3:
        item["enable_http3"] = True
    return item


def parse_upstream_text(value, group):
    if not isinstance(value, str):
        raise ValueError(f"{group} 上游格式无效")
    lines = [line.strip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not 1 <= len(lines) <= 8:
        raise ValueError("国内和国外上游分别需要 1 至 8 个服务器")
    entries = [normalize_upstream_line(line, group, index) for index, line in enumerate(lines, 1)]
    fingerprints = [(item["protocol"], item["addr"], item.get("dial_addr", ""), item.get("enable_http3", False)) for item in entries]
    if len(fingerprints) != len(set(fingerprints)):
        raise ValueError(f"{group} 上游存在重复服务器")
    return entries


def save_upstream_config(domestic_text, foreign_text):
    if worker_busy():
        raise RuntimeError("当前有软件或规则维护任务正在运行，请稍后再试")
    if not worker_lock.acquire(blocking=False):
        raise RuntimeError("当前有维护任务正在运行，请稍后再试")
    try:
        current = core_request("/api/v1/upstream/config")
        domestic = parse_upstream_text(domestic_text, "domestic")
        foreign = parse_upstream_text(foreign_text, "foreign")
        proxy = next((str(item.get("socks5", "")).strip() for item in current.get("foreign", []) if item.get("socks5")), DEFAULT_SOCKS5)
        for item in foreign:
            item["socks5"] = proxy

        # Keep disabled and unsupported entries intact so this editor changes only active DNS upstreams.
        old_groups = {group: current.get(group, []) for group in ("domestic", "foreign")}
        new_groups = {}
        for group, active in (("domestic", domestic), ("foreign", foreign)):
            preserved = [item for item in old_groups[group] if not item.get("enabled") or item.get("protocol") not in UPSTREAM_PROTOCOLS]
            new_groups[group] = active + preserved

        backup_dir = COMPOSE_DIR / "backup"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / f"upstream-change-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        atomic_json(backup, {"domestic": old_groups["domestic"], "foreign": old_groups["foreign"]})

        try:
            for group in ("domestic", "foreign"):
                core_json_request("/api/v1/upstream/config", {"plugin_tag": group, "upstreams": new_groups[group]})
            wait_healthy(35)
            route_matrix = validate_route_matrix()
        except Exception as exc:
            failure = str(exc)
            rollback_errors = []
            for group in ("domestic", "foreign"):
                try:
                    core_json_request("/api/v1/upstream/config", {"plugin_tag": group, "upstreams": old_groups[group]})
                except Exception as rollback_exc:
                    rollback_errors.append(f"{group}: {rollback_exc}")
            try:
                wait_healthy(35)
            except Exception as rollback_exc:
                rollback_errors.append(f"健康检查: {rollback_exc}")
            if rollback_errors:
                raise RuntimeError(f"新配置验证失败：{failure}；回滚异常：{'；'.join(rollback_errors)}") from exc
            raise RuntimeError(f"新配置验证失败，已恢复原配置：{failure}") from exc

        return {
            "message": "上游已保存、热重载，并通过国内外分流验证",
            "backup": str(backup),
            "route_matrix": route_matrix,
            "config": upstream_config(),
        }
    finally:
        worker_lock.release()


def validate_route_matrix(mode="full"):
    if mode not in ("quick", "full"):
        raise ValueError("DNS 检查模式无效")
    if mode == "full":
        flush_route_caches()
    direct_results = []
    for direction, domains in ROUTE_PROBES.items():
        for domain in domains:
            answer = command(["dig", "+tries=1", "+time=4", "+short", f"@{DNS_SERVER}", domain, "A"], timeout=7)
            if not answer:
                raise RuntimeError(f"分流回归失败：{domain} 没有返回 IPv4 地址")
            addresses = [line.strip() for line in answer.splitlines() if re.fullmatch(r"[0-9.]+", line.strip())]
            if not addresses:
                raise RuntimeError(f"分流回归失败：{domain} 没有有效 IPv4 地址")
            bad_answers = [address for address in addresses if suspicious_answer({"type": "A", "data": address})]
            if bad_answers:
                raise RuntimeError(f"异常 DNS 地址：{domain} 返回 {', '.join(bad_answers)}")
            direct_results.append({"domain": domain, "direction": direction, "answers": addresses})

    if mode == "quick":
        apple_push = command(["dig", "+tries=1", "+time=4", "+comments", f"@{DNS_SERVER}", "push.apple.com", "A"], timeout=7)
        if "status: NOERROR" not in apple_push:
            raise RuntimeError("Apple Push 探针没有返回 NOERROR")
        return direct_results

    logs = core_request("/api/v2/audit/logs?limit=500").get("logs", [])
    results = []
    for direction, domains in ROUTE_PROBES.items():
        for domain in domains:
            candidates = [
                item for item in logs
                if item.get("query_name") == domain
                and item.get("query_type") == "A"
                and item.get("final_upstream")
            ]
            if not candidates:
                raise RuntimeError(f"分流回归失败：{domain} 没有实际查询上游记录")
            item = max(candidates, key=lambda value: value.get("query_time", ""))
            effective_tag = str(item.get("effective_tag", ""))
            upstream = str(item.get("final_upstream", ""))
            if upstream != direction:
                raise RuntimeError(f"分流方向错误：{domain} 使用了 {upstream} 上游，应为 {direction}")
            if not any(tag in effective_tag for tag in ROUTE_TAGS[direction]):
                raise RuntimeError(f"分流标签错误：{domain} 命中 {effective_tag}")
            bad_answers = [answer.get("data", "") for answer in item.get("answers", []) if suspicious_answer(answer)]
            if bad_answers:
                raise RuntimeError(f"异常 DNS 地址：{domain} 返回 {', '.join(bad_answers)}")
            results.append({
                "domain": domain,
                "direction": direction,
                "effective_tag": effective_tag,
                "upstream": upstream,
                "duration_ms": item.get("duration_ms"),
            })
    apple_push = command(["dig", "+tries=1", "+time=4", "+comments", f"@{DNS_SERVER}", "push.apple.com", "A"], timeout=7)
    if "status: NOERROR" not in apple_push:
        raise RuntimeError("Apple Push 探针没有返回 NOERROR")
    return results


def do_verify(mode):
    set_verify_status("checking", "正在执行快速检查" if mode == "quick" else "正在清理路由缓存并核对分流方向", mode=mode)
    try:
        results = validate_route_matrix(mode)
        message = "快速检查通过，缓存保持不变" if mode == "quick" else "完整回归通过，国内外实际分流方向正确"
        set_verify_status("passed", message, mode=mode, probes=len(results), completed_at=now_iso())
    except Exception as exc:
        set_verify_status("error", f"检查失败：{exc}", mode=mode, completed_at=now_iso())


def validate_rule_update(previous):
    current = current_rule_sources()
    old_counts = {item["tag"]: item["rule_count"] for item in previous}
    for item in current:
        minimum = RULE_SOURCES[item["tag"]]["minimum"]
        lower_bound = max(minimum, int(old_counts.get(item["tag"], 0) * RULE_SOURCES[item["tag"]]["minimum_ratio"]))
        if item["rule_count"] < lower_bound:
            raise RuntimeError(f"{item['label']} 规则数量异常：{item['rule_count']} < {lower_bound}")
    return current, validate_route_matrix()


def wait_rule_source(tag, previous_updated, timeout=180):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        values = core_request(f"/plugins/{tag}/config")
        last = (values[0] if isinstance(values, list) and values else values) or {}
        if last.get("last_updated") and last.get("last_updated") != previous_updated and int(last.get("rule_count", 0)) > 0:
            return last
        time.sleep(1)
    raise RuntimeError(f"{RULE_SOURCES[tag]['label']} 更新超时：{last}")


def refresh_rule_source(tag, previous_updated, attempts=3):
    """The MosDNS source updater occasionally sees transient upstream timeouts."""
    failure = None
    for attempt in range(attempts):
        try:
            core_request(f"/plugins/{tag}/update/{tag}", method="POST", timeout=180)
            return wait_rule_source(tag, previous_updated)
        except Exception as exc:
            failure = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"{RULE_SOURCES[tag]['label']}连续 {attempts} 次更新失败：{failure}")


def do_rule_update():
    with worker_lock:
        backup = None
        try:
            value = config()
            value["last_rule_check"] = int(time.time())
            save_config(value)
            previous = current_rule_sources()
            backup = backup_rules()
            set_rule_status("updating", "正在下载到临时状态并校验官方规则", backup=str(backup), sources=previous)
            previous_by_tag = {item["tag"]: item for item in previous}
            for tag in RULE_SOURCES:
                refresh_rule_source(tag, previous_by_tag[tag].get("last_updated"))
            current, route_matrix = validate_rule_update(previous)
            update_retry_state("rule", succeeded=True)
            set_rule_status(
                "updated",
                "三组官方规则已更新并通过数量、标签、上游方向与异常地址校验",
                sources=current,
                route_matrix=route_matrix,
                backup=str(backup),
                completed_at=now_iso(),
            )
        except Exception as exc:
            failure = str(exc)
            retry = update_retry_state("rule", succeeded=False)
            retry_at = datetime.fromtimestamp(retry["next_rule_retry"], timezone.utc).isoformat(timespec="seconds")
            if backup:
                try:
                    set_rule_status("rolling_back", f"规则校验失败，正在恢复旧文件：{failure}", backup=str(backup))
                    restore_rules(backup)
                    set_rule_status("rolled_back", f"规则更新失败，已恢复旧规则；将于 {retry_at} 自动重试：{failure}", sources=current_rule_sources(), backup=str(backup), completed_at=now_iso())
                    return
                except Exception as rollback_exc:
                    failure += f"；自动回滚也失败：{rollback_exc}"
            set_rule_status("error", f"规则更新失败；将于 {retry_at} 自动重试：{failure}", completed_at=now_iso())


def parse_labels(value):
    return dict(re.findall(r'(\w+)="([^"]*)"', value))


def quantile_from_buckets(buckets, count, ratio):
    if not count:
        return 0
    target = count * ratio
    for upper, value in sorted(buckets, key=lambda item: item[0]):
        if value >= target:
            return upper
    return buckets[-1][0] if buckets else 0


def metrics_summary():
    with urllib.request.urlopen(CORE_API + "/metrics", timeout=5) as response:
        metrics = response.read().decode("utf-8", "replace")
    series = {}
    pattern = re.compile(r'^mosdns_aliapi_(query|error|upstream_winner)_total\{([^}]*)\}\s+([0-9.eE+-]+)$')
    bucket_pattern = re.compile(r'^mosdns_aliapi_response_latency_millisecond_bucket\{([^}]*)\}\s+([0-9.eE+-]+)$')
    sum_pattern = re.compile(r'^mosdns_aliapi_response_latency_millisecond_(sum|count)\{([^}]*)\}\s+([0-9.eE+-]+)$')
    for line in metrics.splitlines():
        match = pattern.match(line)
        if match:
            labels = parse_labels(match.group(2)); key = (labels.get("metrics_tag"), labels.get("tag"), labels.get("addr"))
            series.setdefault(key, {"group": key[0], "name": key[1], "address": key[2], "buckets": []})[match.group(1)] = float(match.group(3))
            continue
        match = bucket_pattern.match(line)
        if match:
            labels = parse_labels(match.group(1)); key = (labels.get("metrics_tag"), labels.get("tag"), labels.get("addr"))
            if labels.get("le") != "+Inf":
                series.setdefault(key, {"group": key[0], "name": key[1], "address": key[2], "buckets": []})["buckets"].append((float(labels["le"]), float(match.group(2))))
            continue
        match = sum_pattern.match(line)
        if match:
            labels = parse_labels(match.group(2)); key = (labels.get("metrics_tag"), labels.get("tag"), labels.get("addr"))
            series.setdefault(key, {"group": key[0], "name": key[1], "address": key[2], "buckets": []})[match.group(1)] = float(match.group(3))
    upstreams = []
    for item in series.values():
        count = item.get("count", 0); queries = item.get("query", 0); errors = item.get("error", 0)
        if item.get("group") not in ("domestic", "foreign") or not queries:
            continue
        upstreams.append({
            "group": item["group"], "name": item["name"], "address": item["address"],
            "queries": int(queries), "errors": int(errors), "error_rate": errors / queries * 100,
            "winners": int(item.get("upstream_winner", 0)),
            "average_ms": item.get("sum", 0) / count if count else 0,
            "p95_ms": quantile_from_buckets(item["buckets"], count, 0.95),
            "p99_ms": quantile_from_buckets(item["buckets"], count, 0.99),
        })
    logs = core_request("/api/v2/audit/logs?limit=2000").get("logs", [])
    durations = sorted(float(item.get("duration_ms", 0)) for item in logs)
    def exact(ratio):
        return durations[min(len(durations) - 1, int((len(durations) - 1) * ratio))] if durations else 0
    return {"p95_ms": exact(0.95), "p99_ms": exact(0.99), "sample_size": len(durations), "upstreams": upstreams, "generated_at": now_iso()}


def do_check():
    with worker_lock:
        set_status("checking", "正在检查 MosDNS-T 第三方整合 Docker 镜像")
        try:
            local = running_image_id()
            remote = remote_image_id()
            available = local != remote
            release = third_party_release()
            set_status(
                "available" if available else "up_to_date",
                "发现可用更新" if available else "当前已经是最新版本",
                update_available=available,
                current_image=local,
                latest_image=remote,
                current_version=core_version(),
                checked_at=now_iso(),
                **release,
            )
        except Exception as exc:
            set_status("error", f"检查失败：{exc}", update_available=False, checked_at=now_iso())


def do_update():
    with worker_lock:
        lock_file = LOCK_PATH.open("a+")
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            set_status("busy", "另一个更新任务正在运行")
            lock_file.close()
            return
        old_image = ""
        backup = ""
        try:
            old_image = running_image_id()
            set_status("updating", "正在备份 MosDNS 配置", current_image=old_image)
            backup = backup_config()
            set_status("updating", "正在拉取 MosDNS 整合 Docker 镜像", current_image=old_image, backup=backup)
            new_image = download_latest_image()
            if new_image == old_image:
                set_status("up_to_date", "当前已经是最新版本", update_available=False, current_image=old_image, latest_image=new_image, current_version=core_version(), checked_at=now_iso())
                return
            set_status("updating", "正在隔离预检新镜像", current_image=old_image, latest_image=new_image, backup=backup)
            verify_new_image(new_image)
            rollback_tag = "family-mosdns-t:rollback-" + datetime.now().strftime("%Y%m%d-%H%M%S")
            command(["docker", "image", "tag", old_image, rollback_tag], timeout=15)
            set_status("updating", "正在重建 MosDNS 容器", current_image=old_image, latest_image=new_image, backup=backup, rollback_image=rollback_tag)
            command(["docker", "compose", "up", "-d", "--no-deps", "--force-recreate", "mosdns-t"], timeout=180)
            wait_healthy()
            set_status("updated", "MosDNS 已更新并通过健康检查", update_available=False, previous_image=old_image, current_image=new_image, current_version=core_version(), backup=backup, rollback_image=rollback_tag, completed_at=now_iso())
        except ImagePreflightError as exc:
            # The live container was not touched; do not recreate or roll back.
            set_status("error", f"新镜像预检失败，未改动当前容器：{exc}", update_available=True, backup=backup, completed_at=now_iso())
        except Exception as exc:
            failure = str(exc)
            if old_image:
                try:
                    set_status("rolling_back", f"更新验证失败，正在恢复旧镜像：{failure}", backup=backup)
                    command(["docker", "image", "tag", old_image, IMAGE], timeout=15)
                    command(["docker", "compose", "up", "-d", "--no-deps", "--force-recreate", "mosdns-t"], timeout=180)
                    wait_healthy(90)
                    set_status("rolled_back", f"新版本验证失败，已恢复旧版本：{failure}", update_available=True, current_image=old_image, current_version=core_version(), backup=backup, completed_at=now_iso())
                    return
                except Exception as rollback_exc:
                    failure += f"；自动回滚也失败：{rollback_exc}"
            set_status("error", f"更新失败：{failure}", update_available=True, backup=backup, completed_at=now_iso())
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
            lock_file.close()


def start_worker(target):
    global worker_active
    with worker_state_lock:
        if worker_active:
            return False
        worker_active = True

    def runner():
        global worker_active
        try:
            target()
        finally:
            with worker_state_lock:
                worker_active = False

    threading.Thread(target=runner, daemon=True).start()
    return True


def worker_busy():
    with worker_state_lock:
        return worker_active


def auto_check_task():
    """Run the scheduled check without changing the running core."""
    do_check()
    current = status()
    if current.get("phase") == "error":
        retry = config()
        retry["last_auto_check"] = int(time.time() - retry["interval_hours"] * 3600 + 6 * 3600)
        save_config(retry)


def scheduler():
    while True:
        time.sleep(300)
        value = config()
        now = time.time()
        if value["adblock_auto_enabled"] and update_due(value, "adblock", now):
            # Do not record a successful scheduling attempt while another task owns the worker.
            if start_worker(do_adblock_update):
                continue
            # A busy worker is expected during maintenance; retry scheduling on the next loop.
            continue
        if value["rule_auto_enabled"] and update_due(value, "rule", now):
            if start_worker(do_rule_update):
                continue
            continue
        if value["auto_enabled"] and now - value["last_auto_check"] >= value["interval_hours"] * 3600:
            value["last_auto_check"] = int(now)
            save_config(value)
            start_worker(auto_check_task)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def authorized(self):
        try:
            expected = SECRET_PATH.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        return bool(expected) and self.headers.get("X-Family-Gateway", "") == expected

    def reply(self, code, value):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.authorized():
            self.reply(HTTPStatus.FORBIDDEN, {"error": "request rejected"})
            return
        if self.path == "/rules/status":
            value = rule_status()
            value["config"] = config()
            value["busy"] = worker_busy()
            try:
                value["sources"] = current_rule_sources()
            except Exception as exc:
                value["source_error"] = str(exc)
            self.reply(HTTPStatus.OK, value)
            return
        if self.path == "/verify/status":
            value = verify_status()
            value["busy"] = worker_busy()
            self.reply(HTTPStatus.OK, value)
            return
        if self.path == "/adblock/status":
            try:
                self.reply(HTTPStatus.OK, adblock_runtime_status())
            except Exception as exc:
                self.reply(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        if self.path == "/metrics":
            try:
                self.reply(HTTPStatus.OK, metrics_summary())
            except Exception as exc:
                self.reply(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        if self.path == "/upstreams":
            try:
                self.reply(HTTPStatus.OK, upstream_config())
            except Exception as exc:
                self.reply(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        if self.path != "/status":
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        value = status()
        value["config"] = config()
        value["busy"] = worker_busy()
        value.setdefault("current_version", core_version())
        self.reply(HTTPStatus.OK, value)

    def do_POST(self):
        if not self.authorized() or self.headers.get("X-Requested-With") != "family-dns":
            self.reply(HTTPStatus.FORBIDDEN, {"error": "request rejected"})
            return
        if self.path == "/check":
            started = start_worker(do_check)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始检查" if started else "已有任务正在运行"})
            return
        if self.path == "/verify/run":
            size = min(int(self.headers.get("Content-Length", "0")), 4096)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
                mode = str(body.get("mode", "quick"))
                if mode not in ("quick", "full"):
                    raise ValueError("DNS 检查模式无效")
            except (ValueError, TypeError) as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid json"})
                return
            started = start_worker(lambda: do_verify(mode))
            message = "已开始快速检查" if mode == "quick" else "已开始完整 DNS 回归"
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": message if started else "已有任务正在运行"})
            return
        if self.path == "/update":
            started = start_worker(do_update)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始更新" if started else "已有任务正在运行"})
            return
        if self.path == "/rules/update":
            started = start_worker(do_rule_update)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始更新规则" if started else "已有任务正在运行"})
            return
        if self.path == "/adblock/update":
            started = start_worker(do_adblock_update)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始直连下载并校验精简过滤规则" if started else "已有任务正在运行"})
            return
        if self.path == "/adblock/mode":
            size = min(int(self.headers.get("Content-Length", "0")), 4096)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
                mode = str(body.get("mode", ""))
                if mode not in ("off", "observe", "block"):
                    raise ValueError("过滤模式无效")
            except (ValueError, TypeError) as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid json"})
                return
            started = start_worker(lambda: do_adblock_mode(mode))
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始切换过滤模式" if started else "已有任务正在运行"})
            return
        if self.path == "/adblock/allowlist":
            size = min(int(self.headers.get("Content-Length", "0")), 65536)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
                allowlist = parse_allowlist(body.get("value", ""))
            except (ValueError, TypeError) as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid json"})
                return
            if worker_busy():
                self.reply(HTTPStatus.CONFLICT, {"started": False, "message": "已有任务正在运行"})
                return
            atomic_text(ADBLOCK_PENDING_ALLOWLIST_PATH, "\n".join(allowlist) + "\n")
            started = start_worker(do_adblock_update)
            if not started:
                ADBLOCK_PENDING_ALLOWLIST_PATH.unlink(missing_ok=True)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "放行名单已提交并开始重新校验" if started else "已有任务正在运行"})
            return
        if self.path == "/upstreams":
            size = min(int(self.headers.get("Content-Length", "0")), 32768)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
                result = save_upstream_config(body.get("domestic"), body.get("foreign"))
                self.reply(HTTPStatus.OK, result)
            except ValueError as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:
                self.reply(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        if self.path == "/rules/auto":
            size = min(int(self.headers.get("Content-Length", "0")), 4096)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
            except ValueError:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            value = config()
            value["rule_auto_enabled"] = bool(body.get("enabled"))
            value["last_rule_check"] = int(time.time())
            save_config(value)
            self.reply(HTTPStatus.OK, {"config": value, "message": "规则自动更新已开启" if value["rule_auto_enabled"] else "规则自动更新已关闭"})
            return
        if self.path == "/adblock/auto":
            size = min(int(self.headers.get("Content-Length", "0")), 4096)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
            except ValueError:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            value = config()
            value["adblock_auto_enabled"] = bool(body.get("enabled"))
            value["last_adblock_check"] = int(time.time())
            save_config(value)
            self.reply(HTTPStatus.OK, {"config": value, "message": "过滤规则自动更新已开启" if value["adblock_auto_enabled"] else "过滤规则自动更新已关闭"})
            return
        if self.path == "/auto":
            size = min(int(self.headers.get("Content-Length", "0")), 4096)
            try:
                body = json.loads(self.rfile.read(size) or "{}")
            except ValueError:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            value = config()
            value["auto_enabled"] = bool(body.get("enabled"))
            value["last_auto_check"] = int(time.time())
            save_config(value)
            self.reply(HTTPStatus.OK, {"config": value, "message": "自动更新已开启" if value["auto_enabled"] else "自动更新已关闭"})
            return
        self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})


class RuleFileHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        files = {
            "/family-cn-ads-lite.rules": ADBLOCK_SOURCES["cn_ads"]["file"],
            "/family-adult-filter.rules": ADBLOCK_SOURCES["adult"]["file"],
        }
        path = files.get(urllib.parse.urlsplit(self.path).path)
        if path is None or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        initial = dict(DEFAULT_CONFIG)
        initial["last_auto_check"] = int(time.time())
        initial["last_rule_check"] = int(time.time())
        initial["last_adblock_check"] = int(time.time())
        save_config(initial)
    threading.Thread(target=scheduler, daemon=True).start()
    threading.Thread(
        target=ThreadingHTTPServer((ADBLOCK_RULES_HOST, ADBLOCK_RULES_PORT), RuleFileHandler).serve_forever,
        daemon=True,
    ).start()
    ThreadingHTTPServer(("127.0.0.1", 18102), Handler).serve_forever()
