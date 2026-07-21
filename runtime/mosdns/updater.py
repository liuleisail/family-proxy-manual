#!/usr/bin/env python3
"""Restricted Docker image updater for the family MosDNS service."""

import fcntl
import ipaddress
import json
import os
import re
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
COMPOSE_DIR = Path(os.environ.get("FAMILY_MOSDNS_COMPOSE_DIR", "/var/lib/family-proxy/docker/family-mosdns-t"))
STATE_DIR = Path("/etc/family-proxy-ui")
CONFIG_PATH = STATE_DIR / "mosdns-updater.json"
STATUS_PATH = STATE_DIR / "mosdns-updater-status.json"
RULE_STATUS_PATH = STATE_DIR / "mosdns-rule-updater-status.json"
LOCK_PATH = STATE_DIR / "mosdns-updater.lock"
SECRET_PATH = STATE_DIR / "gateway.secret"
DEFAULT_CONFIG = {
    "auto_enabled": True,
    "interval_hours": 168,
    "last_auto_check": 0,
    "rule_auto_enabled": True,
    "rule_interval_hours": 24,
    "last_rule_check": 0,
}
CORE_API = os.environ.get("FAMILY_MOSDNS_CORE_API", "http://172.31.53.2:9099").rstrip("/")
DNS_SERVER = os.environ.get("FAMILY_MOSDNS_DNS_SERVER", "127.0.0.1")
DEFAULT_SOCKS5 = os.environ.get("FAMILY_MOSDNS_SOCKS5", "172.31.53.1:7890")
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
    return {
        "auto_enabled": bool(value.get("auto_enabled", True)),
        "interval_hours": max(24, min(720, int(value.get("interval_hours", 168)))),
        "last_auto_check": max(0, int(value.get("last_auto_check", 0))),
        "rule_auto_enabled": bool(value.get("rule_auto_enabled", True)),
        "rule_interval_hours": max(12, min(168, int(value.get("rule_interval_hours", 24)))),
        "last_rule_check": max(0, int(value.get("last_rule_check", 0))),
    }


def save_config(value):
    atomic_json(CONFIG_PATH, value)


def status():
    return load_json(STATUS_PATH, {"phase": "idle", "message": "尚未检查软件更新"})


def rule_status():
    return load_json(RULE_STATUS_PATH, {"phase": "idle", "message": "尚未执行规则更新"})


def set_status(phase, message, **extra):
    value = status()
    value.update({"phase": phase, "message": message, "updated_at": now_iso(), **extra})
    atomic_json(STATUS_PATH, value)
    return value


def set_rule_status(phase, message, **extra):
    value = rule_status()
    value.update({"phase": phase, "message": message, "updated_at": now_iso(), **extra})
    atomic_json(RULE_STATUS_PATH, value)
    return value


def core_request(path, method="GET", timeout=15):
    request = urllib.request.Request(CORE_API + path, method=method)
    if method != "GET":
        request.add_header("Content-Length", "0")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        return json.loads(body) if body else {}


def core_json_request(path, payload, timeout=30):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(CORE_API + path, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = response.read()
            return json.loads(value) if value else {}
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
        "NO_PROXY": "127.0.0.1,localhost,192.168.2.0/24,172.31.53.0/24",
    })
    return command([CRANE, *args], timeout=timeout, env=environment)


def remote_image_id():
    manifest = json.loads(crane_command(["manifest", IMAGE, "--platform=linux/amd64"], timeout=60))
    digest = manifest.get("config", {}).get("digest")
    if not digest:
        raise RuntimeError("官方镜像清单缺少配置标识")
    return digest


def download_latest_image():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / ".mosdns-image-download.tar"
    try:
        archive.unlink(missing_ok=True)
        crane_command(["pull", IMAGE, str(archive), "--platform=linux/amd64", "--format=legacy"], timeout=600)
        command(["docker", "load", "--input", str(archive)], timeout=300)
    finally:
        archive.unlink(missing_ok=True)
    return command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=10)


def backup_config():
    backup_dir = COMPOSE_DIR / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"software-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    candidates = [
        "compose.yml", "nginx/default.conf", "web/index.html", "auth",
        "data/config_custom.yaml", "data/sub_config", "data/rule", "data/srs", "data/webinfo",
    ]
    with tarfile.open(target, "w:gz") as archive:
        for relative in candidates:
            path = COMPOSE_DIR / relative
            if path.exists():
                archive.add(path, arcname=relative, recursive=True)
    return str(target)


def wait_healthy(timeout=90):
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
                answer = command(["dig", "+tries=1", "+time=3", "+short", f"@{DNS_SERVER}", domain, "A"], timeout=6)
                if not answer:
                    raise RuntimeError(f"{domain} 没有返回 IPv4 地址")
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


def validate_route_matrix():
    flush_route_caches()
    for direction, domains in ROUTE_PROBES.items():
        for domain in domains:
            answer = command(["dig", "+tries=1", "+time=4", "+short", f"@{DNS_SERVER}", domain, "A"], timeout=7)
            if not answer:
                raise RuntimeError(f"分流回归失败：{domain} 没有返回 IPv4 地址")

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
                core_request(f"/plugins/{tag}/update/{tag}", method="POST", timeout=180)
                wait_rule_source(tag, previous_by_tag[tag].get("last_updated"))
            current, route_matrix = validate_rule_update(previous)
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
            if backup:
                try:
                    set_rule_status("rolling_back", f"规则校验失败，正在恢复旧文件：{failure}", backup=str(backup))
                    restore_rules(backup)
                    set_rule_status("rolled_back", f"规则更新失败，已恢复旧规则：{failure}", sources=current_rule_sources(), backup=str(backup), completed_at=now_iso())
                    return
                except Exception as rollback_exc:
                    failure += f"；自动回滚也失败：{rollback_exc}"
            set_rule_status("error", f"规则更新失败：{failure}", completed_at=now_iso())


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
        set_status("checking", "正在检查官方 Docker 镜像")
        try:
            local = running_image_id()
            remote = remote_image_id()
            available = local != remote
            set_status(
                "available" if available else "up_to_date",
                "发现可用更新" if available else "当前已经是最新版本",
                update_available=available,
                current_image=local,
                latest_image=remote,
                current_version=core_version(),
                checked_at=now_iso(),
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
            set_status("updating", "正在拉取官方 Docker 镜像", current_image=old_image, backup=backup)
            new_image = download_latest_image()
            if new_image == old_image:
                set_status("up_to_date", "当前已经是最新版本", update_available=False, current_image=old_image, latest_image=new_image, current_version=core_version(), checked_at=now_iso())
                return
            rollback_tag = "family-mosdns-t:rollback-" + datetime.now().strftime("%Y%m%d-%H%M%S")
            command(["docker", "image", "tag", old_image, rollback_tag], timeout=15)
            set_status("updating", "正在重建 MosDNS 容器", current_image=old_image, latest_image=new_image, backup=backup, rollback_image=rollback_tag)
            command(["docker", "compose", "up", "-d", "--no-deps", "--force-recreate", "mosdns-t"], timeout=180)
            wait_healthy()
            set_status("updated", "MosDNS 已更新并通过健康检查", update_available=False, previous_image=old_image, current_image=new_image, current_version=core_version(), backup=backup, rollback_image=rollback_tag, completed_at=now_iso())
        except Exception as exc:
            failure = str(exc)
            if old_image:
                try:
                    set_status("rolling_back", f"更新验证失败，正在恢复旧镜像：{failure}", backup=backup)
                    command(["docker", "image", "tag", old_image, IMAGE], timeout=15)
                    command(["docker", "compose", "up", "-d", "--no-deps", "--force-recreate", "mosdns-t"], timeout=180)
                    wait_healthy(60)
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


def scheduler():
    while True:
        time.sleep(300)
        value = config()
        now = time.time()
        if value["rule_auto_enabled"] and now - value["last_rule_check"] >= value["rule_interval_hours"] * 3600:
            value["last_rule_check"] = int(now)
            save_config(value)
            start_worker(do_rule_update)
            continue
        if value["auto_enabled"] and now - value["last_auto_check"] >= value["interval_hours"] * 3600:
            value["last_auto_check"] = int(now)
            save_config(value)

            def auto_task():
                do_check()
                current = status()
                if current.get("phase") == "error":
                    retry = config()
                    retry["last_auto_check"] = int(time.time() - retry["interval_hours"] * 3600 + 6 * 3600)
                    save_config(retry)
                elif current.get("update_available"):
                    do_update()

            start_worker(auto_task)


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
        if self.path == "/update":
            started = start_worker(do_update)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始更新" if started else "已有任务正在运行"})
            return
        if self.path == "/rules/update":
            started = start_worker(do_rule_update)
            self.reply(HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT, {"started": started, "message": "已开始更新规则" if started else "已有任务正在运行"})
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


if __name__ == "__main__":
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        initial = dict(DEFAULT_CONFIG)
        initial["last_auto_check"] = int(time.time())
        initial["last_rule_check"] = int(time.time())
        save_config(initial)
    threading.Thread(target=scheduler, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 18102), Handler).serve_forever()
