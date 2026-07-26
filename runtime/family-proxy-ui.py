#!/usr/bin/env python3
"""LAN-only controller for selected-device family Mihomo routing."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import shutil
import socket
import subprocess
import threading
import time
import yaml
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen


CONFIG_PATH = Path("/etc/family-proxy-ui/router.env")
GATEWAY_SECRET_PATH = Path("/etc/family-proxy-ui/gateway.secret")
MANAGED_IPS_PATH = Path("/etc/family-proxy-ui/managed-ips")
DEVICE_PREFS_PATH = Path("/etc/family-proxy-ui/device-preferences.json")
ALERT_CONFIG_PATH = Path("/etc/family-proxy-ui/mihomo-alert.json")
ALERT_SOURCES_PATH = Path("/tmp/zfsv3/nvme13/18053615760/data/docker/family-mihomo-sub-import/providers/sources.json")
TPROXY_SYNC = "/usr/local/sbin/family-mihomo-tproxy-auto"
MIHOMO_API = "http://127.0.0.1:9091"
MIHOMO_CONFIG_PATH = Path("__FAMILY_DOCKER_ROOT__/family-mihomo-fallback/config.yaml")
MIHOMO_UPGRADE_SCRIPT = "/usr/local/sbin/family-mihomo-upgrade"
RULE_BACKUP_DIR = MIHOMO_CONFIG_PATH.parent / "rule-backups"
RULES_TEMPLATE_PATH = Path("/opt/family-proxy-ui/rules.html")
MIHOMO_GROUPS = ("AI", "Youtube", "Telegram", "Google", "Others")
LAN = ipaddress.ip_network("__FAMILY_LAN_CIDR__")
PROXY_IP = "__FAMILY_PROXY_IP__"
FIXED_MANAGED_IPS = set()
RESERVED_IPS = {"__FAMILY_ROUTER_IP__", "__FAMILY_RESERVED_GATEWAY_IP__", PROXY_IP}
AUDIT_PATH = Path("/var/log/family-proxy-ui-audit.jsonl")
CSRF_TOKEN_PATH = Path("/etc/family-proxy-ui/csrf-token")
BUILD_VERSION = "2026.07.22-wireguard-monitor"
SHARED_LIST = "family_mihomo_devices"
SHARED_TABLE = "family_mihomo_shared"
SHARED_CONN_MARK = "family_mihomo_conn"
SHARED_TAG = "family-mihomo-shared"
def load_csrf_token():
    try:
        token = CSRF_TOKEN_PATH.read_text(encoding="utf-8").strip()
        if len(token) >= 32:
            return token
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    CSRF_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CSRF_TOKEN_PATH.with_suffix(".new")
    temporary.write_text(token + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, CSRF_TOKEN_PATH)
    return token


CSRF_TOKEN = load_csrf_token()
HEALTH_LOCK = threading.Lock()
HEALTH_GATE = {"ready": True, "failures": 0, "successes": 0}
RULES_LOCK = threading.Lock()
DEVICE_PREFS_LOCK = threading.Lock()
DNS_METRICS_LOCK = threading.Lock()
DNS_SAMPLES = deque(maxlen=120)
SYSTEM_STATUS_LOCK = threading.Lock()
SYSTEM_STATUS_CACHE = {"timestamp": 0.0, "value": None, "cpu_sample": None}
HDD_TEMPERATURE_CACHE = {"timestamp": 0.0, "value": []}
WIREGUARD_STATUS_LOCK = threading.Lock()
WIREGUARD_EVENTS_PATH = Path("/var/lib/family-proxy/wireguard-events.json")
WIREGUARD_EVENT_RETENTION = 7 * 24 * 60 * 60
WIREGUARD_EVENT_LIMIT = 200
WIREGUARD_STATE = {"interfaces": {}, "probe_timestamp": 0.0, "probe": None}
CAPTURE_DIR = Path("/run/family-proxy-captures")
CAPTURE_INTERFACE = os.environ.get("FAMILY_CAPTURE_INTERFACE", "kvmbr0")
CAPTURE_MAX_BYTES = 50_000_000
CAPTURE_TOTAL_BYTES = 200_000_000
CAPTURE_RETENTION_SECONDS = 24 * 60 * 60
CAPTURE_DURATIONS = {30, 60, 180}
CAPTURE_SCOPES = {
    "all": ("全部流量", ()),
    "dns": ("仅 DNS", ("and", "port", "53")),
    "tcp": ("仅 TCP", ("and", "tcp")),
    "udp": ("仅 UDP", ("and", "udp")),
}
CAPTURE_LOCK = threading.Lock()
CAPTURE_STATE = {"active": None}
PROTECTED_RULES = {"GEOSITE,CN,DIRECT", "GEOIP,CN,DIRECT,no-resolve"}


class RouterError(RuntimeError):
    pass


def load_config():
    config = {}
    for line in CONFIG_PATH.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.strip().split("=", 1)
            config[key] = value
    required = {"ROUTER_HOST", "ROUTER_USER", "ROUTER_PASSWORD"}
    if required - config.keys():
        raise RouterError("Router automation credentials are incomplete")
    return config


def valid_basic_auth(header):
    config = load_config()
    username = config.get("UI_USERNAME")
    salt = config.get("UI_PASSWORD_SALT")
    expected = config.get("UI_PASSWORD_HASH")
    if not username or not salt or not expected or not header.startswith("Basic "):
        return False
    try:
        supplied = base64.b64decode(header[6:], validate=True).decode()
        supplied_user, supplied_password = supplied.split(":", 1)
        supplied_hash = hashlib.pbkdf2_hmac("sha256", supplied_password.encode(), bytes.fromhex(salt), 210000).hex()
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(supplied_user, username) and hmac.compare_digest(supplied_hash, expected)


def trusted_gateway(client_ip, header):
    try:
        return (ipaddress.ip_address(client_ip).is_loopback
                and hmac.compare_digest(header, GATEWAY_SECRET_PATH.read_text().strip()))
    except (OSError, ValueError):
        return False


def encode_length(length):
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        return (length | 0x8000).to_bytes(2, "big")
    if length < 0x200000:
        return (length | 0xC00000).to_bytes(3, "big")
    if length < 0x10000000:
        return (length | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + length.to_bytes(4, "big")


def decode_length(sock):
    first = sock.recv(1)
    if not first:
        raise RouterError("Router API connection closed")
    value = first[0]
    if value < 0x80:
        return value
    if value < 0xC0:
        return ((value & 0x3F) << 8) + sock.recv(1)[0]
    if value < 0xE0:
        return ((value & 0x1F) << 16) + int.from_bytes(sock.recv(2), "big")
    if value < 0xF0:
        return ((value & 0x0F) << 24) + int.from_bytes(sock.recv(3), "big")
    return int.from_bytes(sock.recv(4), "big")


class RouterOS:
    def __init__(self):
        self.config = load_config()
        self.sock = None

    def __enter__(self):
        self.sock = socket.create_connection((self.config["ROUTER_HOST"], 8728), timeout=5)
        self.sock.settimeout(8)
        self.talk("/login", {"name": self.config["ROUTER_USER"], "password": self.config["ROUTER_PASSWORD"]})
        return self

    def __exit__(self, *_):
        if self.sock:
            self.sock.close()

    def send(self, words):
        for word in words:
            data = word.encode()
            self.sock.sendall(encode_length(len(data)) + data)
        self.sock.sendall(b"\x00")

    def read_sentence(self):
        words = []
        while True:
            length = decode_length(self.sock)
            if length == 0:
                return words
            data = b""
            while len(data) < length:
                chunk = self.sock.recv(length - len(data))
                if not chunk:
                    raise RouterError("Router API connection closed")
                data += chunk
            words.append(data.decode(errors="replace"))

    def talk(self, command, props=None):
        words = [command]
        for key, value in (props or {}).items():
            if value is not None:
                words.append(f"={key}={value}")
        self.send(words)
        records = []
        while True:
            sentence = self.read_sentence()
            if not sentence:
                continue
            kind, *fields = sentence
            values = {}
            for field in fields:
                if field.startswith("=") and "=" in field[1:]:
                    key, value = field[1:].split("=", 1)
                    values[key] = value
            if kind == "!re":
                records.append(values)
            elif kind == "!trap":
                raise RouterError(values.get("message", "Router rejected the operation"))
            elif kind == "!done":
                if values:
                    records.append(values)
                return records

    def print(self, path):
        return self.talk(path + "/print")

    def add(self, path, **props):
        return self.talk(path + "/add", props)

    def remove(self, path, item_id):
        return self.talk(path + "/remove", {".id": item_id})

    def set(self, path, item_id, **props):
        props[".id"] = item_id
        return self.talk(path + "/set", props)


def managed_tag(ip):
    return f"family-mihomo-auto-{ip}"


def legacy_tag(ip):
    return f"family-mihomo-{ip.rsplit('.', 1)[1]}"


def policy_address(comment):
    if not comment.endswith("route to z4pro"):
        return None
    head = comment.split()[0]
    if head.startswith("family-mihomo-auto-"):
        address = head.removeprefix("family-mihomo-auto-")
    elif head.startswith("family-mihomo-"):
        token = head.removeprefix("family-mihomo-")
        address = f"__FAMILY_LAN_PREFIX__{int(token)}" if token.isdigit() else token
    else:
        return None
    try:
        return address if ipaddress.ip_address(address) in LAN else None
    except ValueError:
        return None


def managed_ips():
    if not MANAGED_IPS_PATH.exists():
        return set()
    return {line.strip() for line in MANAGED_IPS_PATH.read_text().splitlines() if line.strip()}


def address_list_managed(api):
    return {
        item.get("address") for item in api.print("/ip/firewall/address-list")
        if item.get("list") == SHARED_LIST and item.get("address")
    }


def save_managed_ips(addresses):
    content = "".join(f"{address}\n" for address in sorted(addresses, key=lambda value: tuple(map(int, value.split(".")))))
    temporary = MANAGED_IPS_PATH.with_suffix(".new")
    temporary.write_text(content)
    os.chmod(temporary, 0o600)
    os.replace(temporary, MANAGED_IPS_PATH)


def sync_tproxy():
    result = subprocess.run([TPROXY_SYNC, "sync"], text=True, capture_output=True)
    if result.returncode:
        raise RouterError("Z4Pro 透明代理同步失败")


def mihomo_request(path, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(MIHOMO_API + path, data=data, method=method)
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RouterError("mihomo 控制接口不可用") from exc


def dns_probe(name="www.baidu.com"):
    transaction = secrets.token_bytes(2)
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    packet = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, (PROXY_IP, 53))
        response, _ = client.recvfrom(4096)
    return (response[:2] == transaction and len(response) >= 12 and
            response[3] & 0x0F == 0 and int.from_bytes(response[6:8], "big") > 0)


def local_health():
    started = time.monotonic()
    checks = {"mihomo": False, "dns": False, "policy": False}
    detail = {}
    try:
        version = mihomo_request("/version")
        checks["mihomo"] = bool(version)
        detail["version"] = version.get("version", "")
        policy = mihomo_request("/proxies/Proxy-Auto")
        checks["policy"] = bool(policy.get("now") and policy.get("all"))
        detail["proxy"] = policy.get("now")
    except RouterError:
        pass
    try:
        dns_started = time.monotonic()
        checks["dns"] = dns_probe()
        dns_ms = round((time.monotonic() - dns_started) * 1000, 1)
        if checks["dns"]:
            with DNS_METRICS_LOCK:
                DNS_SAMPLES.append(dns_ms)
                ordered = sorted(DNS_SAMPLES)
                detail["dns_ms"] = dns_ms
                detail["dns_p50_ms"] = ordered[(len(ordered) - 1) // 2]
                detail["dns_p95_ms"] = ordered[max(0, round((len(ordered) - 1) * 0.95))]
                detail["dns_samples"] = len(ordered)
    except (OSError, TimeoutError):
        pass
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "detail": detail,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def gated_health():
    health = local_health()
    with HEALTH_LOCK:
        if health["ready"]:
            HEALTH_GATE["successes"] += 1
            HEALTH_GATE["failures"] = 0
            if HEALTH_GATE["successes"] >= 2:
                HEALTH_GATE["ready"] = True
        else:
            HEALTH_GATE["failures"] += 1
            HEALTH_GATE["successes"] = 0
            if HEALTH_GATE["failures"] >= 2:
                HEALTH_GATE["ready"] = False
        health["raw_ready"] = health["ready"]
        health["ready"] = HEALTH_GATE["ready"]
        health["gate"] = dict(HEALTH_GATE)
    return health


def audit(action, ip, outcome, detail=""):
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "action": action,
        "ip": ip,
        "outcome": outcome,
        "detail": detail[:300],
    }
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.chmod(AUDIT_PATH, 0o600)
    except OSError:
        pass


def mihomo_groups():
    groups = []
    for name in MIHOMO_GROUPS:
        try:
            group = mihomo_request("/proxies/" + quote(name, safe=""))
        except RouterError:
            if name == "AI":
                continue
            raise
        groups.append({"name": name, "now": group.get("now"), "all": group.get("all", [])})
    return {"groups": groups}


def select_mihomo_node(group_name, node_name):
    if group_name not in MIHOMO_GROUPS:
        raise RouterError("不允许管理该策略组")
    group = mihomo_request("/proxies/" + quote(group_name, safe=""))
    if node_name not in group.get("all", []):
        raise RouterError("该节点不属于当前策略组")
    mihomo_request("/proxies/" + quote(group_name, safe=""), method="PUT", payload={"name": node_name})
    return {"message": f"{group_name} 已切换到 {node_name}"}


def mihomo_upgrade_status():
    result = subprocess.run([MIHOMO_UPGRADE_SCRIPT, "status"], text=True, capture_output=True, timeout=5)
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RouterError("Mihomo 维护状态无法读取") from exc
    if not isinstance(payload, dict):
        raise RouterError("Mihomo 维护状态格式错误")
    return payload


def start_mihomo_upgrade(unit):
    if unit not in {"family-mihomo-upgrade-check.service", "family-mihomo-upgrade.service"}:
        raise RouterError("不允许的维护操作")
    result = subprocess.run(["systemctl", "start", "--no-block", unit], text=True, capture_output=True, timeout=8)
    if result.returncode:
        raise RouterError("Mihomo 维护任务无法启动")
    return {"message": "维护任务已启动，请等待状态刷新", "status": mihomo_upgrade_status()}


def load_alert_settings():
    try:
        data = json.loads(ALERT_CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RouterError("Telegram 告警设置读取失败") from exc
    available = available_alert_sources()
    valid_slots = {item["slot"] for item in available}
    return {
        "enabled": bool(data.get("enabled")),
        "configured": bool(str(data.get("token", "")).strip() and str(data.get("chat_id", "")).strip()),
        "chat_id_masked": ("*" * max(0, len(str(data.get("chat_id", ""))) - 4) + str(data.get("chat_id", ""))[-4:]) if data.get("chat_id") else "",
        "notify_recovery": bool(data.get("notify_recovery", True)),
        "source_slots": [slot for slot in data.get("source_slots", []) if slot in valid_slots],
        "available_sources": available,
    }


def available_alert_sources():
    try:
        data = json.loads(ALERT_SOURCES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = [{"slot": "primary", "label": "主力机场"}]
    return [{"slot": str(item["slot"]), "label": str(item.get("label", item["slot"]))}
            for item in data if isinstance(item, dict) and item.get("slot")]


def save_alert_settings(payload):
    try:
        existing = json.loads(ALERT_CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        existing = {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RouterError("Telegram 告警设置读取失败") from exc
    token = str(payload.get("token", "")).strip() or str(existing.get("token", "")).strip()
    chat_id = str(payload.get("chat_id", "")).strip() or str(existing.get("chat_id", "")).strip()
    enabled = bool(payload.get("enabled"))
    source_slots = [str(item) for item in payload.get("source_slots", []) if isinstance(item, str)]
    valid_slots = {item["slot"] for item in available_alert_sources()}
    source_slots = [slot for slot in source_slots if slot in valid_slots]
    if enabled and (not token or not chat_id):
        raise RouterError("启用告警需要同时填写 Bot Token 和 Chat ID")
    if enabled and not source_slots:
        raise RouterError("启用告警至少选择一个机场来源")
    data = {"enabled": enabled, "token": token, "chat_id": chat_id,
            "notify_recovery": bool(payload.get("notify_recovery", True)), "source_slots": source_slots}
    ALERT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = ALERT_CONFIG_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, ALERT_CONFIG_PATH)
    audit("alert_settings", "saved", "enabled=" + str(enabled))
    return load_alert_settings()


def send_alert_test():
    try:
        data = json.loads(ALERT_CONFIG_PATH.read_text(encoding="utf-8"))
        token, chat_id = str(data.get("token", "")).strip(), str(data.get("chat_id", "")).strip()
    except (OSError, json.JSONDecodeError) as exc:
        raise RouterError("请先保存 Telegram 告警设置") from exc
    if not data.get("enabled") or not token or not chat_id:
        raise RouterError("请先启用并完成 Telegram 告警设置")
    target = "https://api.telegram.org/bot" + token + "/sendMessage?" + urlencode({
        "chat_id": chat_id, "text": "家庭旁路测试通知\nTelegram 告警通道已验证",
    })
    try:
        mihomo_request("/proxies/TG-Notify/delay?" + urlencode({"url": target, "timeout": 15000}))
    except RouterError as exc:
        raise RouterError("Telegram 测试消息发送失败") from exc
    audit("alert_settings", "test_sent", "telegram")
    return {"message": "测试消息已发送"}


def rules_version(rules):
    value = json.dumps(rules, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()[:16]


def load_mihomo_config():
    try:
        text = MIHOMO_CONFIG_PATH.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RouterError("Mihomo 配置无法读取") from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise RouterError("Mihomo 配置缺少有效的 rules 数组")
    rules = document["rules"]
    if not all(isinstance(rule, str) for rule in rules):
        raise RouterError("Mihomo 规则格式不受支持")
    return text, document, rules


def rules_payload():
    _, document, rules = load_mihomo_config()
    policies = ["DIRECT", "REJECT", "REJECT-DROP", "PASS"]
    policies.extend(
        group.get("name") for group in document.get("proxy-groups", [])
        if isinstance(group, dict) and isinstance(group.get("name"), str)
    )
    return {
        "rules": rules,
        "version": rules_version(rules),
        "policies": list(dict.fromkeys(policies)),
        "protected": sorted(PROTECTED_RULES),
    }


def normalize_rules(value):
    if not isinstance(value, list):
        raise RouterError("规则列表格式错误")
    if not 1 <= len(value) <= 200:
        raise RouterError("规则数量必须在 1 到 200 条之间")
    rules = []
    for index, rule in enumerate(value, 1):
        if not isinstance(rule, str):
            raise RouterError(f"第 {index} 条规则不是文本")
        rule = rule.strip()
        if not rule or len(rule) > 512 or "\n" in rule or "\r" in rule:
            raise RouterError(f"第 {index} 条规则为空或过长")
        if "," not in rule:
            raise RouterError(f"第 {index} 条规则缺少分隔符")
        rules.append(rule)
    missing = PROTECTED_RULES - set(rules)
    if missing:
        raise RouterError("国内直连保护规则不能删除")
    matches = [index for index, rule in enumerate(rules) if rule.upper().startswith("MATCH,")]
    if matches != [len(rules) - 1]:
        raise RouterError("必须且只能保留一条 MATCH 规则，并放在最后")
    return rules


def mihomo_apply_payload(payload):
    data = json.dumps({"payload": payload}, ensure_ascii=False).encode()
    request = Request(MIHOMO_API + "/configs?force=true", data=data, method="PUT")
    request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=15) as response:
            response.read()
    except HTTPError as exc:
        try:
            detail = exc.read().decode(errors="replace")[:240]
        except OSError:
            detail = ""
        raise RouterError("Mihomo 拒绝了规则配置" + (f"：{detail}" if detail else "")) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RouterError("Mihomo 规则校验接口不可用") from exc


def save_mihomo_rules(value, expected_version):
    rules = normalize_rules(value)
    with RULES_LOCK:
        original_text, document, current_rules = load_mihomo_config()
        if expected_version != rules_version(current_rules):
            raise RouterError("规则已被其他操作更新，请刷新后重试")
        if rules == current_rules:
            return {**rules_payload(), "message": "规则没有变化"}
        document["rules"] = rules
        candidate = yaml.safe_dump(document, allow_unicode=True, sort_keys=False)
        mihomo_apply_payload(candidate)
        try:
            RULE_BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup = RULE_BACKUP_DIR / f"config-before-rules-{stamp}-{rules_version(current_rules)}.yaml"
            backup.write_text(original_text, encoding="utf-8")
            os.chmod(backup, 0o600)
            temporary = RULE_BACKUP_DIR / f".config-{os.getpid()}-{secrets.token_hex(4)}.yaml"
            temporary.write_text(candidate, encoding="utf-8")
            os.chmod(temporary, 0o640)
            os.replace(temporary, MIHOMO_CONFIG_PATH)
            for old_backup in sorted(RULE_BACKUP_DIR.glob("config-before-rules-*.yaml"))[:-20]:
                old_backup.unlink()
        except OSError as exc:
            try:
                mihomo_apply_payload(original_text)
            except RouterError:
                pass
            raise RouterError("规则已撤回：配置无法安全写入磁盘") from exc
        health = local_health()
        if not health["ready"]:
            MIHOMO_CONFIG_PATH.write_text(original_text, encoding="utf-8")
            mihomo_apply_payload(original_text)
            raise RouterError("规则已撤回：应用后健康检查未通过")
        audit("rules", "mihomo", "ok", f"{len(current_rules)} -> {len(rules)}")
        return {**rules_payload(), "message": f"已应用 {len(rules)} 条规则，并保存回滚备份"}


def validate_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RouterError("请输入有效的 IPv4 地址") from exc
    if address not in LAN or str(address) in RESERVED_IPS:
        raise RouterError("该地址不在可管理范围内")
    return str(address)


def capture_paths(capture_id):
    if (not isinstance(capture_id, str) or not capture_id.startswith("capture-")
            or len(capture_id) > 64
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in capture_id)):
        raise RouterError("抓包记录编号无效")
    return CAPTURE_DIR / f"{capture_id}.pcap", CAPTURE_DIR / f"{capture_id}.json"


def write_capture_metadata(metadata):
    _, metadata_path = capture_paths(metadata["id"])
    temporary = metadata_path.with_suffix(".json.new")
    temporary.write_text(json.dumps(metadata, ensure_ascii=False), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, metadata_path)


def read_capture_metadata(metadata_path):
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        capture_paths(metadata.get("id"))
        return metadata
    except (OSError, ValueError, json.JSONDecodeError, RouterError):
        return None


def public_capture(metadata):
    capture_path, _ = capture_paths(metadata["id"])
    size = capture_path.stat().st_size if capture_path.exists() else 0
    result = {key: metadata.get(key) for key in (
        "id", "ip", "scope", "scope_label", "duration", "status",
        "created_at", "finished_at", "expires_at", "message",
    )}
    result.update({
        "size": size,
        "running": metadata.get("status") == "running",
        "downloadable": metadata.get("status") != "running" and size >= 24,
    })
    return result


def cleanup_captures():
    CAPTURE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CAPTURE_DIR, 0o700)
    now = time.time()
    active_id = CAPTURE_STATE["active"]["id"] if CAPTURE_STATE.get("active") else None
    records = []
    known_pcaps = set()
    for metadata_path in CAPTURE_DIR.glob("capture-*.json"):
        metadata = read_capture_metadata(metadata_path)
        if not metadata:
            metadata_path.unlink(missing_ok=True)
            continue
        if metadata.get("status") == "running" and metadata["id"] != active_id:
            metadata["status"] = "interrupted"
            metadata["finished_at"] = int(now)
            metadata["message"] = "管理服务重启，抓包已停止"
            write_capture_metadata(metadata)
        capture_path, _ = capture_paths(metadata["id"])
        known_pcaps.add(capture_path)
        if metadata["id"] != active_id and float(metadata.get("expires_at", 0) or 0) <= now:
            capture_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            continue
        if capture_path.exists():
            records.append((capture_path.stat().st_mtime, capture_path, metadata_path))
    for capture_path in CAPTURE_DIR.glob("capture-*.pcap"):
        if capture_path not in known_pcaps and now - capture_path.stat().st_mtime > 300:
            capture_path.unlink(missing_ok=True)
    total = sum(path.stat().st_size for _, path, _ in records if path.exists())
    for _, capture_path, metadata_path in sorted(records):
        capture_id = metadata_path.stem
        if total <= CAPTURE_TOTAL_BYTES:
            break
        if capture_id == active_id:
            continue
        size = capture_path.stat().st_size if capture_path.exists() else 0
        capture_path.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        total -= size


def capture_live_reader(record):
    stream = record["live_process"].stdout
    if not stream:
        return
    for raw_line in stream:
        line = " ".join(raw_line.strip().split())[-320:]
        if not line:
            continue
        with CAPTURE_LOCK:
            record["live_packets"] += 1
            record["live_lines"].append({
                "seq": record["live_packets"],
                "text": line,
            })


def stop_capture_process(process):
    if not process or process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=3)


def capture_monitor(record):
    process = record["process"]
    deadline = record["started_monotonic"] + record["metadata"]["duration"]
    reason = "completed"
    while process.poll() is None:
        with CAPTURE_LOCK:
            requested = record.get("stop_reason")
        if requested:
            reason = requested
            break
        if time.monotonic() >= deadline:
            reason = "completed"
            break
        time.sleep(0.2)
    stop_capture_process(process)
    stop_capture_process(record.get("live_process"))
    stderr = process.stderr.read().strip()[-500:] if process.stderr else ""
    return_code = process.returncode
    with CAPTURE_LOCK:
        if record.get("stop_reason"):
            reason = record["stop_reason"]
        metadata = record["metadata"]
        if reason == "manual":
            metadata["status"] = "stopped"
            metadata["message"] = "已手动停止"
        elif return_code in (0, 130, -signal.SIGINT):
            metadata["status"] = "completed"
            metadata["message"] = "已达到设定时长"
        elif return_code in (-signal.SIGXFSZ, 153):
            metadata["status"] = "limit"
            metadata["message"] = "已达到 50 MB 容量上限"
        else:
            metadata["status"] = "failed"
            metadata["message"] = stderr or f"tcpdump 退出码 {return_code}"
        metadata["finished_at"] = int(time.time())
        metadata["live_packets"] = record["live_packets"]
        metadata["recent_lines"] = list(record["live_lines"])[-30:]
        write_capture_metadata(metadata)
        if CAPTURE_STATE.get("active") is record:
            CAPTURE_STATE["active"] = None
        cleanup_captures()
    audit("capture_finish", metadata["ip"], metadata["status"], metadata["id"])


def start_capture(ip, duration, scope):
    ip = validate_ip(ip)
    if ip not in managed_ips():
        raise RouterError("只能诊断当前已接管的设备")
    try:
        duration = int(duration)
    except (TypeError, ValueError) as exc:
        raise RouterError("抓包时长无效") from exc
    if duration not in CAPTURE_DURATIONS:
        raise RouterError("抓包时长只能选择 30 秒、1 分钟或 3 分钟")
    if scope not in CAPTURE_SCOPES:
        raise RouterError("抓包范围无效")
    with CAPTURE_LOCK:
        cleanup_captures()
        active = CAPTURE_STATE.get("active")
        if active and active["process"].poll() is None:
            raise RouterError(f"{active['metadata']['ip']} 正在抓包，请等待结束或先停止")
        capture_id = "capture-" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
        capture_path, _ = capture_paths(capture_id)
        scope_label, scope_filter = CAPTURE_SCOPES[scope]
        command = [
            "/usr/bin/prlimit", f"--fsize={CAPTURE_MAX_BYTES}:{CAPTURE_MAX_BYTES}", "--",
            "/usr/bin/tcpdump", "-i", CAPTURE_INTERFACE, "-nn", "-s", "128", "-U",
            "-w", str(capture_path), "host", ip, *scope_filter,
        ]
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        live_command = [
            "/usr/bin/tcpdump", "-i", CAPTURE_INTERFACE, "-nn", "-tt", "-q", "-l",
            "-s", "128", "host", ip, *scope_filter,
        ]
        live_process = subprocess.Popen(
            live_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, start_new_session=True,
        )
        now = int(time.time())
        metadata = {
            "id": capture_id,
            "ip": ip,
            "scope": scope,
            "scope_label": scope_label,
            "duration": duration,
            "status": "running",
            "created_at": now,
            "finished_at": None,
            "expires_at": now + CAPTURE_RETENTION_SECONDS,
            "message": "正在抓取",
        }
        record = {
            "id": capture_id, "process": process, "live_process": live_process,
            "live_packets": 0, "live_lines": deque(maxlen=60), "metadata": metadata,
            "started_monotonic": time.monotonic(), "stop_reason": None,
        }
        CAPTURE_STATE["active"] = record
        write_capture_metadata(metadata)
        threading.Thread(target=capture_live_reader, args=(record,), daemon=True).start()
        threading.Thread(target=capture_monitor, args=(record,), daemon=True).start()
    time.sleep(0.15)
    if process.poll() is not None:
        time.sleep(0.1)
        metadata = read_capture_metadata(capture_paths(capture_id)[1]) or metadata
        raise RouterError("抓包启动失败：" + metadata.get("message", "tcpdump 无法启动"))
    audit("capture_start", ip, "success", f"{capture_id} scope={scope} duration={duration}")
    return {"message": f"已开始抓取 {scope_label}，最长 {duration} 秒", "capture": public_capture(metadata)}


def stop_capture(capture_id):
    with CAPTURE_LOCK:
        active = CAPTURE_STATE.get("active")
        if not active or active["id"] != capture_id or active["process"].poll() is not None:
            raise RouterError("该抓包任务当前没有运行")
        active["stop_reason"] = "manual"
        process = active["process"]
    try:
        process.send_signal(signal.SIGINT)
    except ProcessLookupError:
        pass
    return {"message": "正在停止抓包"}


def list_captures(ip=None):
    if ip is not None:
        ip = validate_ip(ip)
    with CAPTURE_LOCK:
        cleanup_captures()
        records = []
        for metadata_path in CAPTURE_DIR.glob("capture-*.json"):
            metadata = read_capture_metadata(metadata_path)
            if metadata and (ip is None or metadata.get("ip") == ip):
                records.append(public_capture(metadata))
        records.sort(key=lambda item: item.get("created_at") or 0, reverse=True)
        active = CAPTURE_STATE.get("active")
        live = None
        if active and active["process"].poll() is None and (ip is None or active["metadata"]["ip"] == ip):
            live = {
                "id": active["id"],
                "packets": active["live_packets"],
                "lines": list(active["live_lines"]),
                "running": True,
            }
        elif records:
            _, metadata_path = capture_paths(records[0]["id"])
            latest = read_capture_metadata(metadata_path) or {}
            if latest.get("recent_lines"):
                live = {
                    "id": records[0]["id"],
                    "packets": latest.get("live_packets", 0),
                    "lines": latest["recent_lines"],
                    "running": False,
                }
        return {
            "captures": records[:20],
            "active_id": active["id"] if active and active["process"].poll() is None else None,
            "live": live,
            "limits": {"file_bytes": CAPTURE_MAX_BYTES, "total_bytes": CAPTURE_TOTAL_BYTES,
                       "retention_seconds": CAPTURE_RETENTION_SECONDS},
        }


def delete_capture(capture_id):
    with CAPTURE_LOCK:
        active = CAPTURE_STATE.get("active")
        if active and active["id"] == capture_id and active["process"].poll() is None:
            raise RouterError("请先停止正在运行的抓包任务")
        capture_path, metadata_path = capture_paths(capture_id)
        if not metadata_path.exists() and not capture_path.exists():
            raise RouterError("抓包记录不存在")
        capture_path.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
    audit("capture_delete", "", "success", capture_id)
    return {"message": "抓包文件已删除"}


def capture_cleanup_loop():
    while True:
        time.sleep(3600)
        try:
            with CAPTURE_LOCK:
                cleanup_captures()
        except OSError:
            pass


def find(records, **wanted):
    return [record for record in records if all(record.get(key) == value for key, value in wanted.items())]


def normalize_mac(value):
    value = str(value or "").strip().upper()
    parts = value.split(":")
    if len(parts) != 6 or any(len(part) != 2 or any(char not in "0123456789ABCDEF" for char in part) for part in parts):
        raise RouterError("设备 MAC 地址格式无效")
    return value


def load_device_preferences():
    defaults = {"aliases": {}, "favorites": []}
    if not DEVICE_PREFS_PATH.exists():
        return defaults
    try:
        data = json.loads(DEVICE_PREFS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RouterError("设备名称与常用名单读取失败") from exc
    aliases = data.get("aliases", {})
    favorites = data.get("favorites", [])
    if not isinstance(aliases, dict) or not isinstance(favorites, list):
        raise RouterError("设备名称与常用名单格式错误")
    clean_aliases = {}
    clean_favorites = set()
    for mac, alias in aliases.items():
        try:
            normalized = normalize_mac(mac)
        except RouterError:
            continue
        if isinstance(alias, str) and alias.strip():
            clean_aliases[normalized] = alias.strip()[:40]
    for mac in favorites:
        try:
            clean_favorites.add(normalize_mac(mac))
        except RouterError:
            continue
    return {"aliases": clean_aliases, "favorites": sorted(clean_favorites)}


def save_device_preferences(data):
    DEVICE_PREFS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = DEVICE_PREFS_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, DEVICE_PREFS_PATH)


def update_device_preference(mac, alias=None, favorite=None):
    mac = normalize_mac(mac)
    with RouterOS() as api:
        lease = next((item for item in api.print("/ip/dhcp-server/lease")
                      if item.get("mac-address", "").upper() == mac), None)
    if not lease:
        raise RouterError("没有找到该设备的 DHCP 租约")
    with DEVICE_PREFS_LOCK:
        data = load_device_preferences()
        favorites = set(data["favorites"])
        if alias is not None:
            if not isinstance(alias, str):
                raise RouterError("设备名称格式错误")
            alias = alias.strip()
            if len(alias) > 40 or any(ord(char) < 32 for char in alias):
                raise RouterError("设备名称需为 1 至 40 个可见字符")
            if alias:
                data["aliases"][mac] = alias
            else:
                data["aliases"].pop(mac, None)
        if favorite is not None:
            if not isinstance(favorite, bool):
                raise RouterError("常用设备状态格式错误")
            if favorite:
                favorites.add(mac)
            else:
                favorites.discard(mac)
        data["favorites"] = sorted(favorites)
        save_device_preferences(data)
    ip = lease.get("address", "")
    audit("device_preference", ip, "success", f"mac={mac} favorite={favorite} alias_changed={alias is not None}")
    return {"message": "设备信息已保存", "mac": mac}


def routeros_duration_seconds(value):
    """Convert RouterOS durations such as 1w2d3h4m5s to seconds."""
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = 0
    number = ""
    for char in str(value or ""):
        if char.isdigit():
            number += char
        elif char in units and number:
            total += int(number) * units[char]
            number = ""
        elif char not in ".":
            number = ""
    return total


def mask_endpoint(value):
    endpoint = str(value or "").strip()
    if not endpoint:
        return "未建立"
    host, separator, port = endpoint.rpartition(":")
    if not separator:
        host, port = endpoint, ""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        if address.version == 4:
            parts = str(address).split(".")
            host = ".".join(parts[:2] + ["*", "*"])
        else:
            host = f"{address.exploded.split(':')[0]}:{address.exploded.split(':')[1]}::*"
    except ValueError:
        labels = host.split(".")
        host = "*." + ".".join(labels[-2:]) if len(labels) > 2 else host
    return f"{host}:{port}" if port else host


def load_wireguard_events(now=None):
    now = int(now or time.time())
    try:
        events = json.loads(WIREGUARD_EVENTS_PATH.read_text(encoding="utf-8"))
        if not isinstance(events, list):
            events = []
    except (OSError, ValueError, json.JSONDecodeError):
        events = []
    return [item for item in events
            if isinstance(item, dict) and now - int(item.get("timestamp", 0)) <= WIREGUARD_EVENT_RETENTION][
                -WIREGUARD_EVENT_LIMIT:]


def save_wireguard_events(events):
    WIREGUARD_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = WIREGUARD_EVENTS_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(events[-WIREGUARD_EVENT_LIMIT:], ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, WIREGUARD_EVENTS_PATH)


def wireguard_probe(api, target, source):
    if not target:
        return None
    props = {"address": target, "count": "2", "interval": "200ms"}
    if source:
        props["src-address"] = source
    try:
        replies = api.talk("/ping", props)
    except RouterError:
        return {"target": target, "reachable": False, "latency_ms": None}
    latencies = []
    for reply in replies:
        raw = reply.get("time", "")
        try:
            if "ms" in raw:
                milliseconds, remainder = raw.split("ms", 1)
                latency = float(milliseconds)
                if remainder.endswith("us") and remainder[:-2]:
                    latency += float(remainder[:-2]) / 1000
                latencies.append(latency)
            elif raw.endswith("us"):
                latencies.append(float(raw[:-2]) / 1000)
        except ValueError:
            pass
    return {
        "target": target,
        "reachable": bool(latencies),
        "latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
    }


def wireguard_status():
    config = load_config()
    mobile_name = config.get("WIREGUARD_MOBILE_INTERFACE") or "back-to-home-vpn"
    site_name = config.get("WIREGUARD_SITE_INTERFACE") or "wg-home"
    mobile_label = config.get("WIREGUARD_MOBILE_LABEL") or "手机按需回家"
    site_label = config.get("WIREGUARD_SITE_LABEL") or "站点常驻互联"
    site_probe = config.get("WIREGUARD_SITE_PROBE", "")
    site_probe_source = config.get("WIREGUARD_SITE_PROBE_SOURCE", "")
    now = int(time.time())
    with WIREGUARD_STATUS_LOCK:
        with RouterOS() as api:
            interfaces = api.print("/interface/wireguard")
            peers = api.print("/interface/wireguard/peers")
            routes = api.print("/ip/route")
            nat_rules = api.print("/ip/firewall/nat")
            if now - WIREGUARD_STATE["probe_timestamp"] >= 60:
                WIREGUARD_STATE["probe"] = wireguard_probe(api, site_probe, site_probe_source)
                WIREGUARD_STATE["probe_timestamp"] = now

        output = []
        current_states = {}
        for interface in interfaces:
            name = interface.get("name", "")
            if not name:
                continue
            kind = "mobile" if name == mobile_name else "site" if name == site_name else "other"
            label = mobile_label if kind == "mobile" else site_label if kind == "site" else name
            interface_peers = [item for item in peers if item.get("interface") == name]
            peer_rows = []
            active_peers = 0
            latest = None
            rx_bytes = tx_bytes = 0
            for index, peer in enumerate(interface_peers, 1):
                handshake = peer.get("last-handshake", "")
                age = routeros_duration_seconds(handshake) if handshake else None
                active = age is not None and age <= 180
                active_peers += int(active)
                latest = age if age is not None and (latest is None or age < latest) else latest
                rx = int(peer.get("rx", 0) or 0)
                tx = int(peer.get("tx", 0) or 0)
                rx_bytes += rx
                tx_bytes += tx
                endpoint_value = peer.get("current-endpoint-address") or peer.get("endpoint-address", "")
                endpoint_port = peer.get("current-endpoint-port") or peer.get("endpoint-port", "")
                if endpoint_value and endpoint_port:
                    endpoint_value = f"{endpoint_value}:{endpoint_port}"
                peer_rows.append({
                    "name": peer.get("name") or peer.get("comment") or f"对端 {index}",
                    "allowed_address": peer.get("allowed-address", ""),
                    "endpoint": mask_endpoint(endpoint_value),
                    "last_handshake_seconds": age,
                    "active": active,
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                })
            running = interface.get("running") == "true" and interface.get("disabled") != "true"
            if not running:
                state, state_text = "down", "接口未运行"
            elif kind == "mobile":
                state, state_text = ("up", "手机正在连接") if active_peers else ("idle", "待机，等待手机连接")
            elif latest is not None and latest <= 180:
                state, state_text = "up", "链路正常"
            elif latest is not None and latest <= 600:
                state, state_text = "warn", "握手时间偏久"
            else:
                state, state_text = "down", "链路未建立"
            current_states[name] = state
            route_rows = [{
                "destination": route.get("dst-address", ""),
                "gateway": route.get("gateway", ""),
                "active": route.get("active") == "true" and route.get("disabled") != "true",
            } for route in routes if route.get("gateway") == name]
            nat_ready = any(
                rule.get("in-interface") == name and rule.get("disabled") != "true"
                and rule.get("action") in {"masquerade", "src-nat"}
                for rule in nat_rules
            )
            output.append({
                "name": name, "label": label, "kind": kind, "state": state, "state_text": state_text,
                "running": running, "listen_port": interface.get("listen-port", ""), "mtu": interface.get("mtu", ""),
                "peer_total": len(peer_rows), "peer_active": active_peers,
                "last_handshake_seconds": latest, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
                "routes": route_rows, "nat_ready": nat_ready, "peers": peer_rows,
                "probe": WIREGUARD_STATE["probe"] if kind == "site" else None,
            })

        events = load_wireguard_events(now)
        previous = WIREGUARD_STATE["interfaces"]
        for item in output:
            old_state = previous.get(item["name"])
            if old_state and old_state != item["state"]:
                events.append({
                    "timestamp": now, "interface": item["name"], "label": item["label"],
                    "from": old_state, "to": item["state"],
                    "message": f"{item['label']}：{item['state_text']}",
                })
        if events != load_wireguard_events(now):
            save_wireguard_events(events)
        WIREGUARD_STATE["interfaces"] = current_states
        return {"updated_at": now, "interfaces": output, "events": events[-20:]}


def router_summary(api):
    checks = api.print("/tool/netwatch")
    health = next((item for item in checks if item.get("name") == "family-mihomo-tproxy-health"), None)
    router_resource = {"available": False}
    try:
        resources = api.print("/system/resource")
        if resources:
            resource = resources[0]
            total_memory = int(resource.get("total-memory", 0))
            free_memory = int(resource.get("free-memory", 0))
            used_memory = max(0, total_memory - free_memory)
            router_resource = {
                "available": True,
                "cpu_percent": int(resource.get("cpu-load", 0)),
                "cpu_count": int(resource.get("cpu-count", 0)),
                "cpu_frequency": int(resource.get("cpu-frequency", 0)),
                "memory_percent": round(used_memory * 100 / total_memory, 1) if total_memory else 0,
                "memory_used": used_memory,
                "memory_free": free_memory,
                "memory_total": total_memory,
                "uptime": resource.get("uptime", ""),
                "version": resource.get("version", ""),
                "board_name": resource.get("board-name", "RB5009"),
            }
    except (RouterError, TypeError, ValueError):
        pass
    summary = local_health()
    try:
        secret = GATEWAY_SECRET_PATH.read_text(encoding="utf-8").strip()
        request = Request(
            "http://127.0.0.1:18102/metrics",
            headers={"X-Family-Gateway": secret},
        )
        with urlopen(request, timeout=2) as response:
            metrics = json.load(response)
        ranked = {}
        for group in ("domestic", "foreign"):
            candidates = [item for item in metrics.get("upstreams", []) if item.get("group") == group]
            candidates.sort(key=lambda item: (
                float(item.get("error_rate", 100)),
                -int(item.get("winners", 0)) / max(1, int(item.get("queries", 0))),
                float(item.get("average_ms", 999999)),
            ))
            if candidates:
                ranked[group] = candidates[0]
        summary["dns_performance"] = {
            "p95_ms": metrics.get("p95_ms", 0),
            "p99_ms": metrics.get("p99_ms", 0),
            "groups": ranked,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        summary["dns_performance"] = {}
    summary.update({
        "netwatch": health.get("status", "unknown") if health else "missing",
        "router": "connected",
        "router_resource": router_resource,
        "version": BUILD_VERSION,
    })
    return summary


def last_audit_event():
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1]) if lines else None
    except (OSError, json.JSONDecodeError):
        return None


def latest_backup(config):
    root = config.get("BACKUP_ROOT", "").strip()
    if not root:
        return None
    try:
        candidates = [path for path in Path(root).iterdir() if path.is_dir()]
        latest = max(candidates, key=lambda path: path.stat().st_mtime)
        return {"name": latest.name, "time": time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(latest.stat().st_mtime))}
    except (OSError, ValueError):
        return None


def connection_packets(connections, ip):
    packets = 0
    active = 0
    for connection in connections:
        source = connection.get("src-address", "").rsplit(":", 1)[0]
        reply_destination = connection.get("reply-dst-address", "").rsplit(":", 1)[0]
        if source == ip or reply_destination == ip:
            active += 1
            packets += int(connection.get("orig-packets", "0") or 0)
            packets += int(connection.get("repl-packets", "0") or 0)
    return active, packets


def configuration_drift(api, leases, router_managed, file_managed):
    issues = []
    lease_by_ip = {item.get("address"): item for item in leases}
    if router_managed != file_managed:
        issues.append("RouterOS 名单与 Z4Pro 状态文件不一致")
    for ip in sorted(router_managed | file_managed):
        lease = lease_by_ip.get(ip)
        if not lease:
            issues.append(f"{ip} 缺少 DHCP 租约")
            continue
        if lease.get("dhcp-option"):
            issues.append(f"{ip} 仍使用设备专属网关或 DNS")
        mac = lease.get("mac-address", "")
        guard = any(
            item.get("comment") == managed_tag(ip) + " IPv6 bypass guard"
            and item.get("src-mac-address", "").upper() == mac.upper()
            for item in api.print("/ipv6/firewall/filter")
        )
        if not guard:
            issues.append(f"{ip} 缺少 IPv6 防漏规则")
    legacy_lists = {
        item.get("list") for item in api.print("/ip/firewall/address-list")
        if item.get("list", "").startswith("family_mihomo_") and item.get("list") != SHARED_LIST
    }
    if legacy_lists:
        issues.append("仍有旧设备地址列表：" + "、".join(sorted(legacy_lists)))
    return issues


def list_devices():
    with DEVICE_PREFS_LOCK:
        preferences = load_device_preferences()
    favorite_macs = set(preferences["favorites"])
    managed_macs = set()
    with RouterOS() as api:
        leases = api.print("/ip/dhcp-server/lease")
        mangle = api.print("/ip/firewall/mangle")
        connections = api.print("/ip/firewall/connection")
        managed = address_list_managed(api)
        legacy_managed = set()
        for rule in mangle:
            comment = rule.get("comment", "")
            address = policy_address(comment)
            if address:
                legacy_managed.add(address)
        managed |= legacy_managed
        file_managed = managed_ips()
        devices = []
        for lease in leases:
            ip = lease.get("address")
            if not ip or ipaddress.ip_address(ip) not in LAN or ip in RESERVED_IPS:
                continue
            mac = lease.get("mac-address", "").upper()
            if not mac:
                continue
            active_connections, packets = connection_packets(connections, ip)
            is_managed = ip in managed
            if is_managed:
                managed_macs.add(mac)
            router_name = lease.get("host-name") or lease.get("comment") or "未命名设备"
            devices.append({
                "ip": ip,
                "mac": mac,
                "name": preferences["aliases"].get(mac) or router_name,
                "router_name": router_name,
                "custom_name": mac in preferences["aliases"],
                "status": lease.get("status", "unknown"),
                "static": lease.get("dynamic") != "true",
                "managed": is_managed,
                "favorite": is_managed or mac in favorite_macs,
                "fixed": False,
                "packets": packets,
                "connections": active_connections,
                "effective": is_managed and active_connections > 0,
            })
        summary = router_summary(api)
        drift = configuration_drift(api, leases, address_list_managed(api), file_managed)
        upnp = [item for item in api.print("/ip/firewall/nat")
                if item.get("dynamic") == "true" and item.get("comment", "").startswith("upnp ")]
        upnp_settings = api.print("/ip/upnp")
        upnp_enabled = bool(upnp_settings and upnp_settings[0].get("enabled") == "true")
        summary.update({
            "drift": drift,
            "upnp_mappings": len(upnp),
            "upnp_enabled": upnp_enabled,
            "last_change": last_audit_event(),
            "backup": latest_backup(load_config()),
            "ipv6_policy": "纳管设备快速拒绝并回退 IPv4",
        })
    if managed_macs - favorite_macs:
        with DEVICE_PREFS_LOCK:
            latest = load_device_preferences()
            latest["favorites"] = sorted(set(latest["favorites"]) | managed_macs)
            save_device_preferences(latest)
    devices.sort(key=lambda item: (not item["managed"], not item["favorite"], tuple(map(int, item["ip"].split(".")))))
    return {"summary": summary, "devices": devices}


def ensure_table(api, table):
    if not find(api.print("/routing/table"), name=table):
        api.add("/routing/table", name=table, fib="yes")


def ensure_policy_anchors(api):
    anchors = (
        ("/ip/firewall/mangle", "family-mihomo-auto anchor", "prerouting"),
        ("/ip/firewall/nat", "family-mihomo-auto DNS anchor", "dstnat"),
    )
    for path, comment, chain in anchors:
        if not any(item.get("comment") == comment for item in api.print(path)):
            api.add(path, chain=chain, action="accept", disabled="yes", comment=comment)


def ensure_shared_policy(api):
    ensure_table(api, SHARED_TABLE)
    ensure_policy_anchors(api)
    mangle_anchor = rule_id(api, "/ip/firewall/mangle", "family-mihomo-auto anchor")
    nat_anchor = rule_id(api, "/ip/firewall/nat", "family-mihomo-auto DNS anchor")

    if not any(item.get("comment") == SHARED_TAG + " route" for item in api.print("/ip/route")):
        api.add("/ip/route", **{
            "dst-address": "0.0.0.0/0", "gateway": PROXY_IP, "routing-table": SHARED_TABLE,
            "check-gateway": "ping", "comment": SHARED_TAG + " route",
        })

    mangle = api.print("/ip/firewall/mangle")
    if not any(item.get("comment") == SHARED_TAG + " route to z4pro" for item in mangle):
        route_id = add_before(api, "/ip/firewall/mangle", mangle_anchor,
                              chain="prerouting", action="mark-routing",
                              **{"new-routing-mark": SHARED_TABLE, "passthrough": "no",
                                 "src-address-list": SHARED_LIST,
                                 "connection-mark": SHARED_CONN_MARK,
                                 "comment": SHARED_TAG + " route to z4pro"})
        mark_id = add_before(api, "/ip/firewall/mangle", route_id,
                             chain="prerouting", action="mark-connection",
                             **{"new-connection-mark": SHARED_CONN_MARK, "passthrough": "yes",
                                "src-address-list": SHARED_LIST,
                                "dst-address-list": "!local_lan_ipv4",
                                "connection-mark": "no-mark",
                                "comment": SHARED_TAG + " mark connection"})
        add_before(api, "/ip/firewall/mangle", mark_id,
                   chain="prerouting", action="accept",
                   **{"src-address-list": SHARED_LIST,
                      "dst-address-list": "local_lan_ipv4",
                      "comment": SHARED_TAG + " local bypass"})

    nat = api.print("/ip/firewall/nat")
    if not any(item.get("comment") == SHARED_TAG + " DNS TCP" for item in nat):
        tcp_id = add_before(api, "/ip/firewall/nat", nat_anchor,
                            chain="dstnat", action="dst-nat", protocol="tcp",
                            **{"src-address-list": SHARED_LIST, "dst-port": "53",
                               "to-addresses": PROXY_IP, "to-ports": "53",
                               "comment": SHARED_TAG + " DNS TCP"})
        add_before(api, "/ip/firewall/nat", tcp_id,
                   chain="dstnat", action="dst-nat", protocol="udp",
                   **{"src-address-list": SHARED_LIST, "dst-port": "53",
                      "to-addresses": PROXY_IP, "to-ports": "53",
                      "comment": SHARED_TAG + " DNS UDP"})

    filters = api.print("/ip/firewall/filter")
    if not any(item.get("comment") == SHARED_TAG + " FastTrack exclude" for item in filters):
        fasttrack = next((rule for rule in filters if rule.get("action") == "fasttrack-connection"), None)
        api.add("/ip/firewall/filter", chain="forward", action="accept", **{
            "connection-mark": SHARED_CONN_MARK, "comment": SHARED_TAG + " FastTrack exclude",
        })
        exclude = next((rule for rule in api.print("/ip/firewall/filter")
                        if rule.get("comment") == SHARED_TAG + " FastTrack exclude"), None)
        if exclude and fasttrack:
            api.talk("/ip/firewall/filter/move", {
                "numbers": exclude[".id"], "destination": fasttrack[".id"]})

    filters = api.print("/ip/firewall/filter")
    exclude = next((rule for rule in filters
                    if rule.get("comment") == SHARED_TAG + " FastTrack exclude"), None)
    quic_comment = SHARED_TAG + " QUIC fast fallback"
    quic_rule = next((rule for rule in filters if rule.get("comment") == quic_comment), None)
    quic_props = {
        "chain": "forward", "action": "reject", "reject-with": "icmp-port-unreachable",
        "protocol": "udp", "src-address-list": SHARED_LIST,
        "dst-address-list": "!local_lan_ipv4", "dst-port": "443", "comment": quic_comment,
    }
    if not quic_rule:
        api.add("/ip/firewall/filter", **quic_props)
        quic_rule = next((rule for rule in api.print("/ip/firewall/filter")
                          if rule.get("comment") == quic_comment), None)
    else:
        api.set("/ip/firewall/filter", quic_rule[".id"], **quic_props)
    if quic_rule and exclude:
        api.talk("/ip/firewall/filter/move", {
            "numbers": quic_rule[".id"], "destination": exclude[".id"]})

    ipv6_filters = api.print("/ipv6/firewall/filter")
    ipv6_guard = next((rule for rule in ipv6_filters
                       if rule.get("comment") == "family-mihomo-auto IPv6 drop"), None)
    if not ipv6_guard:
        api.add("/ipv6/firewall/filter", chain="family_mihomo_auto_v6",
                action="reject", **{"reject-with": "icmp-admin-prohibited",
                                    "comment": "family-mihomo-auto IPv6 drop"})
    elif (ipv6_guard.get("action") != "reject"
          or ipv6_guard.get("reject-with") != "icmp-admin-prohibited"):
        api.set("/ipv6/firewall/filter", ipv6_guard[".id"], action="reject",
                **{"reject-with": "icmp-admin-prohibited"})


def rule_id(api, path, comment):
    matches = [item for item in api.print(path) if item.get("comment") == comment]
    if not matches:
        raise RouterError(f"缺少策略锚点：{comment}")
    return matches[-1][".id"]


def add_before(api, path, destination, **props):
    api.add(path, **props)
    matches = [item for item in api.print(path) if item.get("comment") == props.get("comment")]
    item_id = matches[-1][".id"] if matches else None
    if item_id:
        api.talk(path + "/move", {"numbers": item_id, "destination": destination})
    return item_id


def clear_device_connections(api, ip):
    removed = 0
    for connection in api.print("/ip/firewall/connection"):
        source = connection.get("src-address", "").rsplit(":", 1)[0]
        reply_destination = connection.get("reply-dst-address", "").rsplit(":", 1)[0]
        if source == ip or reply_destination == ip:
            api.remove("/ip/firewall/connection", connection[".id"])
            removed += 1
    return removed


def cleanup_device_rules(api, ip):
    tags = (managed_tag(ip), legacy_tag(ip))
    tables = (f"family_mihomo_auto_{ip.rsplit('.', 1)[1]}", f"family_mihomo_{ip.rsplit('.', 1)[1]}")
    removed = 0
    for path in ("/ip/firewall/mangle", "/ip/firewall/nat", "/ip/firewall/filter",
                 "/ipv6/firewall/filter", "/ip/route"):
        for item in api.print(path):
            if item.get("comment", "").startswith(tags):
                api.remove(path, item[".id"])
                removed += 1
    for item in api.print("/routing/table"):
        if item.get("name") in tables:
            api.remove("/routing/table", item[".id"])
            removed += 1
    clear_device_connections(api, ip)
    return removed


def remove_shared_membership(api, ip):
    removed = 0
    for item in api.print("/ip/firewall/address-list"):
        if item.get("list") == SHARED_LIST and item.get("address") == ip:
            api.remove("/ip/firewall/address-list", item[".id"])
            removed += 1
    tag = managed_tag(ip) + " IPv6 bypass guard"
    for item in api.print("/ipv6/firewall/filter"):
        if item.get("comment") == tag:
            api.remove("/ipv6/firewall/filter", item[".id"])
            removed += 1
    return removed


def conflicting_policy(api, ip):
    memberships = set()
    address = ipaddress.ip_address(ip)
    for item in api.print("/ip/firewall/address-list"):
        try:
            if address in ipaddress.ip_network(item.get("address", ""), strict=False) and item.get("list"):
                memberships.add(item["list"])
        except ValueError:
            continue
    for rule in api.print("/ip/firewall/mangle"):
        if rule.get("disabled") == "true" or rule.get("comment", "").startswith("family-mihomo-"):
            continue
        if rule.get("action") not in {"mark-routing", "mark-connection"}:
            continue
        direct_match = rule.get("src-address") == ip
        list_match = rule.get("src-address-list") in memberships
        if direct_match or list_match:
            return rule.get("comment") or rule.get("new-routing-mark") or "其它策略路由"
    return None


def verify_device_rules(api, ip):
    missing = []
    membership = any(item.get("list") == SHARED_LIST and item.get("address") == ip
                     for item in api.print("/ip/firewall/address-list"))
    if not membership:
        missing.append("设备名单")
    expected = (
        ("/ip/firewall/mangle", 3),
        ("/ip/firewall/nat", 2),
        ("/ip/firewall/filter", 1),
        ("/ip/route", 1),
    )
    for path, count in expected:
        actual = sum(item.get("comment", "").startswith(SHARED_TAG) for item in api.print(path))
        if actual < count:
            missing.append(f"{path}:{actual}/{count}")
    guard = sum(item.get("comment") == managed_tag(ip) + " IPv6 bypass guard"
                for item in api.print("/ipv6/firewall/filter"))
    if guard != 1:
        missing.append(f"IPv6 防漏:{guard}/1")
    if missing:
        raise RouterError("规则创建不完整：" + ", ".join(missing))


def enable_device(ip):
    ip = validate_ip(ip)
    tag = managed_tag(ip)
    health = local_health()
    if not health["ready"]:
        raise RouterError("Z4Pro 复合健康检查未通过，未创建任何规则")
    with RouterOS() as api:
        leases = find(api.print("/ip/dhcp-server/lease"), address=ip)
        if not leases:
            raise RouterError("未找到该 IP 的 DHCP 租约；请先让设备重新连接 Wi-Fi")
        lease = leases[0]
        mac = lease.get("mac-address")
        if not mac:
            raise RouterError("该 DHCP 租约没有 MAC 地址")
        if ip in address_list_managed(api):
            raise RouterError("该设备已由页面管理")
        conflict = conflicting_policy(api, ip)
        if conflict:
            raise RouterError(f"设备仍命中其它策略：{conflict}；请先解除冲突")

        if lease.get("dynamic") == "true":
            api.talk("/ip/dhcp-server/lease/make-static", {".id": lease[".id"]})
        try:
            ensure_shared_policy(api)
            api.add("/ip/firewall/address-list", list=SHARED_LIST, address=ip,
                    comment="family-mihomo-managed " + ip)
            api.add("/ipv6/firewall/filter", chain="forward", action="jump", **{
                "jump-target": "family_mihomo_auto_v6", "src-mac-address": mac,
                "comment": tag + " IPv6 bypass guard",
            })
            verify_device_rules(api, ip)
            addresses = managed_ips()
            addresses.add(ip)
            save_managed_ips(addresses)
            sync_tproxy()
            cleared = clear_device_connections(api, ip)
            audit("enable", ip, "success", f"cleared_connections={cleared}")
        except (RouterError, OSError) as exc:
            remove_shared_membership(api, ip)
            addresses = managed_ips()
            addresses.discard(ip)
            save_managed_ips(addresses)
            try:
                sync_tproxy()
            except RouterError:
                pass
            audit("enable", ip, "rolled_back", str(exc))
            raise
        return {"ip": ip, "message": "已加入旁路并通过规则校验；旧连接已清理，请重新打开应用验证"}


def remove_device(ip):
    ip = validate_ip(ip)
    with RouterOS() as api:
        removed = remove_shared_membership(api, ip)
        removed += cleanup_device_rules(api, ip)
        addresses = managed_ips()
        addresses.discard(ip)
        save_managed_ips(addresses)
        sync_tproxy()
        audit("remove", ip, "success", f"removed_rules={removed}")
        return {"ip": ip, "message": f"已移除 {removed} 条页面管理规则，设备恢复直连"}


def cpu_sample():
    fields = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields), idle


def temperature_status():
    try:
        result = subprocess.run(["sensors", "-j"], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return {"cpu_c": None, "nvme_c": None, "hdd": hdd_temperature_status()}
    if result.returncode:
        return {"cpu_c": None, "nvme_c": None, "hdd": hdd_temperature_status()}
    try:
        document = json.loads(result.stdout)
    except (TypeError, ValueError):
        return {"cpu_c": None, "nvme_c": None, "hdd": hdd_temperature_status()}

    def reading(chip_prefix, feature_name):
        for chip, features in document.items():
            if not chip.startswith(chip_prefix):
                continue
            feature = features.get(feature_name, {})
            for key, value in feature.items():
                if key.endswith("_input"):
                    return round(float(value), 1)
        return None

    return {
        "cpu_c": reading("coretemp-", "Package id 0"),
        "nvme_c": reading("nvme-", "Composite"),
        "hdd": hdd_temperature_status(),
    }


def hdd_temperature_status():
    """Return rotating-disk SMART temperatures, with a modest read-rate limit."""
    now = time.monotonic()
    cached = HDD_TEMPERATURE_CACHE.get("value")
    if cached is not None and now - HDD_TEMPERATURE_CACHE["timestamp"] < 30:
        return list(cached)
    disks = []
    try:
        listed = subprocess.run(
            ["lsblk", "--json", "-d", "-o", "NAME,MODEL,ROTA,TYPE"],
            capture_output=True, text=True, timeout=3,
        )
        for item in json.loads(listed.stdout).get("blockdevices", []):
            if item.get("type") == "disk" and item.get("rota") in (True, 1, "1"):
                disks.append((str(item.get("name")), str(item.get("model") or "机械盘").strip()))
    except (OSError, ValueError, subprocess.SubprocessError):
        disks = []

    readings = []
    for name, model in disks:
        try:
            result = subprocess.run(["smartctl", "-A", "-j", f"/dev/{name}"],
                                    capture_output=True, text=True, timeout=4)
            table = json.loads(result.stdout).get("ata_smart_attributes", {}).get("table", [])
            attributes = {item.get("id"): item for item in table}
            attribute = attributes.get(194) or attributes.get(190)
            raw_data = (attribute or {}).get("raw", {})
            raw = str(raw_data.get("string") or raw_data.get("value", ""))
            match = re.search(r"\d+", raw)
            if match:
                readings.append({"name": name, "model": model, "temperature_c": int(match.group())})
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    HDD_TEMPERATURE_CACHE.update({"timestamp": now, "value": readings})
    return list(readings)


def docker_status():
    result = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{json .}}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode:
        return {"running": None, "total": None, "unhealthy": None}
    containers = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    running = sum(item.get("State") == "running" for item in containers)
    unhealthy = sum("unhealthy" in item.get("Status", "").lower() for item in containers)
    return {"running": running, "total": len(containers), "unhealthy": unhealthy}


def system_status():
    with SYSTEM_STATUS_LOCK:
        now = time.monotonic()
        cached = SYSTEM_STATUS_CACHE.get("value")
        if cached and now - SYSTEM_STATUS_CACHE["timestamp"] < 5:
            return dict(cached)

        previous = SYSTEM_STATUS_CACHE.get("cpu_sample")
        current = cpu_sample()
        if previous is None:
            time.sleep(0.12)
            previous, current = current, cpu_sample()
        total_delta = current[0] - previous[0]
        idle_delta = current[1] - previous[1]
        cpu_percent = round(max(0.0, min(100.0, 100 * (total_delta - idle_delta) / total_delta)), 1) if total_delta else 0.0
        SYSTEM_STATUS_CACHE["cpu_sample"] = current

        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0]) * 1024
        memory_total = memory["MemTotal"]
        memory_used = memory_total - memory.get("MemAvailable", memory.get("MemFree", 0))
        swap_total = memory.get("SwapTotal", 0)
        swap_used = max(0, swap_total - memory.get("SwapFree", 0))
        load_1m, load_5m, load_15m = os.getloadavg()
        uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
        disk = shutil.disk_usage(MIHOMO_CONFIG_PATH.parent.parent)
        temperatures = temperature_status()
        containers = docker_status()
        memory_percent = round(memory_used / memory_total * 100, 1)
        disk_percent = round(disk.used / disk.total * 100, 1)
        swap_percent = round(swap_used / swap_total * 100, 1) if swap_total else 0.0
        healthy = (
            cpu_percent < 95 and memory_percent < 90 and disk_percent < 90
            and (temperatures["cpu_c"] is None or temperatures["cpu_c"] < 85)
            and (temperatures["nvme_c"] is None or temperatures["nvme_c"] < 75)
            and all(item["temperature_c"] < 60 for item in temperatures["hdd"])
            and not containers.get("unhealthy")
        )
        value = {
            "healthy": healthy,
            "cpu": {"percent": cpu_percent, "cores": os.cpu_count() or 0,
                    "load_1m": round(load_1m, 2), "load_5m": round(load_5m, 2), "load_15m": round(load_15m, 2)},
            "memory": {"used": memory_used, "total": memory_total, "percent": memory_percent,
                       "swap_used": swap_used, "swap_total": swap_total, "swap_percent": swap_percent},
            "temperature": temperatures,
            "disk": {"used": disk.used, "total": disk.total, "free": disk.free, "percent": disk_percent},
            "docker": containers,
            "uptime_seconds": uptime_seconds,
            "kernel": os.uname().release,
            "updated_at": int(time.time()),
        }
        SYSTEM_STATUS_CACHE.update({"timestamp": now, "value": value})
        return dict(value)


PAGE = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>家庭旁路设备管理</title><style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#15191d;color:#eef2f4}*{box-sizing:border-box}body{margin:0}.wrap{max-width:980px;margin:auto;padding:34px 22px}header{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;border-bottom:1px solid #394249;padding-bottom:22px;flex-wrap:wrap}h1{margin:0;font-size:25px;letter-spacing:0}p{color:#aeb9bf;margin:8px 0 0;line-height:1.55}.badge{white-space:nowrap;border:1px solid #3b805f;background:#173527;color:#9fe1b8;padding:7px 10px;border-radius:5px;font-size:13px}.badge.bad{border-color:#8b4945;background:#3b211f;color:#ffb4aa}.health-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-top:18px}.health-item{padding:11px 12px;border-top:2px solid #3b805f;background:#1b2125}.health-item.bad{border-color:#a4514b}.health-item b{display:block;font-size:13px}.health-item span{display:block;margin-top:4px;color:#97a4aa;font-size:12px}.panel{margin-top:22px;border:1px solid #394249;background:#20262b;border-radius:7px;padding:20px}h2{font-size:16px;margin:0 0 14px}.add{display:flex;gap:10px;align-items:center}input{background:#101417;border:1px solid #4b5961;color:#fff;border-radius:4px;padding:10px 12px;font-size:15px;width:220px}button{border:0;border-radius:4px;padding:10px 14px;font-weight:650;cursor:pointer;background:#62c77c;color:#092212;font-size:14px}button.remove{background:#2a3035;border:1px solid #626e75;color:#e4ebee}button:disabled{opacity:.5;cursor:default}.note{font-size:13px;margin-top:10px}.status{min-height:22px;margin-top:12px;font-size:14px}.error{color:#ffb4aa}.ok{color:#9fe1b8}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:13px 8px;border-top:1px solid #354048}th{color:#aeb9bf;font-weight:600}td:last-child{text-align:right}.muted{color:#94a1a8}.state{display:inline-block;font-size:12px;border:1px solid #4b5961;padding:3px 7px;border-radius:4px}.state.active{border-color:#3b805f;color:#9fe1b8}.state.wait{border-color:#8e7a44;color:#e7cd81}@media(max-width:650px){.wrap{padding:22px 14px}header{display:block}.badge{display:inline-block;margin-top:14px}.health-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.panel{padding:15px}.add{align-items:stretch;flex-direction:column}input{width:100%}table th:nth-child(2),table td:nth-child(2){display:none}table{font-size:13px}}</style><body><main class="wrap"><header><div><h1>家庭旁路设备管理</h1><p>加入、验证、撤出均按单台设备执行，不改全屋网关和公网服务。</p></div><span class="badge" id="health">连接检查中</span></header><div class="health-grid" id="healthChecks"></div><section class="panel"><h2>加入旁路</h2><div class="add"><input id="ip" inputmode="decimal" placeholder="__FAMILY_LAN_PREFIX__x"><button onclick="enableDevice()">加入并校验</button></div><p class="note">系统先检查 Z4Pro、DNS、策略组和冲突策略；失败会清理本次创建的规则。设备需已有 DHCP 租约。</p><div class="status" id="status"></div></section><section class="panel"><h2>设备列表</h2><table><thead><tr><th>设备</th><th>MAC 地址</th><th>在线</th><th>实际状态</th><th></th></tr></thead><tbody id="devices"></tbody></table></section></main><script>
const csrf="__CSRF__",statusEl=document.querySelector('#status');function setStatus(msg,ok){statusEl.textContent=msg;statusEl.className='status '+(ok?'ok':'error')}async function api(path,opt={}){let r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf,...(opt.headers||{})}}),b=await r.json();if(!r.ok)throw Error(b.error||'请求失败');return b}function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}function healthItem(name,ok,text){return `<div class="health-item ${ok?'':'bad'}"><b>${name}</b><span>${text}</span></div>`}async function load(){try{let data=await api('/api/devices'),s=data.summary,c=s.checks||{};let ready=s.ready&&s.netwatch==='up';let badge=document.querySelector('#health');badge.textContent=ready?'旁路平面正常':'旁路平面需检查';badge.className='badge '+(ready?'':'bad');document.querySelector('#healthChecks').innerHTML=healthItem('RB5009',s.router==='connected','管理连接')+healthItem('DNS',c.dns,'国内解析')+healthItem('Mihomo',c.mihomo,'控制接口')+healthItem('策略组',c.policy,s.detail?.proxy||'未就绪')+healthItem('自动回退',s.netwatch==='up',s.netwatch);let rows=data.devices.map(d=>{let label=!d.managed?'未接管':d.effective?'已生效':'等待新流量',state=!d.managed?'':d.effective?'active':'wait',action=d.fixed?'<span class="muted">固定灰度</span>':d.managed?`<button class="remove" onclick="removeDevice('${d.ip}')">恢复直连</button>`:`<button class="remove" onclick="choose('${d.ip}')">选择</button>`;return `<tr><td>${esc(d.name)}<div class="muted">${d.ip}${d.static?' · 固定':''}</div></td><td class="muted">${esc(d.mac)}</td><td>${esc(d.status)}</td><td><span class="state ${state}">${label}</span>${d.managed?`<div class="muted">${d.packets} 个包</div>`:''}</td><td>${action}</td></tr>`}).join('');document.querySelector('#devices').innerHTML=rows||'<tr><td colspan="5" class="muted">未发现 DHCP 设备</td></tr>'}catch(e){setStatus(e.message,false)}}function choose(ip){document.querySelector('#ip').value=ip;document.querySelector('#ip').focus()}async function enableDevice(){let ip=document.querySelector('#ip').value.trim();try{setStatus('正在执行健康检查、冲突检查和规则事务...',true);let r=await api('/api/enable',{method:'POST',body:JSON.stringify({ip})});setStatus(r.message,true);await load()}catch(e){setStatus(e.message,false)}}async function removeDevice(ip){if(!confirm('将 '+ip+' 恢复直连并清理旧连接？'))return;try{setStatus('正在恢复直连...',true);let r=await api('/api/remove',{method:'POST',body:JSON.stringify({ip})});setStatus(r.message,true);await load()}catch(e){setStatus(e.message,false)}}load();setInterval(load,30000)</script></body></html>"""


MIHOMO_PAGE = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mihomo 节点管理</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#15191d;color:#eef2f4}*{box-sizing:border-box}body{margin:0}.wrap{max-width:760px;margin:auto;padding:34px 22px}a{color:#9fe1b8;text-decoration:none}h1{font-size:24px;margin:18px 0 0}.sub{color:#aeb9bf;margin:8px 0 24px}.panel{border:1px solid #394249;background:#20262b;border-radius:7px;padding:18px;margin-top:14px}.row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}h2{font-size:16px;margin:0}.current{color:#9fe1b8;font-size:14px;margin-top:4px}select{min-width:270px;flex:1;background:#101417;border:1px solid #4b5961;color:#fff;border-radius:4px;padding:10px;font-size:14px}button{background:#62c77c;color:#092212;border:0;border-radius:4px;padding:10px 14px;font-weight:650;cursor:pointer}.status{min-height:22px;margin-top:16px;color:#aeb9bf}.error{color:#ffb4aa}@media(max-width:600px){.wrap{padding:22px 14px}.row{align-items:stretch;flex-direction:column}select{min-width:0}}</style><body><main class="wrap"><a href="/">← 设备管理</a><h1>Mihomo 节点管理</h1><p class="sub">切换仅影响对应策略组；AI 组不包含香港节点。</p><div id="groups"></div><div class="status" id="status"></div></main><script>const csrf="__CSRF__";const status=document.querySelector('#status');function esc(s){return String(s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}async function req(path,opt={}){let r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}});let d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}async function load(){try{let d=await req('/api/mihomo');document.querySelector('#groups').innerHTML=d.groups.map(g=>`<section class="panel"><div class="row"><div><h2>${esc(g.name)}</h2><div class="current">当前：${esc(g.now||'未选择')}</div></div><select id="group-${esc(g.name)}">${g.all.map(n=>`<option ${n===g.now?'selected':''}>${esc(n)}</option>`).join('')}</select><button onclick="choose('${esc(g.name)}')">切换</button></div></section>`).join('')}catch(e){status.textContent=e.message;status.className='status error'}}async function choose(group){try{let node=document.querySelector('#group-'+group).value;let d=await req('/api/mihomo/select',{method:'POST',body:JSON.stringify({group,node})});status.textContent=d.message;status.className='status';await load()}catch(e){status.textContent=e.message;status.className='status error'}}load()</script></body></html>"""


PAGE = (PAGE
    .replace("h2{font-size:16px", ".panel-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px}.panel-head h2{margin:0}.filters{display:flex;gap:4px}.filters button{padding:6px 9px;background:#2a3035;border:1px solid #4b5961;color:#c7d0d5;font-size:12px}.filters button.active{background:#3b805f;border-color:#62c77c;color:#fff}h2{font-size:16px", 1)
    .replace('<section class="panel"><h2>设备列表</h2>', '<section class="panel"><div class="panel-head"><h2>设备列表</h2><div class="filters"><button data-device-filter="managed" class="active" onclick="setDeviceFilter(\'managed\')">已接管</button><button data-device-filter="online" onclick="setDeviceFilter(\'online\')">在线</button><button data-device-filter="all" onclick="setDeviceFilter(\'all\')">全部</button></div></div>', 1)
    .replace("</script></body></html>", "</script><script>let deviceFilter='managed';function applyDeviceFilter(){document.querySelectorAll('#devices tr').forEach(row=>{let cells=row.cells;if(cells.length<4)return;let managed=cells[3].textContent.includes('已生效')||cells[3].textContent.includes('等待新流量');let online=cells[2].textContent.trim()==='bound';row.hidden=!(deviceFilter==='all'||deviceFilter==='managed'&&managed||deviceFilter==='online'&&online)})}function setDeviceFilter(value){deviceFilter=value;document.querySelectorAll('[data-device-filter]').forEach(button=>button.classList.toggle('active',button.dataset.deviceFilter===value));applyDeviceFilter()}new MutationObserver(applyDeviceFilter).observe(document.querySelector('#devices'),{childList:true})</script></body></html>", 1))
MIHOMO_PAGE = MIHOMO_PAGE.replace('<meta name="viewport" content="width=device-width,initial-scale=1">', '<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">', 1)


PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>家庭旁路</title><style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","PingFang SC","Segoe UI",sans-serif;background:#000;color:#f5f5f7;letter-spacing:0}*{box-sizing:border-box}body{margin:0;background:#000;color:#f5f5f7}.topbar{position:sticky;top:0;z-index:10;border-bottom:1px solid rgba(255,255,255,.1);background:rgba(18,18,20,.88);backdrop-filter:saturate(180%) blur(22px);-webkit-backdrop-filter:saturate(180%) blur(22px)}.topbar-inner{max-width:1040px;height:58px;margin:auto;padding:0 22px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-size:17px;font-weight:650;color:#fff;white-space:nowrap}.nav{display:flex;align-items:center;gap:4px;padding:3px;background:#2c2c2e;border-radius:8px}.nav a{padding:7px 11px;border-radius:6px;color:#aeaeb2;text-decoration:none;font-size:13px;white-space:nowrap}.nav a.active{background:#636366;color:#fff}.wrap{max-width:1040px;margin:auto;padding:38px 22px 64px}.intro{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:25px}.eyebrow{font-size:13px;color:#8e8e93;margin-bottom:7px}.intro h1{font-size:30px;line-height:1.15;margin:0;font-weight:700;letter-spacing:0}.intro p{margin:9px 0 0;color:#98989d;font-size:14px}.overall{display:flex;align-items:center;gap:8px;padding:8px 11px;border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;color:#30d158;font-size:13px;white-space:nowrap}.overall.bad{color:#ff453a}.dot{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 0 3px color-mix(in srgb,currentColor 16%,transparent)}.section{margin-top:26px}.section-title{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:0 2px 9px}.section-title h2{font-size:13px;text-transform:none;color:#8e8e93;font-weight:600;margin:0}.group{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.health-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr))}.health-item{min-width:0;padding:16px;border-right:1px solid #38383a}.health-item:last-child{border-right:0}.health-item b{display:flex;align-items:center;gap:7px;font-size:14px;font-weight:600}.health-item b:before{content:"";width:7px;height:7px;border-radius:50%;background:#30d158;flex:0 0 auto}.health-item.bad b:before{background:#ff453a}.health-item span{display:block;margin:6px 0 0 14px;color:#8e8e93;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.add-row{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;padding:15px 16px}.field{min-width:0}.field label{display:block;font-size:14px;font-weight:600;margin-bottom:5px}.field input{width:100%;height:38px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:15px inherit;outline:none}.field input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}button{font:600 14px inherit;letter-spacing:0;cursor:pointer}.primary{height:38px;border:0;border-radius:7px;background:#0a84ff;color:#fff;padding:0 15px}.primary:hover{background:#409cff}.secondary{border:0;background:transparent;color:#0a84ff;padding:7px 8px;border-radius:6px}.secondary:hover{background:rgba(10,132,255,.12)}.secondary:disabled{color:#636366;cursor:default;background:transparent}.danger{color:#ff453a}.help{padding:0 16px 15px;color:#8e8e93;font-size:12px;line-height:1.5}.status{min-height:0;margin:0 16px 15px;padding:10px 12px;border-radius:7px;background:#2c2c2e;color:#30d158;font-size:13px}.status:empty{display:none}.status.error{color:#ff6961}.device-controls{display:flex;align-items:center;gap:8px}.device-search{width:210px;height:32px;border:1px solid #48484a;border-radius:7px;background:#1c1c1e;color:#fff;padding:0 10px;font:13px inherit;outline:none}.device-search:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.18)}.segment{display:flex;padding:2px;background:#2c2c2e;border-radius:7px}.segment button{border:0;background:transparent;color:#aeaeb2;border-radius:5px;padding:6px 9px;font-size:12px}.segment button.active{background:#636366;color:#fff}.device-list{min-height:54px}.device-row{display:grid;grid-template-columns:minmax(170px,1.3fr) minmax(130px,.9fr) 72px minmax(112px,.7fr) minmax(185px,auto);align-items:center;gap:12px;padding:13px 16px;border-top:1px solid #38383a}.device-row:first-child{border-top:0}.device-name{font-size:14px;font-weight:600;min-width:0}.device-meta,.muted{color:#8e8e93;font-size:12px;margin-top:4px;overflow-wrap:anywhere}.online{font-size:13px;color:#aeaeb2}.online.bound{color:#30d158}.state{font-size:13px;color:#aeaeb2}.state.active{color:#30d158}.state.wait{color:#ffd60a}.device-action{display:flex;justify-content:flex-end;align-items:center;gap:2px;flex-wrap:wrap}.empty{padding:24px 16px;text-align:center;color:#8e8e93;font-size:13px}dialog{width:min(420px,calc(100% - 28px));border:1px solid #48484a;border-radius:8px;background:#1c1c1e;color:#f5f5f7;padding:0;box-shadow:0 24px 70px rgba(0,0,0,.55)}dialog::backdrop{background:rgba(0,0,0,.68)}.dialog-body{padding:20px}.dialog-body h2{margin:0;font-size:18px}.dialog-body p{font-size:13px}.dialog-body input{width:100%;height:40px;margin-top:16px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;outline:none}.dialog-body input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}.dialog-actions{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px;border-top:1px solid #38383a}.dialog-actions button{height:36px;border:0;border-radius:7px;padding:0 14px}.dialog-cancel{background:#2c2c2e;color:#f5f5f7}.dialog-save{background:#0a84ff;color:#fff}@media(max-width:760px){.topbar-inner{height:auto;min-height:58px;padding:10px 14px;align-items:flex-start;flex-direction:column;gap:8px}.nav{width:100%;display:grid;grid-template-columns:repeat(3,1fr)}.nav a{text-align:center;padding:7px 5px}.wrap{padding:28px 14px 50px}.intro{align-items:flex-start;flex-direction:column}.health-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.health-item{border-bottom:1px solid #38383a}.health-item:nth-child(2n){border-right:0}.health-item:last-child{border-bottom:0}.add-row{grid-template-columns:1fr}.primary{width:100%}.device-row{grid-template-columns:1fr auto;gap:8px}.device-mac{display:none}.device-online{grid-column:1}.device-state{grid-column:1}.device-action{grid-column:2;grid-row:1/4;max-width:145px}.section-title{align-items:stretch;flex-direction:column}.device-controls{align-items:stretch;flex-direction:column}.device-search{width:100%}.segment{width:100%;display:grid;grid-template-columns:repeat(3,1fr)}.segment button{width:100%}}
</style></head><body><header class="topbar"><div class="topbar-inner"><div class="brand">家庭旁路</div><nav class="nav"><a class="active" href="/">设备</a><a href="/rules">规则</a><a href="/airport/">机场与候选池</a></nav></div></header><main class="wrap"><div class="intro"><div><div class="eyebrow">SELECTIVE ROUTING</div><h1>设备管理</h1><p>只接管需要旁路的设备，其余家庭网络保持原样。</p></div><div class="overall" id="health"><span class="dot"></span><span>正在检查</span></div></div><section class="section"><div class="section-title"><h2>运行状态</h2></div><div class="group health-grid" id="healthChecks"></div></section><section class="section"><div class="section-title"><h2>加入旁路</h2></div><div class="group"><div class="add-row"><div class="field"><label for="ip">设备 IP 地址</label><input id="ip" inputmode="decimal" autocomplete="off" placeholder="__FAMILY_LAN_PREFIX__x"></div><button class="primary" onclick="enableDevice()">加入并校验</button></div><div class="help">系统会检查健康状态与规则冲突。也可以先在“全部在线”中找到设备，再加入旁路。</div><div class="status" id="status"></div></div></section><section class="section"><div class="section-title"><h2>设备</h2><div class="device-controls"><input id="deviceSearch" class="device-search" type="search" autocomplete="off" placeholder="搜索名称、IP 或 MAC"><div class="segment"><button data-filter="managed" class="active" onclick="setFilter('managed')">已接管</button><button data-filter="favorites" onclick="setFilter('favorites')">常用设备</button><button data-filter="online" onclick="setFilter('online')">全部在线</button></div></div></div><div class="group device-list" id="devices"><div class="empty">正在载入设备</div></div></section></main><dialog id="renameDialog"><form onsubmit="saveRename(event)"><div class="dialog-body"><h2>修改设备名称</h2><p>名称只保存在家庭旁路页面；留空保存可恢复路由器中的原名称。</p><input id="renameInput" maxlength="40" autocomplete="off" placeholder="输入设备名称"></div><div class="dialog-actions"><button type="button" class="dialog-cancel" onclick="closeRename()">取消</button><button type="submit" class="dialog-save">保存</button></div></form></dialog><script>
const csrf="__CSRF__",statusEl=document.querySelector('#status');let filter='managed',devices=[],deviceQuery='',editingMac='';function esc(s){return String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}function setStatus(message,ok=true){statusEl.textContent=message;statusEl.className='status '+(ok?'':'error')}async function api(path,opt={}){let response=await fetch(new URL(path,location.origin),{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf,...(opt.headers||{})}}),body=await response.json();if(!response.ok)throw Error(body.error||'请求失败');return body}function healthItem(name,ok,text){return `<div class="health-item ${ok?'':'bad'}"><b>${esc(name)}</b><span title="${esc(text)}">${esc(text)}</span></div>`}function deviceActions(d){let rename=`<button class="secondary" onclick="openRename('${d.mac}')">改名</button>`;if(d.managed)return rename+(d.fixed?'<span class="muted">固定设备</span>':`<button class="secondary danger" onclick="removeDevice('${d.ip}')">恢复直连</button>`);let join=`<button class="secondary" onclick="choose('${d.ip}')">加入旁路</button>`;if(filter==='favorites')return rename+join+`<button class="secondary danger" onclick="setFavorite('${d.mac}',false)">移出常用</button>`;let keep=d.favorite?`<button class="secondary danger" onclick="setFavorite('${d.mac}',false)">取消保留</button>`:`<button class="secondary" onclick="setFavorite('${d.mac}',true)">保留</button>`;return rename+join+keep}function render(){let q=deviceQuery.toLowerCase(),shown=devices.filter(d=>(filter==='managed'&&d.managed||filter==='favorites'&&d.favorite||filter==='online'&&d.status==='bound')&&(!q||`${d.name} ${d.ip} ${d.mac}`.toLowerCase().includes(q)));let empty={managed:'尚无已接管设备',favorites:'尚未保留常用设备，可在“全部在线”中添加',online:'当前没有可见的在线设备'}[filter];document.querySelector('#devices').innerHTML=shown.length?shown.map(d=>{let label=!d.managed?(d.favorite?'常用设备':'未接管'):d.effective?'已生效':'等待新流量',state=!d.managed?'':d.effective?'active':'wait';return `<div class="device-row"><div class="device-name">${esc(d.name)}<div class="device-meta">${esc(d.ip)}${d.static?' · 固定地址':''}${d.custom_name?' · 自定义名称':''}</div></div><div class="device-mac muted">${esc(d.mac)}</div><div class="device-online online ${d.status==='bound'?'bound':''}">${d.status==='bound'?'在线':'离线'}</div><div class="device-state state ${state}">${label}${d.managed?`<div class="device-meta">${d.packets} 个包</div>`:''}</div><div class="device-action">${deviceActions(d)}</div></div>`}).join(''):`<div class="empty">${empty}</div>`}function setFilter(value){filter=value;document.querySelectorAll('[data-filter]').forEach(b=>b.classList.toggle('active',b.dataset.filter===value));render()}async function load(){try{let data=await api('/api/devices'),summary=data.summary,checks=summary.checks||{},ready=summary.ready&&summary.netwatch==='up';devices=data.devices;let badge=document.querySelector('#health');badge.className='overall '+(ready?'':'bad');badge.innerHTML=`<span class="dot"></span><span>${ready?'旁路运行正常':'旁路需要检查'}</span>`;document.querySelector('#healthChecks').innerHTML=healthItem('RB5009',summary.router==='connected','管理连接')+healthItem('DNS',checks.dns,'国内解析')+healthItem('Mihomo',checks.mihomo,'控制接口')+healthItem('当前策略',checks.policy,summary.detail?.proxy||'未就绪')+healthItem('自动回退',summary.netwatch==='up',summary.netwatch==='up'?'已启用':'未就绪');render()}catch(e){setStatus(e.message,false)}}function choose(ip){document.querySelector('#ip').value=ip;document.querySelector('#ip').focus();window.scrollTo({top:document.querySelector('.add-row').offsetTop-90,behavior:'smooth'})}function openRename(mac){let d=devices.find(x=>x.mac===mac);if(!d)return;editingMac=mac;document.querySelector('#renameInput').value=d.name;document.querySelector('#renameDialog').showModal();requestAnimationFrame(()=>document.querySelector('#renameInput').select())}function closeRename(){document.querySelector('#renameDialog').close();editingMac=''}async function saveRename(event){event.preventDefault();let alias=document.querySelector('#renameInput').value.trim();try{await api('/api/device/preference',{method:'POST',body:JSON.stringify({mac:editingMac,alias})});closeRename();setStatus(alias?'设备名称已保存':'已恢复路由器原名称',true);await load()}catch(e){setStatus(e.message,false)}}async function setFavorite(mac,favorite){try{await api('/api/device/preference',{method:'POST',body:JSON.stringify({mac,favorite})});setStatus(favorite?'已加入常用设备':'已移出常用设备',true);await load()}catch(e){setStatus(e.message,false)}}async function enableDevice(){let ip=document.querySelector('#ip').value.trim();try{setStatus('正在检查并加入设备…',true);let result=await api('/api/enable',{method:'POST',body:JSON.stringify({ip})});setStatus(result.message,true);await load()}catch(e){setStatus(e.message,false)}}async function removeDevice(ip){if(!confirm(`将 ${ip} 恢复直连并清理旧连接？`))return;try{setStatus('正在恢复直连…',true);let result=await api('/api/remove',{method:'POST',body:JSON.stringify({ip})});setStatus(result.message,true);await load()}catch(e){setStatus(e.message,false)}}document.querySelector('#deviceSearch').addEventListener('input',event=>{deviceQuery=event.target.value.trim();render()});document.querySelector('#renameDialog').addEventListener('click',event=>{if(event.target.id==='renameDialog')closeRename()});load();setInterval(()=>{if(!document.querySelector('#renameDialog').open)load()},30000)
</script></body></html>'''
PAGE = PAGE.replace('<div class="eyebrow">SELECTIVE ROUTING</div>', '')
PAGE = PAGE.replace(
    '.add-row{display:grid;',
    '.router-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}'
    '.router-grid .system-item,.router-grid .system-item:nth-child(3n),.router-grid .system-item:nth-last-child(-n+3){border-right:1px solid #38383a;border-bottom:0}'
    '.router-grid .system-item:last-child{border-right:0}'
    '.system-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}'
    '.system-item{min-width:0;min-height:118px;padding:16px;border-right:1px solid #38383a;border-bottom:1px solid #38383a}'
    '.system-item:nth-child(3n){border-right:0}.system-item:nth-last-child(-n+3){border-bottom:0}'
    '.system-label{color:#8e8e93;font-size:12px}.system-value{margin-top:8px;font-size:23px;line-height:1.15;font-weight:700;font-variant-numeric:tabular-nums}'
    '.system-detail{margin-top:8px;color:#8e8e93;font-size:12px;line-height:1.45;overflow-wrap:anywhere}'
    '.thermal{padding-bottom:13px}.thermal-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:11px}.thermal-reading{display:flex;align-items:baseline;justify-content:space-between;gap:6px;padding:6px 7px;border-radius:6px;background:#2c2c2e}.thermal-reading span{min-width:0;color:#aeaeb2;font-size:11px;white-space:nowrap}.thermal-reading b{color:#f5f5f7;font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap}.thermal.warn .thermal-reading b{color:#ffd60a}.thermal.bad .thermal-reading b{color:#ff453a}'
    '.system-item.warn .system-value{color:#ffd60a}.system-item.bad .system-value{color:#ff453a}'
    '.meter{height:4px;margin-top:10px;border-radius:2px;background:#38383a;overflow:hidden}.meter span{display:block;height:100%;background:#30d158}'
    '.system-item.warn .meter span{background:#ffd60a}.system-item.bad .meter span{background:#ff453a}'
    '.add-row{display:grid;',
    1,
)
PAGE = PAGE.replace(
    '<section class="section"><div class="section-title"><h2>运行状态</h2>',
    '<section class="section"><div class="section-title"><h2>RB5009 运行状态</h2><span class="muted" id="routerUpdated">正在读取</span></div>'
    '<div class="group router-grid" id="routerStatus"><div class="empty">正在读取路由器状态</div></div></section>'
    '<section class="section"><div class="section-title"><h2>WireGuard 远程互联</h2><span class="muted" id="wireguardUpdated">正在读取</span></div>'
    '<div class="group wireguard-list" id="wireguardStatus"><div class="empty">正在读取隧道状态</div></div></section>'
    '<section class="section"><div class="section-title"><h2>Z4Pro 运行状态</h2><span class="muted" id="systemUpdated">正在读取</span></div>'
    '<div class="group system-grid" id="systemStatus"><div class="empty">正在读取系统状态</div></div></section>'
    '<section class="section"><div class="section-title"><h2>旁路运行状态</h2>',
    1,
)
PAGE = PAGE.replace(
    'function deviceActions(d){',
    '''function formatBytes(value){return `${(Number(value||0)/1073741824).toFixed(1)} GB`}
function formatUptime(seconds){let total=Math.max(0,Math.floor(Number(seconds||0))),days=Math.floor(total/86400),hours=Math.floor(total%86400/3600),minutes=Math.floor(total%3600/60);return days?`${days} 天 ${hours} 小时`:hours?`${hours} 小时 ${minutes} 分钟`:`${minutes} 分钟`}
function formatRouterUptime(value){let units={w:'周',d:'天',h:'小时',m:'分钟',s:'秒'},parts=[];String(value||'').replace(/([0-9]+)(w|d|h|m|s)/g,(all,count,unit)=>{if(parts.length<3)parts.push(count+units[unit]);return all});return parts.join(' ')||'不可用'}
function systemTone(value,warn,bad){return Number(value)>=bad?'bad':Number(value)>=warn?'warn':''}
function systemItem(label,value,detail,tone='',percent=null){let meter=percent===null?'':`<div class="meter"><span style="width:${Math.max(0,Math.min(100,Number(percent)||0))}%"></span></div>`;return `<div class="system-item ${tone}"><div class="system-label">${esc(label)}</div><div class="system-value">${esc(value)}</div>${meter}<div class="system-detail">${esc(detail)}</div></div>`}
function thermalItem(t,hdds){let values=[['CPU',t.cpu_c],['M.2 SSD',t.nvme_c],...hdds.slice().sort((a,b)=>String(a.name).localeCompare(String(b.name))).map((item,index)=>[`盘 ${index+1}`,item.temperature_c])],max=Math.max(...values.map(item=>Number(item[1])||0)),tone=systemTone(max,50,60);return `<div class="system-item thermal ${tone}"><div class="system-label">温度</div><div class="thermal-grid">${values.map(([label,value])=>`<div class="thermal-reading"><span>${esc(label)}</span><b>${value==null?'--':`${Number(value).toFixed(0)}°C`}</b></div>`).join('')}</div></div>`}
function renderRouter(r){let target=document.querySelector('#routerStatus'),updated=document.querySelector('#routerUpdated');if(!r?.available){target.innerHTML='<div class="empty">路由器资源暂时不可读</div>';updated.textContent='读取失败';return}target.innerHTML=systemItem('RouterOS',r.version||'不可用',r.board_name||'RB5009')+systemItem('CPU',`${Number(r.cpu_percent).toFixed(0)}%`,`${r.cpu_count} 核 · ${r.cpu_frequency} MHz`,systemTone(r.cpu_percent,75,90),r.cpu_percent)+systemItem('可用内存',formatBytes(r.memory_free),`总计 ${formatBytes(r.memory_total)} · 已用 ${Number(r.memory_percent).toFixed(1)}%`,systemTone(r.memory_percent,75,90),r.memory_percent)+systemItem('运行时间',formatRouterUptime(r.uptime),'RouterOS 持续运行');updated.textContent=new Date().toLocaleTimeString('zh-CN',{hour12:false})}
async function loadSystem(){try{let s=await api('/api/system/status'),c=s.cpu,m=s.memory,t=s.temperature,d=s.disk,x=s.docker,hdds=Array.isArray(t.hdd)?t.hdd:[],dockerValue=x.running==null?'不可用':`${x.running} / ${x.total}`,dockerDetail=x.unhealthy==null?'状态不可用':x.unhealthy?`${x.unhealthy} 个容器异常`:x.total>x.running?`运行中均正常 · ${x.total-x.running} 个已停止`:'运行中容器均正常';document.querySelector('#systemStatus').innerHTML=systemItem('CPU',`${Number(c.percent).toFixed(1)}%`,`${c.cores} 核 · 负载 ${c.load_1m} / ${c.load_5m}`,systemTone(c.percent,75,90),c.percent)+systemItem('内存',`${Number(m.percent).toFixed(1)}%`,`${formatBytes(m.used)} / ${formatBytes(m.total)} · Swap ${Number(m.swap_percent).toFixed(1)}%`,systemTone(m.percent,75,90),m.percent)+thermalItem(t,hdds)+systemItem('M.2 Docker 盘',`${Number(d.percent).toFixed(1)}%`,`${formatBytes(d.used)} / ${formatBytes(d.total)}`,systemTone(d.percent,75,90),d.percent)+systemItem('Docker',dockerValue,dockerDetail,x.unhealthy?'bad':'')+systemItem('运行时间',formatUptime(s.uptime_seconds),`内核 ${s.kernel}`);document.querySelector('#systemUpdated').textContent=`${s.healthy?'状态正常':'需要检查'} · ${new Date(s.updated_at*1000).toLocaleTimeString('zh-CN',{hour12:false})}`}catch(e){document.querySelector('#systemStatus').innerHTML=`<div class="empty">读取失败：${esc(e.message)}</div>`;document.querySelector('#systemUpdated').textContent='读取失败'}}
function deviceActions(d){''',
    1,
)
PAGE = PAGE.replace(
    'function deviceActions(d){',
    r'''let wireguardData={interfaces:[],events:[]},wireguardSelected='';
function trafficBytes(value){let n=Number(value||0),units=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<units.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${units[i]}`}
function handshakeAge(seconds){if(seconds==null)return '从未';let n=Number(seconds);return n<60?`${n} 秒前`:n<3600?`${Math.floor(n/60)} 分钟前`:n<86400?`${Math.floor(n/3600)} 小时前`:`${Math.floor(n/86400)} 天前`}
function wireguardStateText(item){return item.kind==='site'&&item.probe?.reachable?`${item.state_text} · ${item.probe.latency_ms} ms`:item.state_text}
function renderWireGuard(){let target=document.querySelector('#wireguardStatus');target.innerHTML=wireguardData.interfaces.length?wireguardData.interfaces.map(item=>`<div class="wireguard-row"><div class="wg-identity"><span class="wg-dot ${esc(item.state)}"></span><div><b>${esc(item.label)}</b><div class="muted">${esc(item.name)} · UDP ${esc(item.listen_port||'--')}</div></div></div><div class="wg-metric"><span>状态</span><b class="wg-tone ${esc(item.state)}">${esc(wireguardStateText(item))}</b></div><div class="wg-metric"><span>最近握手</span><b>${esc(handshakeAge(item.last_handshake_seconds))}</b></div><div class="wg-metric"><span>对端</span><b>${item.peer_active} / ${item.peer_total} 活跃</b></div><div class="wg-metric"><span>累计流量</span><b>↓ ${trafficBytes(item.rx_bytes)} · ↑ ${trafficBytes(item.tx_bytes)}</b></div><button class="wg-detail" onclick="openWireGuard('${esc(item.name)}')" aria-label="查看 ${esc(item.label)} 详情">详情 <span>›</span></button></div>`).join(''):'<div class="empty">未发现 WireGuard 接口</div>'}
function wireguardDetail(item){let routes=item.routes.length?item.routes.map(route=>`<div class="wg-detail-row"><span>${esc(route.destination)}</span><b class="${route.active?'good':'bad-text'}">${route.active?'路由生效':'路由未生效'}</b></div>`).join(''):'<div class="empty compact">该接口没有独立远端路由</div>',peers=item.peers.length?item.peers.map(peer=>`<div class="wg-peer"><div><b>${esc(peer.name)}</b><span>${esc(peer.allowed_address||'未声明地址')}</span></div><div><b class="${peer.active?'good':''}">${handshakeAge(peer.last_handshake_seconds)}</b><span>${esc(peer.endpoint)} · ↓ ${trafficBytes(peer.rx_bytes)} / ↑ ${trafficBytes(peer.tx_bytes)}</span></div></div>`).join(''):'<div class="empty compact">没有对端</div>',events=wireguardData.events.filter(event=>event.interface===item.name);document.querySelector('#wireguardDialogTitle').textContent=item.label;document.querySelector('#wireguardDialogBody').innerHTML=`<div class="wg-detail-summary"><div><span>当前状态</span><b class="wg-tone ${esc(item.state)}">${esc(wireguardStateText(item))}</b></div><div><span>接口</span><b>${esc(item.name)} · MTU ${esc(item.mtu||'--')}</b></div><div><span>NAT</span><b>${item.kind==='mobile'?(item.nat_ready?'已就绪':'需要检查'):'不适用'}</b></div></div><h3>对端</h3><div class="wg-detail-group">${peers}</div><h3>远端路由</h3><div class="wg-detail-group">${routes}</div><h3>最近状态变化</h3><div class="wg-detail-group">${events.length?events.slice().reverse().map(event=>`<div class="wg-detail-row"><span>${new Date(event.timestamp*1000).toLocaleString('zh-CN',{hour12:false})}</span><b>${esc(event.message)}</b></div>`).join(''):'<div class="empty compact">最近 7 天没有状态变化</div>'}</div>`}
function openWireGuard(name){let item=wireguardData.interfaces.find(value=>value.name===name);if(!item)return;wireguardSelected=name;wireguardDetail(item);document.querySelector('#wireguardDialog').showModal()}
function closeWireGuard(){wireguardSelected='';document.querySelector('#wireguardDialog').close()}
async function loadWireGuard(){try{wireguardData=await api('/api/wireguard/status');renderWireGuard();if(wireguardSelected){let item=wireguardData.interfaces.find(value=>value.name===wireguardSelected);if(item)wireguardDetail(item)}document.querySelector('#wireguardUpdated').textContent=new Date(wireguardData.updated_at*1000).toLocaleTimeString('zh-CN',{hour12:false})}catch(e){document.querySelector('#wireguardStatus').innerHTML=`<div class="empty">读取失败：${esc(e.message)}</div>`;document.querySelector('#wireguardUpdated').textContent='读取失败'}}
function deviceActions(d){''',
    1,
)
PAGE = PAGE.replace(
    "load();setInterval(()=>{if(!document.querySelector('#renameDialog').open)load()},30000)",
    "setupRuntimeFold('bypassStatus');setupRuntimeFold('z4Status');load();loadSystem();loadWireGuard();setInterval(loadSystem,10000);setInterval(loadWireGuard,10000);setInterval(()=>{if(!document.querySelector('#renameDialog').open)load()},30000)",
    1,
)
PAGE = PAGE.replace(
    '.overall.bad{color:#ff453a}',
    '.overall.bad{color:#ff453a}.overall.warn{color:#ffd60a}',
    1,
)
PAGE = PAGE.replace(
    'grid-template-columns:repeat(5,minmax(0,1fr))',
    'grid-template-columns:repeat(auto-fit,minmax(150px,1fr))',
    1,
)
PAGE = PAGE.replace(
    "ready=summary.ready&&summary.netwatch==='up';devices=data.devices;",
    "ready=summary.ready&&summary.netwatch==='up',drift=summary.drift||[],warn=ready&&drift.length;devices=data.devices;renderRouter(summary.router_resource);",
    1,
)
PAGE = PAGE.replace(
    "badge.className='overall '+(ready?'':'bad');badge.innerHTML=`<span class=\"dot\"></span><span>${ready?'旁路运行正常':'旁路需要检查'}</span>`;",
    "badge.className='overall '+(!ready?'bad':warn?'warn':'');badge.innerHTML=`<span class=\"dot\"></span><span>${!ready?'旁路需要检查':warn?'运行正常 · 配置需核对':'旁路运行正常'}</span>`;let bypassSummary=document.querySelector('#bypassUpdated');if(bypassSummary){let foreignError=Number(summary.dns_performance?.groups?.foreign?.error_rate||0),critical=!ready||drift.length>0;bypassSummary.textContent=critical?'核心服务需要检查':foreignError>=1?`核心服务正常 · DNS ${foreignError.toFixed(1)}% 提醒`:'RB5009、Mihomo、自动回退正常';bypassSummary.className='summary-hint '+(critical?'runtime-bad':foreignError>=1?'runtime-warn':'runtime-good');autoOpenFold('bypassStatus',critical)}",
    1,
)
PAGE = PAGE.replace(
    "document.querySelector('#healthChecks').innerHTML=healthItem('RB5009',summary.router==='connected','管理连接')+healthItem('DNS',checks.dns,'国内解析')+healthItem('Mihomo',checks.mihomo,'控制接口')+healthItem('当前策略',checks.policy,summary.detail?.proxy||'未就绪')+healthItem('自动回退',summary.netwatch==='up',summary.netwatch==='up'?'已启用':'未就绪');render()",
    "document.querySelector('#healthChecks').innerHTML=renderStatusDashboard(summary,checks,drift);render()",
    1,
)
PAGE = PAGE.replace(
    "healthItem('自动回退',summary.netwatch==='up',summary.netwatch==='up'?'已启用':'未就绪');render()",
    "healthItem('自动回退',summary.netwatch==='up',summary.netwatch==='up'?'已启用':'未就绪',summary.netwatch==='up'?'故障时自动切换':'等待探针恢复')+healthItem('配置对账',!drift.length,drift.length?'需核对':'一致',drift.join('；')||'页面、路由与状态一致')+healthItem('IPv6',true,summary.ipv6_policy,'纳管设备 IPv6 绕行')+healthItem('备份',!!summary.backup,summary.backup?summary.backup.time:'尚未配置',summary.backup?'最近完整备份':'需要先执行一次备份')+healthItem('UPnP',!summary.upnp_enabled,summary.upnp_enabled?'已开启':'已关闭',summary.upnp_enabled?summary.upnp_mappings+' 个动态映射':summary.upnp_mappings+' 条历史映射等待自然过期')+healthItem('版本',true,summary.version,'页面控制版本');render()",
    1,
)
PAGE = PAGE.replace(
    "healthItem('DNS',checks.dns,'国内解析')",
    "dnsHealthItem('国内 DNS',checks.dns,summary.dns_performance?.groups?.domestic,summary.dns_performance?.p95_ms)+dnsHealthItem('国外 DNS',checks.dns,summary.dns_performance?.groups?.foreign,summary.dns_performance?.p95_ms)",
    1,
)
PAGE = PAGE.replace(
    "function healthItem(name,ok,text){",
    "function dashMetric(value,unit='ms'){return `${Number(value||0).toFixed(1)}<small>${unit}</small>`}function dashDns(name,item){let avg=Number(item?.average_ms||0),p95=Number(item?.p95_ms||0),error=Number(item?.error_rate||0),source=item?.name||'当前上游',tone=error>=10?'bad':error>=1?'warn':'';return `<article class=\"dash-dns ${tone}\"><div class=\"dash-dns-head\"><b>${esc(name)}</b><span>${esc(source)}</span></div><div class=\"dash-metrics\"><div><span>平均</span><strong>${dashMetric(avg)}</strong></div><div><span>P95</span><strong>${dashMetric(p95)}</strong></div><div class=\"dash-error\"><span>错误率</span><strong>${Number(error).toFixed(2)}<small>%</small></strong></div></div></article>`}function dashSetting(name,detail,state,tone='good'){return `<div class=\"dash-setting\"><div><b>${esc(name)}</b><span title=\"${esc(detail)}\">${esc(detail)}</span></div><em class=\"${tone}\">${esc(state)}</em></div>`}function renderStatusDashboard(summary,checks,drift){let domestic=summary.dns_performance?.groups?.domestic,foreign=summary.dns_performance?.groups?.foreign,foreignError=Number(foreign?.error_rate||0),notice=foreignError>=1?`<div class=\"dash-alert ${foreignError>=10?'bad':'warn'}\"><i></i>国外 DNS 需关注 · 错误率 ${foreignError.toFixed(2)}%</div>`:'',routerOk=summary.router==='connected',mihomoOk=!!checks.mihomo,failoverOk=summary.netwatch==='up',policy=summary.detail?.proxy||'未就绪',backup=summary.backup?.time||'尚未配置';return `${notice}<section class=\"dash-panel dash-core\"><div class=\"dash-panel-head\"><b>核心服务</b><span>管理、代理与自动回退</span></div><div class=\"dash-core-grid\"><div class=\"dash-core-item ${routerOk?'':'bad'}\"><small>RB5009</small><strong>${routerOk?'已连接':'不可用'}</strong><span>${summary.router_resource?.available?'管理接口与资源读取正常':'管理接口需要检查'}</span></div><div class=\"dash-core-item ${mihomoOk?'':'bad'}\"><small>Mihomo</small><strong>${mihomoOk?'运行正常':'不可用'}</strong><span title=\"${esc(policy)}\">当前出口：${esc(policy)}</span></div><div class=\"dash-core-item ${failoverOk?'':'bad'}\"><small>自动回退</small><strong>${failoverOk?'已启用':'未就绪'}</strong><span>${failoverOk?'当前出口故障时自动切换':'等待探针恢复'}</span></div></div></section><div class=\"dash-dns-grid\">${dashDns('国内 DNS',domestic)}${dashDns('国外 DNS',foreign)}</div><section class=\"dash-panel dash-settings\"><div class=\"dash-panel-head\"><b>运行设置</b><span>配置与保护状态</span></div><div class=\"dash-settings-grid\">${dashSetting('当前策略',policy,'已生效')}${dashSetting('配置对账',drift.length?drift.join('；'):'页面、路由与状态一致',drift.length?'需核对':'一致',drift.length?'warn':'good')}${dashSetting('IPv6',summary.ipv6_policy||'纳管设备 IPv6 绕行','受控','neutral')}${dashSetting('UPnP',summary.upnp_enabled?`${summary.upnp_mappings||0} 个动态映射`:`${summary.upnp_mappings||0} 条动态映射`,summary.upnp_enabled?'已开启':'已关闭',summary.upnp_enabled?'warn':'neutral')}${dashSetting('备份',backup,summary.backup?'可恢复':'未配置',summary.backup?'good':'warn')}</div></section>`}function dnsHealthItem(name,ok,item,fallback){if(!item)return healthItem(name,ok,`整体 P95 ${Number(fallback||0).toFixed(1)} ms`);let avg=Number(item.average_ms||0),p95=Number(item.p95_ms||0),error=Number(item.error_rate||0),level=!ok?'bad':error>=10?'bad':error>=1?'warn':'';return `<div class=\"health-item dns-health ${level}\"><b>${esc(name)}</b><div class=\"dns-source\">${esc(item.name||'当前上游')}</div><div class=\"dns-metrics\"><div><span>平均</span><strong>${avg.toFixed(1)}<small> ms</small></strong></div><div><span>P95</span><strong>${p95.toFixed(1)}<small> ms</small></strong></div><div class=\"dns-error\"><span>错误率</span><strong>${error.toFixed(2)}<small>%</small></strong></div></div></div>`}function healthItem(name,ok,primary,detail=''){return `<div class=\"health-item ${ok?'':'bad'}\"><b>${esc(name)}</b><div class=\"status-primary\">${esc(primary)}</div>${detail?`<div class=\"status-detail\">${esc(detail)}</div>`:''}</div>`}function legacyHealthItem(name,ok,text){",
    1,
)
PAGE = PAGE.replace(
    "DNS ${foreignError.toFixed(1)}% 提醒",
    "DNS ${foreignError.toFixed(1)}% 尝试异常（累计）",
    1,
)
PAGE = PAGE.replace(
    "国外 DNS 需关注 · 错误率 ${foreignError.toFixed(2)}%",
    "国外 DNS 累计尝试异常 ${foreignError.toFixed(2)}% · 双上游竞速不等于设备解析失败",
    1,
)
PAGE = PAGE.replace(
    "<span>错误率</span>",
    "<span title=\"容器启动以来的单上游尝试异常；双上游竞速时不等于设备 DNS 失败\">上游尝试异常</span>",
    1,
)
PAGE = PAGE.replace(
    "</style></head>",
    ".dash-settings-grid{grid-template-columns:repeat(auto-fill,minmax(220px,1fr));grid-auto-rows:1fr}.dash-setting{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;min-height:118px;height:100%}.dash-setting>div{min-width:0}.dash-setting b{min-width:0;overflow:visible!important;text-overflow:clip!important;white-space:normal!important}.dash-setting span{display:block;max-width:none!important;min-width:0;overflow:visible!important;text-overflow:clip!important;overflow-wrap:anywhere;white-space:normal!important;line-height:1.5}.dash-setting em{margin-left:10px;white-space:nowrap}</style></head>",
    1,
)
PAGE = PAGE.replace(
    "healthItem('RB5009',summary.router==='connected','管理连接')",
    "healthItem('RB5009',summary.router==='connected',summary.router==='connected'?'已连接':'不可用',summary.router_resource?.available?'资源可读':'管理接口')",
    1,
)
PAGE = PAGE.replace(
    "healthItem('Mihomo',checks.mihomo,'控制接口')",
    "healthItem('Mihomo',checks.mihomo,checks.mihomo?'运行正常':'不可用','控制接口')",
    1,
)
PAGE = PAGE.replace(
    "healthItem('当前策略',checks.policy,summary.detail?.proxy||'未就绪')",
    "healthItem('当前策略',checks.policy,summary.detail?.proxy||'未就绪','当前出口')",
    1,
)
PAGE = PAGE.replace(
    "${d.packets} 个包",
    "${d.connections} 条连接 · ${d.packets} 个包",
    1,
)
PAGE = PAGE.replace(
    'grid-template-columns:repeat(3,1fr)}.nav a{text-align:center;padding:7px 5px}',
    'grid-template-columns:repeat(4,1fr)}.nav a{text-align:center;padding:7px 5px;white-space:normal}',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''.health-grid{display:flex;flex-wrap:wrap;background:#1c1c1e}
.health-item,.health-item:last-child{flex:1 1 220px;min-width:220px;border:0;background:#1c1c1e;min-height:116px;box-shadow:inset -1px -1px 0 #38383a}
.status-primary{margin:9px 0 0 14px;color:#f5f5f7;font-size:16px;font-weight:650;line-height:1.25;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.status-detail{margin:5px 0 0 14px;color:#8e8e93;font-size:12px;line-height:1.4;overflow-wrap:anywhere}.health-item.bad .status-primary{color:#ff6961}
.health-item.warn b:before{background:#ffd60a}.dns-health{min-height:132px}.dns-source{margin:7px 0 10px 14px;color:#aeaeb2;font-size:13px;line-height:1.25;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dns-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-left:14px}.dns-metrics div{min-width:0}.dns-metrics span{display:block;margin:0;color:#8e8e93;font-size:11px;line-height:1.2}.dns-metrics strong{display:block;margin-top:3px;color:#f5f5f7;font-size:17px;font-weight:650;font-variant-numeric:tabular-nums;line-height:1.15;white-space:nowrap}.dns-metrics small{font-size:11px;font-weight:500;color:#aeaeb2}.dns-error strong{color:#30d158}.dns-health.warn .dns-error strong{color:#ffd60a}.dns-health.bad .dns-error strong{color:#ff6961}
@media(max-width:760px){.health-item,.health-item:nth-child(2n),.health-item:last-child{flex-basis:calc(50% - 1px);min-width:calc(50% - 1px);border:0}}
@media(max-width:600px){.dns-metrics{gap:6px}.dns-metrics strong{font-size:16px}}@media(max-width:420px){.health-item,.health-item:nth-child(2n),.health-item:last-child{flex-basis:100%;min-width:100%;min-height:0}}</style></head>''',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''.health-grid{display:block!important;background:transparent!important;border:0!important;overflow:visible!important}.dash-alert{display:flex;align-items:center;gap:8px;width:max-content;max-width:100%;margin:0 0 12px auto;padding:8px 11px;border:1px solid #73521c;border-radius:7px;background:#2c2416;color:#ffd08a;font-size:12px;font-weight:600}.dash-alert i{width:7px;height:7px;border-radius:50%;background:currentColor;flex:0 0 auto}.dash-alert.bad{border-color:#703631;background:#2c1d1d;color:#ff9f96}.dash-panel{border:1px solid #38383a;border-radius:8px;background:#1c1c1e;overflow:hidden}.dash-panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 17px;border-bottom:1px solid #38383a}.dash-panel-head b{font-size:14px}.dash-panel-head span{color:#8e8e93;font-size:12px}.dash-core-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.dash-core-item{min-width:0;padding:18px 17px;border-right:1px solid #38383a}.dash-core-item:last-child{border-right:0}.dash-core-item small{display:flex;align-items:center;gap:7px;color:#aeaeb2;font-size:13px}.dash-core-item small:before{content:"";width:7px;height:7px;border-radius:50%;background:#30d158;flex:0 0 auto}.dash-core-item.bad small:before{background:#ff453a}.dash-core-item strong{display:block;margin-top:10px;color:#f5f5f7;font-size:22px;line-height:1.15}.dash-core-item.bad strong{color:#ff6961}.dash-core-item span{display:block;margin-top:7px;color:#8e8e93;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dash-dns-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:14px}.dash-dns{min-width:0;padding:16px 17px;border:1px solid #38383a;border-radius:8px;background:#1c1c1e}.dash-dns-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.dash-dns-head b{font-size:14px}.dash-dns-head span{min-width:0;color:#8e8e93;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dash-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px;margin-top:16px}.dash-metrics span{display:block;color:#8e8e93;font-size:11px}.dash-metrics strong{display:block;margin-top:4px;color:#f5f5f7;font-size:21px;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}.dash-metrics small{margin-left:2px;color:#8e8e93;font-size:11px;font-weight:500}.dash-error strong{color:#30d158}.dash-dns.warn .dash-error strong{color:#ffd60a}.dash-dns.bad .dash-error strong{color:#ff6961}.dash-settings{margin-top:14px}.dash-settings-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:1px;background:#38383a}.dash-setting{display:flex;min-width:0;align-items:flex-start;justify-content:space-between;gap:8px;padding:14px 15px;background:#1c1c1e}.dash-setting b{display:block;color:#aeaeb2;font-size:13px}.dash-setting span{display:block;max-width:100%;margin-top:8px;color:#8e8e93;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dash-setting em{flex:0 0 auto;border-radius:999px;padding:4px 8px;background:#173527;color:#30d158;font-size:12px;font-style:normal;font-weight:650;line-height:1}.dash-setting em.neutral{background:#2c2c2e;color:#d1d1d6}.dash-setting em.warn{background:#332b16;color:#ffd60a}@media (min-width:721px) and (max-width:900px){.dash-settings-grid{grid-template-columns:repeat(6,minmax(0,1fr))}.dash-setting{grid-column:span 2}.dash-setting:nth-child(n+4){grid-column:span 3}}@media(max-width:720px){.dash-alert{margin-left:0}.dash-core-grid{grid-template-columns:1fr}.dash-core-item{border-right:0;border-bottom:1px solid #38383a}.dash-core-item:last-child{border-bottom:0}.dash-dns-grid{grid-template-columns:1fr}.dash-settings-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.dash-setting:nth-child(n+4){border-top:1px solid #38383a}}@media(max-width:480px){.dash-panel-head{align-items:flex-start;flex-direction:column}.dash-settings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.dash-setting:nth-child(n+3){border-top:1px solid #38383a}.dash-setting:last-child{grid-column:span 2}}</style></head>''',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''@media(max-width:820px){.system-grid,.router-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.system-item,.system-item:nth-child(3n),.system-item:nth-last-child(-n+3),.router-grid .system-item,.router-grid .system-item:nth-child(3n),.router-grid .system-item:nth-last-child(-n+3){border-right:1px solid #38383a;border-bottom:1px solid #38383a}.system-item:nth-child(2n),.router-grid .system-item:nth-child(2n){border-right:0}.system-item:nth-last-child(-n+2),.router-grid .system-item:nth-last-child(-n+2){border-bottom:0}}
@media(max-width:420px){.system-grid,.router-grid{grid-template-columns:1fr}.system-item,.system-item:nth-child(2n),.system-item:nth-child(3n),.system-item:nth-last-child(-n+3),.system-item:nth-last-child(-n+2),.router-grid .system-item,.router-grid .system-item:nth-child(2n),.router-grid .system-item:nth-child(3n),.router-grid .system-item:nth-last-child(-n+3),.router-grid .system-item:nth-last-child(-n+2){border-right:0;border-bottom:1px solid #38383a}.system-item:last-child,.router-grid .system-item:last-child{border-bottom:0}}</style></head>''',
    1,
)
PAGE = PAGE.replace('@media(max-width:760px)', '@media(max-width:820px)')
PAGE = PAGE.replace(
    '</style></head>',
    '''.manual-add>summary{display:flex;align-items:center;justify-content:space-between;gap:14px;min-height:46px;padding:0 14px;border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;color:#0a84ff;font-size:13px;font-weight:600;cursor:pointer;list-style:none}.manual-add>summary::-webkit-details-marker{display:none}.manual-add>summary:after{content:"›";font-size:21px;line-height:1;color:#636366;transform:rotate(90deg);transition:transform .16s ease}.manual-add[open]>summary{margin-bottom:9px}.manual-add[open]>summary:after{transform:rotate(-90deg)}.summary-hint{color:#8e8e93;font-size:12px;font-weight:400}@media(max-width:420px){.summary-hint{display:none}}</style></head>''',
    1,
)


def page_section(page, heading):
    marker = f"<h2>{heading}</h2>"
    heading_at = page.index(marker)
    start = page.rfind('<section class="section">', 0, heading_at)
    end = page.index("</section>", heading_at) + len("</section>")
    return start, end, page[start:end]


sections = {heading: page_section(PAGE, heading) for heading in (
    "设备", "加入旁路", "旁路运行状态", "RB5009 运行状态", "WireGuard 远程互联", "Z4Pro 运行状态")}
region_start = min(section[0] for section in sections.values())
region_end = max(section[1] for section in sections.values())
ordered_sections = "".join(sections[heading][2] for heading in (
    "设备", "加入旁路", "旁路运行状态", "Z4Pro 运行状态", "RB5009 运行状态", "WireGuard 远程互联"))
PAGE = PAGE[:region_start] + ordered_sections + PAGE[region_end:]

add_start, add_end, add_section = page_section(PAGE, "加入旁路")
add_section = add_section.replace(
    '<section class="section"><div class="section-title"><h2>加入旁路</h2></div>',
    '<details class="section manual-add" id="manualAdd"><summary><span>按 IP 手动加入</span><span class="summary-hint">适用于已知地址的设备</span></summary>',
    1,
)
add_section = add_section[:-len("</section>")] + "</details>"
PAGE = PAGE[:add_start] + add_section + PAGE[add_end:]
PAGE = PAGE.replace(
    "function choose(ip){document.querySelector('#ip').value=ip;",
    "function choose(ip){document.querySelector('#manualAdd').open=true;document.querySelector('#ip').value=ip;",
    1,
)
PAGE = PAGE.replace(
    "function setStatus(message,ok=true){statusEl.textContent=message;statusEl.className='status '+(ok?'':'error')}",
    "function setStatus(message,ok=true){statusEl.textContent=message;statusEl.className='status '+(ok?'':'error');if(!ok)document.querySelector('#manualAdd').open=true}",
    1,
)


def collapse_diagnostic_section(page, heading, hint, updated_id):
    start, end, section = page_section(page, heading)
    prefix = (f'<section class="section"><div class="section-title"><h2>{heading}</h2>'
              f'<span class="muted" id="{updated_id}">正在读取</span></div>')
    replacement = (f'<details class="section diagnostic-section"><summary><span>{heading}</span>'
                   f'<span class="summary-hint" id="{updated_id}">{hint}</span></summary>'
                   '<div class="diagnostic-content">')
    if prefix not in section:
        raise RuntimeError(f"cannot collapse section: {heading}")
    section = section.replace(prefix, replacement, 1)
    section = section[:-len("</section>")] + "</div></details>"
    return page[:start] + section + page[end:]


PAGE = collapse_diagnostic_section(PAGE, "RB5009 运行状态", "按需查看路由器资源", "routerUpdated")
PAGE = collapse_diagnostic_section(PAGE, "WireGuard 远程互联", "按需查看远程连接", "wireguardUpdated")


def collapse_runtime_section(page, heading, section_id, summary_id):
    start, end, section = page_section(page, heading)
    title_start = section.index('<div class="section-title">')
    title_end = section.index('</div>', title_start) + len('</div>')
    content = section[title_end:-len('</section>')]
    replacement = (f'<details class="section diagnostic-section runtime-section" id="{section_id}">'
                   f'<summary><span>{heading}</span><span class="summary-hint" id="{summary_id}">正在读取</span></summary>'
                   f'<div class="diagnostic-content">{content}</div></details>')
    return page[:start] + replacement + page[end:]


PAGE = collapse_runtime_section(PAGE, "旁路运行状态", "bypassStatus", "bypassUpdated")
PAGE = collapse_runtime_section(PAGE, "Z4Pro 运行状态", "z4Status", "systemUpdated")
PAGE = PAGE.replace(
    '.manual-add>summary{display:flex;',
    '.diagnostic-section>summary,.manual-add>summary{display:flex;',
    1,
)
PAGE = PAGE.replace(
    '.manual-add>summary::-webkit-details-marker{display:none}',
    '.diagnostic-section>summary::-webkit-details-marker,.manual-add>summary::-webkit-details-marker{display:none}',
    1,
)
PAGE = PAGE.replace(
    '.manual-add>summary:after{content:"›";',
    '.diagnostic-section>summary:after,.manual-add>summary:after{content:"›";',
    1,
)
PAGE = PAGE.replace(
    '.manual-add[open]>summary{margin-bottom:9px}',
    '.diagnostic-section[open]>summary,.manual-add[open]>summary{margin-bottom:9px}',
    1,
)
PAGE = PAGE.replace(
    '.manual-add[open]>summary:after{transform:rotate(-90deg)}',
    '.diagnostic-section[open]>summary:after,.manual-add[open]>summary:after{transform:rotate(-90deg)}.diagnostic-content{margin-top:9px}',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''.runtime-section>summary{color:#f5f5f7}.runtime-section>summary .summary-hint{display:block;min-width:0;margin-left:auto;color:#8e8e93;font-size:12px;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.runtime-section>summary .summary-hint.runtime-good{color:#30d158}.runtime-section>summary .summary-hint.runtime-warn{color:#ffd60a}.runtime-section>summary .summary-hint.runtime-bad{color:#ff6961}@media(max-width:600px){.runtime-section>summary .summary-hint{max-width:52%;font-size:11px}}</style></head>''',
    1,
)
PAGE = PAGE.replace(
    'function deviceActions(d){',
    '''function runtimeFoldKey(id){return `family-proxy-fold-${id}`}function setupRuntimeFold(id){let section=document.querySelector(`#${id}`);if(!section||section.dataset.foldReady)return;section.dataset.foldReady='1';let saved=localStorage.getItem(runtimeFoldKey(id));if(saved!==null)section.open=saved==='open';section.addEventListener('toggle',()=>localStorage.setItem(runtimeFoldKey(id),section.open?'open':'closed'))}function autoOpenFold(id,critical){let section=document.querySelector(`#${id}`);if(section&&critical&&localStorage.getItem(runtimeFoldKey(id))===null)section.open=true}function deviceActions(d){''',
    1,
)
PAGE = PAGE.replace(
    "document.querySelector('#systemUpdated').textContent=`${s.healthy?'状态正常':'需要检查'} · ${new Date(s.updated_at*1000).toLocaleTimeString('zh-CN',{hour12:false})}`",
    "let systemCritical=!s.healthy||Number(c.percent)>=90||Number(m.percent)>=90||Number(d.percent)>=90||Number(t.cpu_c)>=60||Number(t.nvme_c)>=60||Number(x.unhealthy||0)>0,systemSummary=document.querySelector('#systemUpdated');systemSummary.textContent=`${s.healthy?'状态正常':'需要检查'} · CPU ${Number(c.percent).toFixed(1)}% · 内存 ${Number(m.percent).toFixed(1)}% · M.2 ${t.nvme_c==null?'--':`${Number(t.nvme_c).toFixed(0)}°C`} · Docker ${dockerValue}`;systemSummary.className='summary-hint '+(systemCritical?'runtime-bad':'runtime-good');autoOpenFold('z4Status',systemCritical)",
    1,
)
PAGE = PAGE.replace(
    '</main><dialog id="renameDialog">',
    '''</main><dialog id="captureDialog"><div class="dialog-body"><h2>网络诊断</h2><p id="captureTarget">选择抓包范围和时长。HTTPS 内容保持加密，只记录流向、握手和重传等元数据。</p><div class="capture-options"><label>抓包范围<select id="captureScope"><option value="all">全部流量</option><option value="dns">仅 DNS</option><option value="tcp">仅 TCP</option><option value="udp">仅 UDP</option></select></label><label>最长时长<select id="captureDuration"><option value="30">30 秒</option><option value="60" selected>1 分钟</option><option value="180">3 分钟</option></select></label></div><div class="capture-note">文件保存在服务器内存盘；单次最多 50 MB、总计最多 200 MB，24 小时后自动删除。</div><div class="capture-status" id="captureStatus"></div><div class="capture-live"><div class="capture-live-head"><b>实时流量</b><span id="captureLiveMeta">尚未开始</span></div><div class="capture-live-lines" id="captureLiveLines"><div class="empty">开始抓包后在这里实时显示最近连接</div></div></div><div class="capture-list" id="captureList"><div class="empty">正在读取诊断记录</div></div></div><div class="dialog-actions"><button type="button" class="dialog-cancel" onclick="closeCapture()">关闭</button><button type="button" class="dialog-save" id="captureStart" onclick="startCapture()">开始抓包</button></div></dialog><dialog id="renameDialog">''',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''.capture-options{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:17px}.capture-options label{color:#8e8e93;font-size:12px}.capture-options select{display:block;width:100%;height:38px;margin-top:6px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 10px;font:14px inherit}.capture-note{margin-top:13px;padding:10px 12px;border-radius:7px;background:#2c2c2e;color:#aeaeb2;font-size:12px;line-height:1.5}.capture-status{min-height:18px;margin-top:12px;color:#30d158;font-size:13px}.capture-status.error{color:#ff6961}.capture-live{margin-top:10px;border:1px solid #38383a;border-radius:7px;background:#111;overflow:hidden}.capture-live-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 11px;border-bottom:1px solid #38383a;font-size:12px}.capture-live-head span{color:#8e8e93}.capture-live-lines{height:156px;overflow:auto;padding:6px 0;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.capture-line{padding:3px 10px;color:#d1d1d6;border-top:1px solid rgba(255,255,255,.04);overflow-wrap:anywhere}.capture-line:first-child{border-top:0}.capture-list{margin-top:10px;border:1px solid #38383a;border-radius:7px;overflow:hidden}.capture-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;padding:11px 12px;border-top:1px solid #38383a}.capture-row:first-child{border-top:0}.capture-title{font-size:13px}.capture-meta{margin-top:4px;color:#8e8e93;font-size:11px}.capture-actions{display:flex;align-items:center;gap:3px}.capture-download{color:#0a84ff;text-decoration:none;font-size:13px;font-weight:600;padding:7px 8px;border-radius:6px}.capture-download:hover{background:rgba(10,132,255,.12)}@media(max-width:420px){.capture-options{grid-template-columns:1fr}.capture-row{grid-template-columns:1fr}.capture-actions{justify-content:flex-end}}</style></head>''',
    1,
)
PAGE = PAGE.replace(
    'function deviceActions(d){',
    '''let captureIp='',captureTimer=0;
function captureSize(bytes){let n=Number(bytes||0);return n<1048576?`${Math.max(0,Math.round(n/1024))} KB`:`${(n/1048576).toFixed(1)} MB`}
function captureTime(value){return value?new Date(Number(value)*1000).toLocaleString('zh-CN',{hour12:false}):'--'}
function captureLabel(item){return item.running?'正在抓取':({completed:'已完成',stopped:'已停止',limit:'达到容量上限',failed:'失败',interrupted:'服务重启中断'}[item.status]||item.status)}
function captureLive(data){let live=data.live,latest=data.captures[0],meta=document.querySelector('#captureLiveMeta'),lines=document.querySelector('#captureLiveLines');if(!live){meta.textContent='尚未开始';lines.innerHTML='<div class="empty">开始抓包后在这里实时显示最近连接</div>';return}meta.textContent=`${live.running?'实时更新':'最近一次'} · ${live.packets} 个包 · ${captureSize(latest?.size||0)}`;lines.innerHTML=live.lines.length?live.lines.map(item=>`<div class="capture-line">${esc(item.text)}</div>`).join(''):'<div class="empty">等待设备产生新流量</div>';lines.scrollTop=lines.scrollHeight}
function captureRows(data){let active=data.active_id;document.querySelector('#captureStart').disabled=Boolean(active);document.querySelector('#captureList').innerHTML=data.captures.length?data.captures.map(item=>`<div class="capture-row"><div><div class="capture-title">${esc(item.scope_label)} · ${captureLabel(item)}</div><div class="capture-meta">${captureTime(item.created_at)} · ${captureSize(item.size)} · 最长 ${item.duration} 秒</div></div><div class="capture-actions">${item.running?`<button class="secondary danger" onclick="stopCapture('${item.id}')">停止</button>`:item.downloadable?`<a class="capture-download" href="/api/capture/download?id=${encodeURIComponent(item.id)}">下载</a><button class="secondary danger" onclick="deleteCapture('${item.id}')">删除</button>`:`<button class="secondary danger" onclick="deleteCapture('${item.id}')">删除</button>`}</div></div>`).join(''):'<div class="empty">暂无抓包记录</div>';captureLive(data)}
async function loadCaptures(){if(!captureIp)return;clearTimeout(captureTimer);try{let data=await api(`/api/captures?ip=${encodeURIComponent(captureIp)}`);captureRows(data);if(document.querySelector('#captureDialog').open)captureTimer=setTimeout(loadCaptures,data.active_id?1000:5000)}catch(e){document.querySelector('#captureStatus').textContent=e.message;document.querySelector('#captureStatus').className='capture-status error'}}
function openCapture(ip){let device=devices.find(item=>item.ip===ip);captureIp=ip;document.querySelector('#captureTarget').textContent=`${device?.name||ip} · ${ip}。HTTPS 内容保持加密，只记录流向、握手和重传等元数据。`;document.querySelector('#captureStatus').textContent='';document.querySelector('#captureStatus').className='capture-status';document.querySelector('#captureDialog').showModal();loadCaptures()}
function closeCapture(){clearTimeout(captureTimer);captureTimer=0;captureIp='';document.querySelector('#captureDialog').close()}
async function startCapture(){let status=document.querySelector('#captureStatus');try{status.textContent='正在启动抓包…';status.className='capture-status';let result=await api('/api/capture/start',{method:'POST',body:JSON.stringify({ip:captureIp,scope:document.querySelector('#captureScope').value,duration:Number(document.querySelector('#captureDuration').value)})});status.textContent=result.message;await loadCaptures()}catch(e){status.textContent=e.message;status.className='capture-status error'}}
async function stopCapture(id){try{let result=await api('/api/capture/stop',{method:'POST',body:JSON.stringify({id})});document.querySelector('#captureStatus').textContent=result.message;await loadCaptures()}catch(e){document.querySelector('#captureStatus').textContent=e.message;document.querySelector('#captureStatus').className='capture-status error'}}
async function deleteCapture(id){if(!confirm('删除这份抓包文件？'))return;try{let result=await api('/api/capture/delete',{method:'POST',body:JSON.stringify({id})});document.querySelector('#captureStatus').textContent=result.message;await loadCaptures()}catch(e){document.querySelector('#captureStatus').textContent=e.message;document.querySelector('#captureStatus').className='capture-status error'}}
document.querySelector('#captureDialog').addEventListener('click',event=>{if(event.target.id==='captureDialog')closeCapture()});
function deviceActions(d){''',
    1,
)
PAGE = PAGE.replace(
    'if(d.managed)return rename+',
    'if(d.managed)return rename+`<button class="secondary" onclick="openCapture(\'${d.ip}\')">诊断</button>`+',
    1,
)
PAGE = PAGE.replace(
    "if(!document.querySelector('#renameDialog').open)load()",
    "if(!document.querySelector('#renameDialog').open&&!document.querySelector('#captureDialog').open)load()",
    1,
)
PAGE = PAGE.replace(
    '</main><dialog id="captureDialog">',
    '''</main><dialog id="wireguardDialog" class="wireguard-dialog"><div class="dialog-body"><h2 id="wireguardDialogTitle">WireGuard 详情</h2><p>仅显示脱敏运行信息，不展示任何密钥。</p><div id="wireguardDialogBody"></div></div><div class="dialog-actions"><button type="button" class="dialog-cancel" onclick="closeWireGuard()">关闭</button></div></dialog><dialog id="captureDialog">''',
    1,
)
PAGE = PAGE.replace(
    '</style></head>',
    '''.wireguard-list{overflow:hidden}.wireguard-row{display:grid;grid-template-columns:minmax(185px,1.35fr) repeat(4,minmax(110px,1fr)) auto;align-items:center;gap:15px;padding:15px 16px;border-top:1px solid #38383a}.wireguard-row:first-child{border-top:0}.wg-identity{display:flex;align-items:center;gap:11px;min-width:0}.wg-identity b{font-size:14px}.wg-dot{width:9px;height:9px;border-radius:50%;background:#8e8e93;box-shadow:0 0 0 3px rgba(142,142,147,.14);flex:0 0 auto}.wg-dot.up{background:#30d158}.wg-dot.warn{background:#ffd60a}.wg-dot.down{background:#ff453a}.wg-metric{min-width:0}.wg-metric span,.wg-detail-summary span{display:block;color:#8e8e93;font-size:11px}.wg-metric b,.wg-detail-summary b{display:block;margin-top:5px;font-size:12px;line-height:1.35;overflow-wrap:anywhere}.wg-tone.up,.good{color:#30d158}.wg-tone.warn{color:#ffd60a}.wg-tone.down,.bad-text{color:#ff453a}.wg-tone.idle{color:#aeaeb2}.wg-detail{border:0;background:transparent;color:#0a84ff;padding:8px;font:600 13px inherit;white-space:nowrap;cursor:pointer}.wg-detail span{font-size:18px;margin-left:3px}.wireguard-dialog{width:min(720px,calc(100% - 28px))}.wireguard-dialog h3{margin:20px 0 8px;color:#8e8e93;font-size:12px;font-weight:600}.wg-detail-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;margin-top:17px;border:1px solid #38383a;border-radius:7px;background:#38383a;overflow:hidden}.wg-detail-summary>div{padding:12px;background:#242426}.wg-detail-group{border:1px solid #38383a;border-radius:7px;overflow:hidden}.wg-peer,.wg-detail-row{display:grid;grid-template-columns:1fr 1.4fr;gap:12px;padding:11px 12px;border-top:1px solid #38383a;font-size:12px}.wg-peer:first-child,.wg-detail-row:first-child{border-top:0}.wg-peer>div:last-child{text-align:right}.wg-peer b,.wg-peer span{display:block}.wg-peer span{margin-top:4px;color:#8e8e93;overflow-wrap:anywhere}.wg-detail-row b{text-align:right}.empty.compact{padding:15px}@media(max-width:820px){.wireguard-row{grid-template-columns:minmax(155px,1.3fr) 1fr 1fr auto}.wg-metric:nth-of-type(4),.wg-metric:nth-of-type(5){display:none}}@media(max-width:520px){.wireguard-row{grid-template-columns:1fr auto;gap:10px}.wg-metric{grid-column:1}.wg-metric:nth-of-type(3){display:block}.wg-detail{grid-column:2;grid-row:1/4}.wg-detail-summary{grid-template-columns:1fr}.wg-peer,.wg-detail-row{grid-template-columns:1fr}.wg-peer>div:last-child,.wg-detail-row b{text-align:left}}</style></head>''',
    1,
)
PAGE = PAGE.replace(
    "document.querySelector('#captureDialog').addEventListener('click',event=>{if(event.target.id==='captureDialog')closeCapture()});",
    "document.querySelector('#captureDialog').addEventListener('click',event=>{if(event.target.id==='captureDialog')closeCapture()});document.querySelector('#wireguardDialog').addEventListener('click',event=>{if(event.target.id==='wireguardDialog')closeWireGuard()});",
    1,
)
PAGE = PAGE.replace(
    "!document.querySelector('#captureDialog').open)load()",
    "!document.querySelector('#captureDialog').open&&!document.querySelector('#wireguardDialog').open)load()",
    1,
)

RULES_PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>代理规则</title><style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","PingFang SC","Segoe UI",sans-serif;background:#000;color:#f5f5f7;letter-spacing:0}*{box-sizing:border-box}body{margin:0;background:#000;color:#f5f5f7}.topbar{position:sticky;top:0;z-index:10;border-bottom:1px solid rgba(255,255,255,.1);background:rgba(18,18,20,.88);backdrop-filter:saturate(180%) blur(22px);-webkit-backdrop-filter:saturate(180%) blur(22px)}.topbar-inner{max-width:1040px;min-height:58px;margin:auto;padding:0 22px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-size:17px;font-weight:650;color:#fff;white-space:nowrap}.nav{display:flex;align-items:center;gap:4px;padding:3px;background:#2c2c2e;border-radius:8px}.nav a{padding:7px 11px;border-radius:6px;color:#aeaeb2;text-decoration:none;font-size:13px;white-space:nowrap}.nav a.active{background:#636366;color:#fff}.wrap{max-width:1040px;margin:auto;padding:38px 22px 64px}.intro{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:25px}.intro h1{font-size:30px;line-height:1.15;margin:0;font-weight:700}.intro p{margin:9px 0 0;color:#98989d;font-size:14px}.count{padding:8px 11px;border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;color:#30d158;font-size:13px;white-space:nowrap}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:9px}.toolbar h2{font-size:13px;color:#8e8e93;font-weight:600;margin:0}.actions{display:flex;gap:7px}.group{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.rule-row{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:9px;padding:9px 12px;border-top:1px solid #38383a}.rule-row:first-child{border-top:0}.rule-index{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#636366;text-align:right}.rule-input{min-width:0;width:100%;height:38px;border:1px solid transparent;border-radius:7px;background:#2c2c2e;color:#f5f5f7;padding:0 10px;font:13px ui-monospace,SFMono-Regular,Menlo,monospace;outline:none}.rule-input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.18)}.rule-input.protected{color:#aeaeb2}.icon-set{display:flex;gap:3px}.icon{width:34px;height:34px;border:0;border-radius:6px;background:transparent;color:#0a84ff;font-size:17px;cursor:pointer}.icon:hover{background:rgba(10,132,255,.12)}.icon.danger{color:#ff453a}.icon:disabled{color:#48484a;cursor:default;background:transparent}.button{height:36px;border:0;border-radius:7px;padding:0 13px;font:600 13px inherit;cursor:pointer}.primary{background:#0a84ff;color:#fff}.secondary{background:#2c2c2e;color:#f5f5f7}.button:disabled{opacity:.5;cursor:default}.footer{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px}.status{min-height:20px;color:#30d158;font-size:13px}.status.error{color:#ff6961}.empty{padding:28px;text-align:center;color:#8e8e93}.dirty .count{color:#ffd60a}@media(max-width:760px){.topbar-inner{height:auto;padding:10px 14px;align-items:flex-start;flex-direction:column;gap:8px}.nav{width:100%;display:grid;grid-template-columns:repeat(4,1fr)}.nav a{text-align:center;padding:7px 5px;white-space:normal}.wrap{padding:28px 14px 50px}.intro{align-items:flex-start;flex-direction:column}.rule-row{grid-template-columns:28px minmax(0,1fr);padding:9px}.icon-set{grid-column:2;justify-content:flex-end}.footer{align-items:stretch;flex-direction:column}.footer .button{width:100%}.actions{width:100%}.actions .button{flex:1}}
</style></head><body><header class="topbar"><div class="topbar-inner"><div class="brand">家庭旁路</div><nav class="nav"><a href="/">设备</a><a class="active" href="/rules">规则</a><a href="/airport/">机场与候选池</a><a href="http://__FAMILY_PROXY_IP__:18091/">DNS</a></nav></div></header><main class="wrap" id="app"><div class="intro"><div><h1>代理规则</h1><p>按顺序匹配流量，国内直连与最终兜底受到保护。</p></div><div class="count" id="count">正在载入</div></div><div class="toolbar"><h2>规则顺序</h2><div class="actions"><button class="button secondary" onclick="reloadRules()">重新载入</button><button class="button primary" id="save" onclick="saveRules()" disabled>应用更改</button></div></div><div class="group" id="rules"><div class="empty">正在读取 Mihomo 配置</div></div><div class="footer"><div class="status" id="status"></div><button class="button secondary" onclick="addRule()">添加规则</button></div></main><script>
const csrf="__CSRF__",app=document.querySelector('#app'),list=document.querySelector('#rules'),statusEl=document.querySelector('#status'),saveButton=document.querySelector('#save'),countEl=document.querySelector('#count');let rules=[],version='',protectedRules=new Set(),dirty=false;function esc(s){return String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}async function api(path,opt={}){let response=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf,...(opt.headers||{})}}),body=await response.json();if(!response.ok)throw Error(body.error||'请求失败');return body}function setStatus(message,ok=true){statusEl.textContent=message;statusEl.className='status '+(ok?'':'error')}function setDirty(value=true){dirty=value;app.classList.toggle('dirty',dirty);saveButton.disabled=!dirty;countEl.textContent=`${rules.length} 条${dirty?' · 未应用':''}`}function render(){list.innerHTML=rules.length?rules.map((rule,index)=>{let terminal=rule.toUpperCase().startsWith('MATCH,'),locked=protectedRules.has(rule)||terminal,blockDown=index===rules.length-1||rules[index+1]?.toUpperCase().startsWith('MATCH,');return `<div class="rule-row"><div class="rule-index">${index+1}</div><input class="rule-input ${locked?'protected':''}" value="${esc(rule)}" oninput="editRule(${index},this.value)" aria-label="第 ${index+1} 条规则" ${locked?'readonly':''}><div class="icon-set"><button class="icon" title="上移" aria-label="上移" onclick="moveRule(${index},-1)" ${index===0||terminal?'disabled':''}>↑</button><button class="icon" title="下移" aria-label="下移" onclick="moveRule(${index},1)" ${blockDown||terminal?'disabled':''}>↓</button><button class="icon danger" title="删除" aria-label="删除" onclick="removeRule(${index})" ${locked?'disabled':''}>×</button></div></div>`}).join(''):'<div class="empty">没有规则</div>';setDirty(dirty)}function applyData(data){rules=[...data.rules];version=data.version;protectedRules=new Set(data.protected||[]);dirty=false;render();setStatus('规则已载入')}async function reloadRules(){if(dirty&&!confirm('放弃尚未应用的修改？'))return;try{applyData(await api('/api/rules'))}catch(error){setStatus(error.message,false)}}function editRule(index,value){rules[index]=value;setDirty()}function moveRule(index,delta){let target=index+delta;if(target<0||target>=rules.length||rules[target].toUpperCase().startsWith('MATCH,'))return;[rules[index],rules[target]]=[rules[target],rules[index]];dirty=true;render()}function removeRule(index){rules.splice(index,1);dirty=true;render()}function addRule(){let matchIndex=rules.findIndex(rule=>rule.toUpperCase().startsWith('MATCH,')),insertAt=matchIndex<0?rules.length:matchIndex;rules.splice(insertAt,0,'DOMAIN-SUFFIX,example.com,Others');dirty=true;render();requestAnimationFrame(()=>document.querySelectorAll('.rule-input')[insertAt]?.focus())}async function saveRules(){if(!dirty)return;if(!confirm(`应用当前 ${rules.length} 条代理规则？`))return;saveButton.disabled=true;setStatus('正在校验并应用…');try{applyData(await api('/api/rules',{method:'POST',body:JSON.stringify({rules,version})}));setStatus('规则已通过校验并生效')}catch(error){setStatus(error.message,false);saveButton.disabled=false}}reloadRules()
</script></body></html>'''
RULES_PAGE = RULES_PAGE.replace(
    "fetch(path,{...opt,headers:",
    "fetch(new URL(path,location.origin),{...opt,headers:",
    1,
)
RULES_PAGE = RULES_PAGE.replace('href="http://__FAMILY_PROXY_IP__:18091/"', 'href="/dns/"')
PAGE = PAGE.replace(
    '<a class="active" href="/">设备</a><a href="/rules">规则</a><a href="/airport/">机场与候选池</a></nav>',
    '<a class="active" href="/">设备</a><a href="/dns/">DNS</a><a href="/airport/">机场与候选池</a><a href="/rules">规则</a><a href="/mihomo-maintenance">维护</a></nav>',
    1,
)
PAGE = PAGE.replace('</style>', '@media(max-width:760px){.nav{grid-template-columns:repeat(5,1fr)}}</style>', 1)
RULES_PAGE = RULES_PAGE.replace(
    '<a href="/">设备</a><a class="active" href="/rules">规则</a><a href="/airport/">机场与候选池</a><a href="/dns/">DNS</a>',
    '<a href="/">设备</a><a href="/dns/">DNS</a><a href="/airport/">机场与候选池</a><a class="active" href="/rules">规则</a><a href="/mihomo-maintenance">维护</a>',
    1,
)
PAGE = PAGE.replace(
    "fetch(path,{...opt,headers:",
    "fetch(new URL(path,location.origin),{...opt,headers:",
    1,
)


MIHOMO_PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>Mihomo 节点</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;background:#000}.wrap{max-width:820px;margin:auto;padding:36px 18px 60px}a{color:#0a84ff;text-decoration:none}h1{font-size:30px;margin:24px 0 7px;letter-spacing:0}.sub{color:#8e8e93;margin:0 0 24px}.group{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.row{display:grid;grid-template-columns:160px 1fr auto;align-items:center;gap:14px;padding:14px 16px;border-top:1px solid #38383a}.row:first-child{border-top:0}h2{font-size:15px;margin:0}.current{color:#8e8e93;font-size:12px;margin-top:4px;overflow-wrap:anywhere}select{min-width:0;width:100%;height:38px;padding:0 10px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;font:14px inherit}button{height:38px;border:0;border-radius:7px;background:#0a84ff;color:#fff;padding:0 15px;font-weight:600}.status{margin-top:14px;color:#30d158}.error{color:#ff453a}@media(max-width:620px){.row{grid-template-columns:1fr}.wrap{padding-top:24px}button{width:100%}}</style></head><body><main class="wrap"><a href="/">返回设备管理</a><h1>节点管理</h1><p class="sub">手动选择只影响对应业务组；AI 组不使用香港节点。</p><div class="group" id="groups"></div><div class="status" id="status"></div></main><script>const csrf="__CSRF__",status=document.querySelector('#status');function esc(s){return String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}async function req(path,opt={}){let r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}async function load(){try{let d=await req('/api/mihomo');document.querySelector('#groups').innerHTML=d.groups.map(g=>`<section class="row"><div><h2>${esc(g.name)}</h2><div class="current">当前：${esc(g.now||'未选择')}</div></div><select id="group-${esc(g.name)}">${g.all.map(n=>`<option ${n===g.now?'selected':''}>${esc(n)}</option>`).join('')}</select><button onclick="choose('${esc(g.name)}')">应用</button></section>`).join('')}catch(e){status.textContent=e.message;status.className='status error'}}async function choose(group){try{let node=document.querySelector('#group-'+group).value,d=await req('/api/mihomo/select',{method:'POST',body:JSON.stringify({group,node})});status.textContent=d.message;status.className='status';await load()}catch(e){status.textContent=e.message;status.className='status error'}}load()</script></body></html>'''

MIHOMO_MAINTENANCE_PAGE = r'''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mihomo 维护</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0}.wrap{max-width:760px;margin:auto;padding:34px 18px}a{color:#0a84ff;text-decoration:none}h1{font-size:30px;margin:24px 0 7px}.sub,.detail{color:#8e8e93;line-height:1.55}.panel{margin-top:22px;padding:18px;border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e}.state{font-weight:650;color:#30d158}.state.bad{color:#ff453a}.state.warn{color:#ffd60a}.actions{display:flex;gap:9px;margin-top:16px;flex-wrap:wrap}button{height:38px;border:0;border-radius:7px;padding:0 14px;background:#2c2c2e;color:#f5f5f7;font:600 14px inherit}.primary{background:#0a84ff}.meta{margin-top:14px;font:12px ui-monospace,monospace;color:#8e8e93;overflow-wrap:anywhere}.release{margin-top:14px;padding:11px;border-radius:7px;background:#2c2c2e;color:#aeaeb2;font-size:13px;line-height:1.55}@media(max-width:520px){.actions button{width:100%}}</style><main class="wrap"><a href="/">返回设备管理</a><h1>Mihomo 维护</h1><p class="sub">不自动升级。检查不会拉取镜像或重启容器；升级只重建 Mihomo，并在失败时自动恢复旧镜像。</p><section class="panel"><div class="state" id="state">正在读取状态</div><p class="detail" id="message"></p><div class="actions"><button onclick="check()">检查更新</button><button class="primary" id="upgrade" onclick="upgrade()">升级并验证</button></div><div class="meta" id="meta"></div><div class="release" id="release">尚未取得发布说明</div></section></main><script>const csrf="__CSRF__",state=document.querySelector('#state'),message=document.querySelector('#message'),meta=document.querySelector('#meta'),release=document.querySelector('#release'),upgradeButton=document.querySelector('#upgrade');async function api(path,opt={}){let r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}function render(d){let busy=['applying','busy'].includes(d.state),bad=['failed','check_failed','rolled_back'].includes(d.state),warn=['update_available','applying','busy'].includes(d.state);state.textContent=({unknown:'尚未检查',checked:'检查完成',current:'当前已是最新',update_available:'发现可用更新',applying:'正在升级',success:'升级完成',rolled_back:'已自动回退',failed:'维护失败',check_failed:'检查失败',busy:'维护任务进行中'})[d.state]||d.state;state.className='state '+(bad?'bad':warn?'warn':'');message.textContent=d.message||'';meta.textContent=[d.current_version?`当前内核：${d.current_version}`:'',d.latest_version?`最新通道：${d.latest_version}`:'',d.latest_published?`最新构建说明时间：${d.latest_published}`:'',d.old_image_id?`当前镜像：${d.old_image_id.slice(0,19)}`:'',d.new_image_id?`最新镜像：${d.new_image_id.slice(0,19)}`:''].filter(Boolean).join(' · ');release.textContent=(d.release_notes_zh||'官方未提供可翻译的逐项变更说明。')+(d.docker_proxy_ready?'':' Docker 守护进程没有代理，已禁止执行升级。');upgradeButton.disabled=busy||d.docker_proxy_ready===false}async function load(){try{render(await api('/api/mihomo/upgrade'))}catch(e){state.textContent=e.message;state.className='state bad'}}async function check(){try{await api('/api/mihomo/upgrade/check',{method:'POST'});state.textContent='正在检查镜像仓库';state.className='state warn';setTimeout(load,1500)}catch(e){state.textContent=e.message;state.className='state bad'}}async function upgrade(){if(!confirm('升级将短暂重建 Mihomo 容器。系统会备份当前配置、保留旧镜像并在验证失败时自动回退。继续？'))return;try{await api('/api/mihomo/upgrade/apply',{method:'POST'});state.textContent='正在升级并验证';state.className='state warn';upgradeButton.disabled=true;poll()}catch(e){state.textContent=e.message;state.className='state bad'}}async function poll(){await load();let text=state.textContent;if(['正在升级','维护任务进行中'].includes(text))setTimeout(poll,2000)}load()</script>'''


MIHOMO_MAINTENANCE_PAGE = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>系统维护</title>
<style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;background:#000}.topbar{position:sticky;top:0;z-index:5;border-bottom:1px solid rgba(255,255,255,.1);background:rgba(18,18,20,.88);backdrop-filter:saturate(180%) blur(22px)}.topbar-inner,.wrap{width:min(1040px,calc(100% - 44px));margin:auto}.topbar-inner{min-height:58px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-size:17px;font-weight:650}.nav{display:flex;gap:4px;padding:3px;border-radius:8px;background:#2c2c2e}.nav a{padding:7px 11px;border-radius:6px;color:#aeaeb2;text-decoration:none;font-size:13px;white-space:nowrap}.nav a.active{background:#636366;color:#fff}.wrap{padding:38px 0 64px}.intro{margin-bottom:24px}.intro h1{margin:0;font-size:30px;line-height:1.15}.intro p{margin:9px 0 0;color:#98989d;line-height:1.55}.summary{display:flex;gap:8px;flex-wrap:wrap;margin-top:17px}.summary-item{display:flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #2c2c2e;border-radius:7px;background:#1c1c1e;color:#aeaeb2;font-size:12px}.dot{width:8px;height:8px;border-radius:50%;background:#636366}.dot.ok{background:#30d158}.dot.warn{background:#ffd60a}.dot.bad{background:#ff453a}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.card{overflow:hidden;border:1px solid #38383a;border-radius:8px;background:#1c1c1e}.card-head{display:flex;justify-content:space-between;gap:14px;padding:16px;border-bottom:1px solid #38383a}.card h2{margin:0;font-size:17px}.card-head p{margin:5px 0 0;color:#8e8e93;font-size:12px;line-height:1.5}.badge{align-self:flex-start;padding:4px 7px;border-radius:6px;background:rgba(48,209,88,.12);color:#30d158;font-size:12px;font-weight:650;white-space:nowrap}.badge.warn{background:rgba(255,214,10,.12);color:#ffd60a}.badge.bad{background:rgba(255,69,58,.12);color:#ff6961}.facts{display:grid;grid-template-columns:1fr 1fr}.fact{min-height:74px;padding:14px;border-left:1px solid #38383a;border-bottom:1px solid #38383a}.fact:nth-child(odd){border-left:0}.label{display:block;color:#8e8e93;font-size:12px}.value{display:block;margin-top:8px;font-size:13px;font-weight:650;overflow-wrap:anywhere}.detail{min-height:78px;padding:14px;border-bottom:1px solid #38383a;color:#aeaeb2;font-size:13px;line-height:1.55}.actions{display:flex;gap:8px;flex-wrap:wrap;padding:14px}button{height:36px;padding:0 13px;border:0;border-radius:7px;background:#3a3a3c;color:#f5f5f7;font:600 13px inherit;cursor:pointer}button.primary{background:#0a84ff}button:disabled{cursor:default;opacity:.45}.notice{margin-top:18px;padding:12px 14px;border-left:3px solid #636366;border-radius:0 7px 7px 0;background:#1c1c1e;color:#98989d;font-size:12px;line-height:1.6}@media(max-width:760px){.topbar-inner{min-height:auto;padding:10px 0;align-items:flex-start;flex-direction:column;gap:8px}.nav{width:100%;display:grid;grid-template-columns:repeat(5,1fr)}.nav a{text-align:center;padding:7px 4px;white-space:normal}.grid{grid-template-columns:1fr}.wrap{padding:28px 0 50px}}@media(max-width:420px){.facts{grid-template-columns:1fr}.fact{border-left:0}.actions button{flex:1 1 100%}}
</style></head><body><header class="topbar"><div class="topbar-inner"><div class="brand">家庭旁路</div><nav class="nav"><a href="/">设备</a><a href="/dns/">DNS</a><a href="/airport/">机场与候选池</a><a href="/rules">规则</a><a class="active" href="/mihomo-maintenance">维护</a></nav></div></header><main class="wrap"><section class="intro"><h1>系统维护</h1><p>仅在手动确认后更新组件。检查不重启服务；升级会先备份并在健康检查失败时自动回退。</p><div class="summary"><span class="summary-item"><i id="mihomo-dot" class="dot"></i><span>Mihomo</span></span><span class="summary-item"><i id="mosdns-dot" class="dot"></i><span>MosDNS</span></span></div></section><section class="grid"><article class="card"><div class="card-head"><div><h2>Mihomo</h2><p>透明代理内核与候选池运行环境</p></div><span id="mihomo-badge" class="badge">读取中</span></div><div class="facts"><div class="fact"><span class="label">当前版本</span><span id="mihomo-current" class="value">--</span></div><div class="fact"><span class="label">可用版本</span><span id="mihomo-latest" class="value">--</span></div><div class="fact"><span class="label">检查时间</span><span id="mihomo-time" class="value">--</span></div><div class="fact"><span class="label">升级条件</span><span id="mihomo-ready" class="value">--</span></div></div><div id="mihomo-detail" class="detail">正在读取维护状态。</div><div class="actions"><button id="mihomo-check">检查更新</button><button id="mihomo-apply" class="primary">升级并验证</button></div></article><article class="card"><div class="card-head"><div><h2>MosDNS</h2><p>DNS 解析内核，不改变现有分流规则</p></div><span id="mosdns-badge" class="badge">读取中</span></div><div class="facts"><div class="fact"><span class="label">当前版本</span><span id="mosdns-current" class="value">--</span></div><div class="fact"><span class="label">官方镜像</span><span id="mosdns-latest" class="value">等待检查</span></div><div class="fact"><span class="label">检查时间</span><span id="mosdns-time" class="value">--</span></div><div class="fact"><span class="label">自动更新</span><span id="mosdns-auto" class="value">--</span></div></div><div id="mosdns-detail" class="detail">正在读取维护状态。</div><div class="actions"><button id="mosdns-check">检查更新</button><button id="mosdns-apply" class="primary" disabled>升级并验证</button></div></article></section><p class="notice">维护页只汇总组件软件更新。DNS 上游、规则数据、广告过滤、候选池和 RouterOS 设置仍在各自页面管理，保持原有行为不变。</p></main><script>
let csrf='__CSRF__'; const $=s=>document.querySelector(s); const labels={unknown:'尚未检查',checked:'检查完成',current:'已是最新',update_available:'有可用更新',applying:'升级中',success:'升级完成',rolled_back:'已自动回退',failed:'维护失败',check_failed:'检查失败',busy:'任务进行中',idle:'尚未检查',checking:'检查中',available:'有可用更新',up_to_date:'已是最新',updating:'升级中',updated:'升级完成',rolling_back:'正在回退',error:'需要检查'};
function stamp(value){if(!value)return '尚无记录';let d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString('zh-CN',{hour12:false})}function shortImage(value){let text=String(value||'');return text.startsWith('sha256:')?'sha256:'+text.slice(7,19):text||'等待检查'}function setState(name,phase,bad,warn){let text=labels[phase]||phase||'尚未检查',klass=bad?'bad':warn?'warn':'';$('#'+name+'-badge').textContent=text;$('#'+name+'-badge').className='badge '+klass;$('#'+name+'-dot').className='dot '+(bad?'bad':warn?'warn':'ok')}
async function renewCsrf(){let r=await fetch('/api/csrf',{cache:'no-store'}),d=await r.json().catch(()=>({}));if(!r.ok||!d.csrf)throw Error('页面安全状态已过期，请重新打开本页');csrf=d.csrf}async function api(path,options={},retried=false){let r=await fetch(path,{cache:'no-store',...options,headers:{'Content-Type':'application/json','X-CSRF':csrf,'X-Requested-With':'family-dns',...(options.headers||{})}}),d=await r.json().catch(()=>({}));if(r.status===403&&d.error==='request rejected'&&!retried){await renewCsrf();return api(path,options,true)}if(!r.ok)throw Error(d.error||d.message||'请求失败');return d}
function renderMihomo(d){let busy=['applying','busy'].includes(d.state),bad=['failed','check_failed','rolled_back'].includes(d.state),warn=busy||d.state==='update_available';setState('mihomo',d.state,bad,warn);$('#mihomo-current').textContent=d.current_version||'--';$('#mihomo-latest').textContent=d.latest_version||'等待检查';$('#mihomo-time').textContent=stamp(d.latest_published);$('#mihomo-ready').textContent=d.docker_proxy_ready===false?'Docker 代理未就绪':'已满足升级条件';$('#mihomo-detail').textContent=(d.message||'尚未检查更新')+(d.release_notes_zh?' · '+d.release_notes_zh:'');$('#mihomo-check').disabled=busy;$('#mihomo-apply').disabled=busy||d.docker_proxy_ready===false}
function renderMosdns(d){let busy=Boolean(d.busy)||['checking','updating','rolling_back'].includes(d.phase),bad=['error','rolled_back'].includes(d.phase),warn=busy||Boolean(d.update_available);setState('mosdns',d.phase,bad,warn);$('#mosdns-current').textContent=d.current_version||'--';$('#mosdns-latest').textContent=shortImage(d.latest_image);$('#mosdns-time').textContent=stamp(d.completed_at||d.checked_at||d.updated_at);$('#mosdns-auto').textContent=d.config?.auto_enabled?'已开启':'已关闭';$('#mosdns-detail').textContent=(d.message||'尚未检查软件更新')+'。升级前会备份，验证失败将自动回退。';$('#mosdns-check').disabled=busy;$('#mosdns-apply').disabled=busy||!d.update_available}
async function loadMihomo(){try{renderMihomo(await api('/api/mihomo/upgrade'))}catch(e){setState('mihomo','维护失败',true,false);$('#mihomo-detail').textContent=e.message}}async function loadMosdns(){try{renderMosdns(await api('/dns/maintenance-api/status'))}catch(e){setState('mosdns','维护失败',true,false);$('#mosdns-detail').textContent=e.message}}
async function poll(load,selector){for(let n=0;n<180;n++){await new Promise(r=>setTimeout(r,2000));await load();if(!$(selector).textContent.match(/检查中|升级中|正在回退|任务进行中/))break}}
async function runAction(button,detail,text,success,action,load,selector){let original=button.textContent;button.disabled=true;button.textContent=text;detail.textContent=text+'，请稍候…';try{await action();await poll(load,selector);detail.textContent=success+'。'+detail.textContent}catch(e){detail.textContent='操作失败：'+e.message;button.disabled=false;button.textContent=original;return}button.textContent=original;button.disabled=false}$('#mihomo-check').onclick=()=>runAction($('#mihomo-check'),$('#mihomo-detail'),'正在检查更新','检查完成，已刷新版本信息',()=>api('/api/mihomo/upgrade/check',{method:'POST'}),loadMihomo,'#mihomo-badge');$('#mihomo-apply').onclick=()=>{if(confirm('升级将短暂重建 Mihomo。系统会保留旧镜像，验证失败自动回退。继续？'))runAction($('#mihomo-apply'),$('#mihomo-detail'),'正在升级并验证','升级流程已完成',()=>api('/api/mihomo/upgrade/apply',{method:'POST'}),loadMihomo,'#mihomo-badge')};$('#mosdns-check').onclick=()=>runAction($('#mosdns-check'),$('#mosdns-detail'),'正在检查更新','检查完成，已刷新版本信息',()=>api('/dns/maintenance-api/check',{method:'POST'}),loadMosdns,'#mosdns-badge');$('#mosdns-apply').onclick=()=>{if(confirm('升级将短暂重启 MosDNS。配置会先备份，验证失败自动回退。继续？'))runAction($('#mosdns-apply'),$('#mosdns-detail'),'正在升级并验证','升级流程已完成',()=>api('/dns/maintenance-api/update',{method:'POST'}),loadMosdns,'#mosdns-badge')};Promise.all([loadMihomo(),loadMosdns()]);
</script></body></html>'''

MIHOMO_MAINTENANCE_PAGE = MIHOMO_MAINTENANCE_PAGE.replace(
    '>官方镜像</span><span id="mosdns-latest"',
    '>整合镜像源</span><span id="mosdns-latest"',
)

_ALERT_CARD = r'''<section class="card alert-card"><div class="card-head"><div><h2>Telegram 告警</h2><p>所选机场来源在某业务池的候选节点全部连续两轮不可用时通知；恢复后可选发送恢复消息。</p></div><span id="alert-badge" class="badge">读取中</span></div><div class="alert-form"><label><span>Bot Token</span><input id="alert-token" type="password" autocomplete="new-password" placeholder="留空则保持已保存的 Token"></label><label><span>Chat ID</span><input id="alert-chat" autocomplete="off" placeholder="填写接收通知的 Chat ID"></label><div class="source-select"><span>告警机场来源</span><div id="alert-sources" class="source-options"></div></div><label class="toggle"><input id="alert-enabled" type="checkbox"><span>启用候选池故障告警</span></label><label class="toggle"><input id="alert-recovery" type="checkbox" checked><span>节点恢复时发送恢复通知</span></label></div><div id="alert-detail" class="detail">正在读取告警设置。</div><div class="actions"><button id="alert-save" class="primary">保存告警设置</button><button id="alert-test">发送测试消息</button></div></section>'''

_ALERT_SCRIPT = r'''function renderAlerts(d){let enabled=Boolean(d.enabled),configured=Boolean(d.configured),selected=new Set(d.source_slots||[]);$('#alert-badge').textContent=enabled&&configured?'已启用':configured?'已配置':'未配置';$('#alert-badge').className='badge '+(enabled&&configured?'':'warn');$('#alert-enabled').checked=enabled;$('#alert-recovery').checked=d.notify_recovery!==false;$('#alert-chat').placeholder=d.chat_id_masked?`已保存：${d.chat_id_masked}；留空保持不变`:'填写接收通知的 Chat ID';$('#alert-sources').innerHTML=(d.available_sources||[]).map(s=>`<label class="source-option"><input type="checkbox" value="${s.slot}" ${selected.has(s.slot)?'checked':''}><span>${s.label}</span></label>`).join('')||'<span class="muted">尚无可选机场</span>';$('#alert-detail').textContent=enabled&&configured?'所选机场来源的候选节点全部不可用时推送；同一故障只通知一次。':configured?'凭据已保存，选择机场来源并启用后开始监控。':'请填写 Bot Token 与 Chat ID 后保存。'}async function loadAlerts(){try{renderAlerts(await api('/api/alerts'))}catch(e){$('#alert-badge').textContent='读取失败';$('#alert-badge').className='badge bad';$('#alert-detail').textContent=e.message}}async function runAlertAction(button,working,action){let original=button.textContent;button.disabled=true;button.textContent=working;$('#alert-detail').textContent=working+'，请稍候…';try{let result=await action();await loadAlerts();$('#alert-detail').textContent=result.message||'操作已完成'}catch(e){$('#alert-detail').textContent='操作失败：'+e.message}finally{button.disabled=false;button.textContent=original}}$('#alert-save').onclick=()=>runAlertAction($('#alert-save'),'正在保存',async()=>{let sources=[...document.querySelectorAll('#alert-sources input:checked')].map(x=>x.value),d=await api('/api/alerts',{method:'POST',body:JSON.stringify({enabled:$('#alert-enabled').checked,notify_recovery:$('#alert-recovery').checked,source_slots:sources,token:$('#alert-token').value.trim(),chat_id:$('#alert-chat').value.trim()})});$('#alert-token').value='';$('#alert-chat').value='';return {...d,message:'告警设置已保存'}});$('#alert-test').onclick=()=>runAlertAction($('#alert-test'),'正在发送',()=>api('/api/alerts/test',{method:'POST'}));'''

MIHOMO_MAINTENANCE_PAGE = MIHOMO_MAINTENANCE_PAGE.replace(
    '</section><p class="notice">', '</section>' + _ALERT_CARD + '<p class="notice">', 1,
).replace(
    '</style>', '.alert-card{margin-top:14px}.alert-form{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:14px;border-bottom:1px solid #38383a}.alert-form label,.source-select{display:grid;gap:6px;color:#aeaeb2;font-size:12px}.alert-form input[type="password"],.alert-form input:not([type]){height:36px;padding:0 10px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#f5f5f7;font:14px inherit}.source-options{display:flex;flex-wrap:wrap;gap:7px}.source-options .source-option{display:flex;align-items:center;gap:6px;padding:7px 8px;border:1px solid #48484a;border-radius:6px;background:#2c2c2e;font-size:13px}.source-option input{width:15px;height:15px;accent-color:#0a84ff}.alert-form .toggle{display:flex;align-items:center;gap:8px;font-size:13px}.alert-form .toggle input{width:16px;height:16px;accent-color:#0a84ff}@media(max-width:760px){.alert-form{grid-template-columns:1fr}}</style>', 1,
).replace(
    'Promise.all([loadMihomo(),loadMosdns()]);', _ALERT_SCRIPT + 'Promise.all([loadMihomo(),loadMosdns(),loadAlerts()]);', 1,
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def allowed(self):
        if trusted_gateway(self.client_address[0], self.headers.get("X-Family-Gateway", "")):
            return True
        try:
            return ipaddress.ip_address(self.client_address[0]) in LAN
        except ValueError:
            return False

    def reply(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def require_auth(self):
        if trusted_gateway(self.client_address[0], self.headers.get("X-Family-Gateway", "")):
            return True
        if valid_basic_auth(self.headers.get("Authorization", "")):
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Family Proxy"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return False

    def send_capture_file(self, capture_id):
        try:
            capture_path, metadata_path = capture_paths(capture_id)
            metadata = read_capture_metadata(metadata_path)
            if not metadata or metadata.get("status") == "running" or not capture_path.exists():
                raise RouterError("抓包文件尚不可下载")
            size = capture_path.stat().st_size
            if size < 24 or size > CAPTURE_MAX_BYTES:
                raise RouterError("抓包文件为空或超过安全限制")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{capture_id}.pcap"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with capture_path.open("rb") as handle:
                shutil.copyfileobj(handle, self.wfile, length=1024 * 1024)
        except RouterError as exc:
            self.reply(HTTPStatus.NOT_FOUND, {"error": str(exc)})

    def do_GET(self):
        if not self.allowed():
            self.reply(HTTPStatus.FORBIDDEN, {"error": "LAN only"})
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" and self.client_address[0] == "__FAMILY_ROUTER_IP__":
            health = gated_health()
            self.reply(HTTPStatus.OK if health["ready"] else HTTPStatus.SERVICE_UNAVAILABLE, health)
            return
        if not self.require_auth():
            return
        if path == "/":
            data = PAGE.replace("__CSRF__", CSRF_TOKEN).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/rules":
            try:
                template = RULES_TEMPLATE_PATH.read_text(encoding="utf-8")
            except OSError:
                template = RULES_PAGE
            nav_start = template.find('<nav class="nav"')
            nav_end = template.find("</nav>", nav_start)
            if nav_start >= 0 and nav_end >= 0:
                navigation = ('<nav class="nav"><a href="/">设备</a><a href="/dns/">DNS</a>'
                              '<a href="/airport/">机场与候选池</a>'
                              '<a class="active" href="/rules">规则</a>'
                              '<a href="/mihomo-maintenance">维护</a></nav>')
                template = template[:nav_start] + navigation + template[nav_end + len("</nav>"):]
            data = template.replace("__CSRF__", CSRF_TOKEN).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/mihomo":
            data = MIHOMO_PAGE.replace("__CSRF__", CSRF_TOKEN).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/mihomo-maintenance":
            data = MIHOMO_MAINTENANCE_PAGE.replace("__CSRF__", CSRF_TOKEN).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/system/status":
            try:
                self.reply(HTTPStatus.OK, system_status())
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.reply(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": f"Z4Pro 状态读取失败：{exc}"},
                )
            return
        if path == "/api/wireguard/status":
            try:
                self.reply(HTTPStatus.OK, wireguard_status())
            except (RouterError, OSError, ValueError) as exc:
                self.reply(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": f"WireGuard 状态读取失败：{exc}"},
                )
            return
        if path == "/api/captures":
            try:
                query = parse_qs(parsed.query)
                self.reply(HTTPStatus.OK, list_captures(query.get("ip", [None])[0]))
            except (RouterError, OSError) as exc:
                self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        if path == "/api/capture/download":
            query = parse_qs(parsed.query)
            self.send_capture_file(query.get("id", [""])[0])
            return
        if path == "/api/devices":
            try:
                self.reply(HTTPStatus.OK, list_devices())
            except (RouterError, OSError) as exc:
                self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        if path == "/api/health":
            health = local_health()
            self.reply(HTTPStatus.OK if health["ready"] else HTTPStatus.SERVICE_UNAVAILABLE, health)
            return
        if path == "/api/csrf":
            self.reply(HTTPStatus.OK, {"csrf": CSRF_TOKEN})
            return
        if path == "/api/mihomo":
            try:
                self.reply(HTTPStatus.OK, mihomo_groups())
            except RouterError as exc:
                self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        if path == "/api/mihomo/upgrade":
            try:
                self.reply(HTTPStatus.OK, mihomo_upgrade_status())
            except (RouterError, OSError, subprocess.SubprocessError) as exc:
                self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        if path == "/api/alerts":
            try:
                self.reply(HTTPStatus.OK, load_alert_settings())
            except RouterError as exc:
                self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        if path == "/api/rules":
            try:
                self.reply(HTTPStatus.OK, rules_payload())
            except RouterError as exc:
                self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if not self.allowed():
            self.reply(HTTPStatus.FORBIDDEN, {"error": "request rejected"})
            return
        if not self.require_auth():
            return
        if self.headers.get("X-CSRF") != CSRF_TOKEN:
            self.reply(HTTPStatus.FORBIDDEN, {"error": "request rejected"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 262144:
                raise RouterError("请求内容过大")
            body = json.loads(self.rfile.read(size) or "{}")
            path = urlparse(self.path).path
            if path == "/api/enable":
                self.reply(HTTPStatus.OK, enable_device(body.get("ip", "")))
            elif path == "/api/remove":
                self.reply(HTTPStatus.OK, remove_device(body.get("ip", "")))
            elif path == "/api/device/preference":
                self.reply(HTTPStatus.OK, update_device_preference(
                    body.get("mac", ""), body.get("alias") if "alias" in body else None,
                    body.get("favorite") if "favorite" in body else None,
                ))
            elif path == "/api/capture/start":
                self.reply(HTTPStatus.OK, start_capture(
                    body.get("ip", ""), body.get("duration", 60), body.get("scope", "all")))
            elif path == "/api/capture/stop":
                self.reply(HTTPStatus.OK, stop_capture(body.get("id", "")))
            elif path == "/api/capture/delete":
                self.reply(HTTPStatus.OK, delete_capture(body.get("id", "")))
            elif path == "/api/mihomo/select":
                self.reply(HTTPStatus.OK, select_mihomo_node(body.get("group", ""), body.get("node", "")))
            elif path == "/api/mihomo/upgrade/check":
                self.reply(HTTPStatus.OK, start_mihomo_upgrade("family-mihomo-upgrade-check.service"))
            elif path == "/api/mihomo/upgrade/apply":
                self.reply(HTTPStatus.OK, start_mihomo_upgrade("family-mihomo-upgrade.service"))
            elif path == "/api/alerts":
                self.reply(HTTPStatus.OK, save_alert_settings(body))
            elif path == "/api/alerts/test":
                self.reply(HTTPStatus.OK, send_alert_test())
            elif path == "/api/rules":
                self.reply(HTTPStatus.OK, save_mihomo_rules(body.get("rules"), body.get("version", "")))
            else:
                self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (RouterError, ValueError, OSError, json.JSONDecodeError) as exc:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


if __name__ == "__main__":
    with CAPTURE_LOCK:
        cleanup_captures()
    threading.Thread(target=capture_cleanup_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 18093), Handler).serve_forever()
