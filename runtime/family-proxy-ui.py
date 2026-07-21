#!/usr/bin/env python3
"""LAN-only controller for selected-device family Mihomo routing."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import threading
import time
import yaml
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


CONFIG_PATH = Path("/etc/family-proxy-ui/router.env")
GATEWAY_SECRET_PATH = Path("/etc/family-proxy-ui/gateway.secret")
MANAGED_IPS_PATH = Path("/etc/family-proxy-ui/managed-ips")
DEVICE_PREFS_PATH = Path("/etc/family-proxy-ui/device-preferences.json")
TPROXY_SYNC = "/usr/local/sbin/family-mihomo-tproxy-auto"
MIHOMO_API = "http://127.0.0.1:9091"
MIHOMO_CONFIG_PATH = Path("__FAMILY_DOCKER_ROOT__/family-mihomo-fallback/config.yaml")
RULE_BACKUP_DIR = MIHOMO_CONFIG_PATH.parent / "rule-backups"
RULES_TEMPLATE_PATH = Path("/opt/family-proxy-ui/rules.html")
MIHOMO_GROUPS = ("AI", "Youtube", "Telegram", "Google", "Others")
LAN = ipaddress.ip_network("__FAMILY_LAN_CIDR__")
PROXY_IP = "__FAMILY_PROXY_IP__"
FIXED_MANAGED_IPS = set()
RESERVED_IPS = {"__FAMILY_ROUTER_IP__", "__FAMILY_RESERVED_GATEWAY_IP__", PROXY_IP}
AUDIT_PATH = Path("/var/log/family-proxy-ui-audit.jsonl")
CSRF_TOKEN = secrets.token_urlsafe(32)
HEALTH_LOCK = threading.Lock()
HEALTH_GATE = {"ready": True, "failures": 0, "successes": 0}
RULES_LOCK = threading.Lock()
DEVICE_PREFS_LOCK = threading.Lock()
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
        checks["dns"] = dns_probe()
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


def router_summary(api):
    checks = api.print("/tool/netwatch")
    health = next((item for item in checks if item.get("name") == "family-mihomo-tproxy-health"), None)
    summary = local_health()
    summary.update({
        "netwatch": health.get("status", "unknown") if health else "missing",
        "router": "connected",
    })
    return summary


def list_devices():
    with DEVICE_PREFS_LOCK:
        preferences = load_device_preferences()
    favorite_macs = set(preferences["favorites"])
    managed_macs = set()
    with RouterOS() as api:
        leases = api.print("/ip/dhcp-server/lease")
        mangle = api.print("/ip/firewall/mangle")
        managed = set()
        counters = {}
        for rule in mangle:
            comment = rule.get("comment", "")
            address = policy_address(comment)
            if address:
                managed.add(address)
                counters[address] = int(rule.get("packets", "0") or 0)
        devices = []
        for lease in leases:
            ip = lease.get("address")
            if not ip or ipaddress.ip_address(ip) not in LAN or ip in RESERVED_IPS:
                continue
            mac = lease.get("mac-address", "").upper()
            if not mac:
                continue
            packets = counters.get(ip, 0)
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
                "effective": is_managed and packets > 0,
            })
        summary = router_summary(api)
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
    tag = managed_tag(ip)
    expected = {
        "/ip/firewall/mangle": 3,
        "/ip/firewall/nat": 2,
        "/ip/firewall/filter": 1,
        "/ipv6/firewall/filter": 1,
        "/ip/route": 1,
    }
    missing = []
    for path, count in expected.items():
        actual = sum(item.get("comment", "").startswith(tag) for item in api.print(path))
        if actual < count:
            missing.append(f"{path}:{actual}/{count}")
    if missing:
        raise RouterError("规则创建不完整：" + ", ".join(missing))


def enable_device(ip):
    ip = validate_ip(ip)
    tag = managed_tag(ip)
    suffix = ip.rsplit(".", 1)[1]
    table = f"family_mihomo_auto_{suffix}"
    mark = f"family_mihomo_auto_{suffix}_conn"
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
        if any(rule.get("comment", "").startswith(tag) for rule in api.print("/ip/firewall/mangle")):
            raise RouterError("该设备已由页面管理")
        conflict = conflicting_policy(api, ip)
        if conflict:
            raise RouterError(f"设备仍命中其它策略：{conflict}；请先解除冲突")

        if lease.get("dynamic") == "true":
            api.talk("/ip/dhcp-server/lease/make-static", {".id": lease[".id"]})
        try:
            ensure_table(api, table)
            ensure_policy_anchors(api)
            mangle_anchor = rule_id(api, "/ip/firewall/mangle", "family-mihomo-auto anchor")
            nat_anchor = rule_id(api, "/ip/firewall/nat", "family-mihomo-auto DNS anchor")
            api.add("/ip/route", **{
                "dst-address": "0.0.0.0/0", "gateway": PROXY_IP, "routing-table": table,
                "check-gateway": "ping", "comment": tag + " route",
            })
            route_id = add_before(api, "/ip/firewall/mangle", mangle_anchor, chain="prerouting", action="mark-routing",
                                  **{"new-routing-mark": table, "passthrough": "no", "src-address": ip,
                                     "connection-mark": mark, "comment": tag + " route to z4pro"})
            mark_id = add_before(api, "/ip/firewall/mangle", route_id, chain="prerouting", action="mark-connection",
                                 **{"new-connection-mark": mark, "passthrough": "yes", "src-address": ip,
                                    "dst-address-list": "!local_lan_ipv4", "connection-mark": "no-mark",
                                    "comment": tag + " mark connection"})
            add_before(api, "/ip/firewall/mangle", mark_id, chain="prerouting", action="accept", **{
                "src-address": ip, "dst-address-list": "local_lan_ipv4", "comment": tag + " local bypass",
            })
            tcp_id = add_before(api, "/ip/firewall/nat", nat_anchor, chain="dstnat", action="dst-nat", protocol="tcp", **{
                "src-address": ip, "dst-port": "53", "to-addresses": PROXY_IP, "to-ports": "53",
                "comment": tag + " DNS TCP",
            })
            add_before(api, "/ip/firewall/nat", tcp_id, chain="dstnat", action="dst-nat", protocol="udp", **{
                "src-address": ip, "dst-port": "53", "to-addresses": PROXY_IP, "to-ports": "53",
                "comment": tag + " DNS UDP",
            })
            fasttrack = next((rule for rule in api.print("/ip/firewall/filter") if rule.get("action") == "fasttrack-connection"), None)
            fasttrack_id = fasttrack.get(".id") if fasttrack else None
            api.add("/ip/firewall/filter", chain="forward", action="accept", **{
                "connection-mark": mark, "comment": tag + " FastTrack exclude",
            })
            excludes = [rule for rule in api.print("/ip/firewall/filter") if rule.get("comment") == tag + " FastTrack exclude"]
            exclude_id = excludes[-1][".id"] if excludes else None
            if exclude_id and fasttrack_id:
                api.talk("/ip/firewall/filter/move", {"numbers": exclude_id, "destination": fasttrack_id})

            ipv6_filters = api.print("/ipv6/firewall/filter")
            if not any(rule.get("comment") == "family-mihomo-auto IPv6 drop" for rule in ipv6_filters):
                api.add("/ipv6/firewall/filter", chain="family_mihomo_auto_v6", action="drop", comment="family-mihomo-auto IPv6 drop")
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
            cleanup_device_rules(api, ip)
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
        removed = cleanup_device_rules(api, ip)
        addresses = managed_ips()
        addresses.discard(ip)
        save_managed_ips(addresses)
        sync_tproxy()
        audit("remove", ip, "success", f"removed_rules={removed}")
        return {"ip": ip, "message": f"已移除 {removed} 条页面管理规则，设备恢复直连"}


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
    'grid-template-columns:repeat(3,1fr)}.nav a{text-align:center;padding:7px 5px}',
    'grid-template-columns:repeat(4,1fr)}.nav a{text-align:center;padding:7px 5px;white-space:normal}',
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
PAGE = PAGE.replace(
    '<a href="/airport/">机场与候选池</a></nav>',
    '<a href="/airport/">机场与候选池</a>'
    '<a href="http://__FAMILY_PROXY_IP__:18091/">DNS</a></nav>',
    1,
)
PAGE = PAGE.replace(
    "fetch(path,{...opt,headers:",
    "fetch(new URL(path,location.origin),{...opt,headers:",
    1,
)


MIHOMO_PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>Mihomo 节点</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;background:#000}.wrap{max-width:820px;margin:auto;padding:36px 18px 60px}a{color:#0a84ff;text-decoration:none}h1{font-size:30px;margin:24px 0 7px;letter-spacing:0}.sub{color:#8e8e93;margin:0 0 24px}.group{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.row{display:grid;grid-template-columns:160px 1fr auto;align-items:center;gap:14px;padding:14px 16px;border-top:1px solid #38383a}.row:first-child{border-top:0}h2{font-size:15px;margin:0}.current{color:#8e8e93;font-size:12px;margin-top:4px;overflow-wrap:anywhere}select{min-width:0;width:100%;height:38px;padding:0 10px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;font:14px inherit}button{height:38px;border:0;border-radius:7px;background:#0a84ff;color:#fff;padding:0 15px;font-weight:600}.status{margin-top:14px;color:#30d158}.error{color:#ff453a}@media(max-width:620px){.row{grid-template-columns:1fr}.wrap{padding-top:24px}button{width:100%}}</style></head><body><main class="wrap"><a href="/">返回设备管理</a><h1>节点管理</h1><p class="sub">手动选择只影响对应业务组；AI 组不使用香港节点。</p><div class="group" id="groups"></div><div class="status" id="status"></div></main><script>const csrf="__CSRF__",status=document.querySelector('#status');function esc(s){return String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}async function req(path,opt={}){let r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}async function load(){try{let d=await req('/api/mihomo');document.querySelector('#groups').innerHTML=d.groups.map(g=>`<section class="row"><div><h2>${esc(g.name)}</h2><div class="current">当前：${esc(g.now||'未选择')}</div></div><select id="group-${esc(g.name)}">${g.all.map(n=>`<option ${n===g.now?'selected':''}>${esc(n)}</option>`).join('')}</select><button onclick="choose('${esc(g.name)}')">应用</button></section>`).join('')}catch(e){status.textContent=e.message;status.className='status error'}}async function choose(group){try{let node=document.querySelector('#group-'+group).value,d=await req('/api/mihomo/select',{method:'POST',body:JSON.stringify({group,node})});status.textContent=d.message;status.className='status';await load()}catch(e){status.textContent=e.message;status.className='status error'}}load()</script></body></html>'''


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

    def do_GET(self):
        if not self.allowed():
            self.reply(HTTPStatus.FORBIDDEN, {"error": "LAN only"})
            return
        path = urlparse(self.path).path
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
        if path == "/api/mihomo":
            try:
                self.reply(HTTPStatus.OK, mihomo_groups())
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
            elif path == "/api/mihomo/select":
                self.reply(HTTPStatus.OK, select_mihomo_node(body.get("group", ""), body.get("node", "")))
            elif path == "/api/rules":
                self.reply(HTTPStatus.OK, save_mihomo_rules(body.get("rules"), body.get("version", "")))
            else:
                self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (RouterError, ValueError, OSError, json.JSONDecodeError) as exc:
            self.reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18093), Handler).serve_forever()
