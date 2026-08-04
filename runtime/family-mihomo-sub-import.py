#!/usr/bin/env python3
"""LAN-only direct subscription importer and Mihomo candidate-pool manager."""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen

import yaml

ENV = Path("/etc/family-proxy-ui/router.env")
GATEWAY_SECRET_PATH = Path("/etc/family-proxy-ui/gateway.secret")
BASE = Path("__FAMILY_DOCKER_ROOT__")
ROOT = BASE / "family-mihomo-sub-import"
PROVIDERS = ROOT / "providers"
MIHOMO_CONFIG = BASE / "family-mihomo-fallback/config.yaml"
DEFAULT_SOURCES = [
    {"slot": "primary", "label": "主力机场", "prefix": "[主力] "},
    {"slot": "backup1", "label": "备用机场 1", "prefix": "[备用1] "},
    {"slot": "backup2", "label": "备用机场 2", "prefix": "[备用2] "},
]
POOLS = {
    "HK-视频": ("hk", "香港", "hkg"),
    "JP-AI": ("jp", "日本", "jpn"),
    "SG-AI": ("sg", "新加坡", "sgp"),
    "US-AI": ("us", "美国", "usa"),
    "其他-AI": (),
    # Telegram candidates are selected by observed reachability, not a fixed
    # Japan-first rule. Limit automatic suggestions to nearby Asian regions.
    "TG": ("hk", "香港", "hkg", "tw", "台湾", "twn", "jp", "日本", "jpn",
           "sg", "新加坡", "sgp", "kr", "韩国", "kor", "th", "泰国", "tha",
           "my", "马来", "mys", "vn", "越南", "vnm", "id", "印尼", "idn"),
    "Proxy": ("hk", "香港", "hkg"),
}
AI_REGIONAL_POOLS = ("JP-AI", "SG-AI", "US-AI")
HK_NODE = re.compile(r"(?:香港|hong[ -]?kong|(?<![a-z])hkg?(?![a-z]))", re.I)
SUGGESTION_SCHEMA = 3
CANDIDATES = PROVIDERS / "candidates.json"
PREVIOUS = PROVIDERS / "candidates.previous.json"
POOL_SETTINGS = PROVIDERS / "pool-settings.json"
PREVIOUS_POOL_SETTINGS = PROVIDERS / "pool-settings.previous.json"
LAST_TESTS = PROVIDERS / "last-tests.json"
CONFIRM_TESTS = PROVIDERS / "last-confirm-tests.json"
POOL_PROBES = PROVIDERS / "pool-probes.json"
SUGGESTIONS = PROVIDERS / "pool-suggestions.json"
SOURCES = PROVIDERS / "sources.json"
RUNTIME_STATE = PROVIDERS / "runtime-state.json"
RUNTIME_EVENTS = PROVIDERS / "runtime-events.json"
ALERT_STATE = PROVIDERS / "alert-state.json"
ALERT_CONFIG = Path("/etc/family-proxy-ui/mihomo-alert.json")
FAILSAFE_STATE = PROVIDERS / "direct-fallback-state.json"
EMERGENCY_SCAN_STATE = PROVIDERS / "emergency-scan-state.json"
RULE_SETS = Path("/etc/family-proxy-ui/rule-sets.json")
VERSIONS = BASE / "family-mihomo-fallback/config-versions"
MAX_BYTES = 12 * 1024 * 1024
CSRF = secrets.token_urlsafe(32)
NOISE = re.compile(
    r"traffic|expire|reset|流量|到期|剩余|套餐|重置|官网|客服|公告|通知|"
    r"订阅地址|使用说明|请勿|禁止|有效期|过期时间|官方群|加入群|距离下次",
    re.I,
)
OPENER = build_opener(ProxyHandler({}))
MONITORED_GROUPS = ("HK-视频", "JP-AI", "SG-AI", "US-AI", "其他-AI", "TG-Auto", "Proxy-Auto", "GitHub-Auto", "V2EX-Auto")
ALERT_GROUPS = ("HK-视频", "JP-AI", "SG-AI", "US-AI", "其他-AI", "TG-Auto", "Proxy-Auto", "GitHub-Auto")
ALERT_FAILURE_THRESHOLD = 2
FAILSAFE_FAILURE_THRESHOLD = 2
FAILSAFE_RECOVERY_THRESHOLD = 3
EMERGENCY_WARM_LIMIT = 8
EMERGENCY_SCAN_LIMIT = 24
EMERGENCY_SCAN_WORKERS = 4
EMERGENCY_SCAN_COOLDOWN = 15 * 60
EMERGENCY_MIN_DWELL = 10 * 60
EMERGENCY_SCAN_LOCK = threading.Lock()
# These select groups are internal safety switches. Business policy groups use
# them by default, while a manual node selection in a business group remains
# untouched by the monitor.
FAILSAFE_EXITS = {
    "HK-视频-出口": {"primary": "HK-视频", "emergency": "HK-视频-应急",
                     "watched": ("HK-视频",), "pools": ("HK-视频",),
                     "url": "https://www.youtube.com/generate_204"},
    "AI-出口": {"primary": "AI-Auto", "emergency": "AI-应急",
                "watched": ("JP-AI", "SG-AI", "US-AI", "其他-AI"),
                "pools": ("JP-AI", "SG-AI", "US-AI", "其他-AI"),
                "url": "https://chatgpt.com/cdn-cgi/trace"},
    "TG-出口": {"primary": "TG-Auto", "emergency": "TG-应急",
                "watched": ("TG-Auto",), "pools": ("TG",),
                "url": "https://core.telegram.org"},
    "Proxy-出口": {"primary": "Proxy-Auto", "emergency": "Proxy-应急",
                   "watched": ("Proxy-Auto",), "pools": ("Proxy",),
                   "url": "https://www.gstatic.com/generate_204"},
    "GitHub-出口": {"primary": "GitHub-Auto", "emergency": "GitHub-应急",
                    "watched": ("GitHub-Auto",),
                    "pools": ("JP-AI", "SG-AI", "US-AI", "Proxy"),
                    "url": "https://github.com/"},
}
BUSINESS_WRAPPERS = {
    "HK-视频-出口": (("Youtube", "HK-视频"),),
    "AI-出口": (("AI", "AI-Auto"), ("Gemini", "AI-Auto")),
    "TG-出口": (("Telegram", "TG-Auto"),),
    "Proxy-出口": (("TikTok", "Proxy-Auto"), ("Google", "Proxy-Auto"),
                   ("Others", "Proxy-Auto")),
    "GitHub-出口": (("GitHub", "GitHub-Auto"),),
}
# Full-library screening stays inexpensive. Before a candidate pool is applied,
# each selected node is tested three times against the actual service it serves.
POOL_TEST_URLS = {
    "HK-视频": "https://www.youtube.com/generate_204",
    "JP-AI": "https://chatgpt.com/cdn-cgi/trace",
    "SG-AI": "https://chatgpt.com/cdn-cgi/trace",
    "US-AI": "https://chatgpt.com/cdn-cgi/trace",
    "其他-AI": "https://chatgpt.com/cdn-cgi/trace",
    "TG": "https://core.telegram.org",
    "Proxy": "https://www.gstatic.com/generate_204",
    "GitHub-Auto": "https://github.com/",
}
DERIVED_EXITS = ("GitHub-Auto",)
POOL_MODES = {
    "select": "手动选择",
    "fallback": "故障切换",
    "url-test": "自动测速",
}
POOL_RUNTIME = {
    "HK-视频": {"group": "HK-视频", "url": "https://www.youtube.com/generate_204", "interval": 300, "expected_status": "204", "default": "fallback"},
    "JP-AI": {"group": "JP-AI", "url": "https://chatgpt.com/cdn-cgi/trace", "interval": 180, "expected_status": "200", "default": "fallback"},
    "SG-AI": {"group": "SG-AI", "url": "https://chatgpt.com/cdn-cgi/trace", "interval": 180, "expected_status": "200", "default": "fallback"},
    "US-AI": {"group": "US-AI", "url": "https://chatgpt.com/cdn-cgi/trace", "interval": 180, "expected_status": "200", "default": "fallback"},
    "其他-AI": {"group": "其他-AI", "url": "https://chatgpt.com/cdn-cgi/trace", "interval": 180, "expected_status": "200", "default": "fallback"},
    "TG": {"group": "TG-Auto", "url": "https://core.telegram.org", "interval": 120, "tolerance": 150, "default": "url-test"},
    "Proxy": {"group": "Proxy-Auto", "url": "https://www.gstatic.com/generate_204", "interval": 300, "expected_status": "204", "default": "fallback"},
}
TEST_JOB_LOCK = threading.Lock()
POOL_SETTINGS_LOCK = threading.Lock()
TEST_STATE_LOCK = threading.Lock()
POOL_PROBE_LOCK = threading.Lock()
POOL_PROBE_STATE_LOCK = threading.Lock()
TEST_STATE = {
    "running": False,
    "total": 0,
    "completed": 0,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "action": None,
    "phase": None,
    "proposal_ready": False,
    "applied": False,
}
POOL_PROBE_STATE = {
    "running": False,
    "pool": None,
    "total": 0,
    "completed": 0,
    "started_at": None,
    "finished_at": None,
    "error": None,
}


def managed_rule_sets():
    data = read_json(RULE_SETS, [])
    if not isinstance(data, list):
        return []
    valid, seen = [], set()
    for item in data:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).strip().lower()
        policy = str(item.get("policy", "")).strip()
        priority = str(item.get("priority", "normal")).strip().lower()
        try:
            interval = int(item.get("interval", 86400))
        except (TypeError, ValueError):
            continue
        raw_sources = item.get("sources")
        if raw_sources is None:
            raw_sources = [{"key": "source-1", "url": item.get("url", ""),
                            "behavior": item.get("behavior", ""), "format": item.get("format", "")}]
        sources, source_keys = [], set()
        for source_index, source in enumerate(raw_sources if isinstance(raw_sources, list) else [], 1):
            if not isinstance(source, dict):
                continue
            source_key = str(source.get("key", f"source-{source_index}")).strip().lower()
            behavior = str(source.get("behavior", "")).strip().lower()
            fmt = str(source.get("format", "")).strip().lower()
            url = str(source.get("url", "")).strip()
            if (not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", source_key) or source_key in source_keys
                    or behavior not in {"domain", "ipcidr", "classical"}
                    or fmt not in {"yaml", "text", "mrs"}
                    or (fmt == "mrs" and behavior == "classical") or not url.startswith("https://")):
                continue
            sources.append({"key": source_key, "behavior": behavior, "format": fmt, "url": url})
            source_keys.add(source_key)
        if (not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", key) or key in seen
                or not sources or len(sources) > 16 or not policy
                or priority not in {"high", "normal"} or not 3600 <= interval <= 604800):
            continue
        valid.append({"key": key, "sources": sources,
                      "policy": policy, "priority": priority, "interval": interval})
        seen.add(key)
    return valid


def telegram_rule_set_keys(rule_sets):
    return {
        item["key"] for item in rule_sets
        if any("telegram" in source["url"].lower() for source in item["sources"])
    }


def has_telegram_ip_rule_set(rule_sets):
    keys = telegram_rule_set_keys(rule_sets)
    return any(item["key"] in keys and any(source["behavior"] == "ipcidr"
                                             for source in item["sources"])
               for item in rule_sets)


def merge_managed_rule_sets(config):
    rule_sets = managed_rule_sets()
    providers = config.get("rule-providers")
    providers = dict(providers) if isinstance(providers, dict) else {}
    for key in list(providers):
        if str(key).startswith("family-"):
            providers.pop(key)
    for item in rule_sets:
        for source in item["sources"]:
            providers[f"family-{item['key']}-{source['key']}"] = {
                "type": "http", "behavior": source["behavior"], "format": source["format"],
                "path": f"./providers/rule-sets/{item['key']}-{source['key']}.{source['format']}",
                "url": source["url"], "interval": item["interval"], "proxy": "Proxy-Auto",
                "size-limit": 4 * 1024 * 1024,
            }
    if providers:
        config["rule-providers"] = providers
    else:
        config.pop("rule-providers", None)
    rules = [str(rule) for rule in config.get("rules") or []]
    def rendered(items):
        return [f"RULE-SET,family-{item['key']}-{source['key']},{item['policy']}" +
                (",no-resolve" if source["behavior"] == "ipcidr" else "")
                for item in items for source in item["sources"]]
    high = [item for item in rule_sets if item["priority"] == "high"]
    normal = [item for item in rule_sets if item["priority"] == "normal"]
    desired = rendered(rule_sets)
    desired_set = set(desired)
    retained, seen = [], set()
    for rule in rules:
        if not rule.startswith("RULE-SET,family-"):
            retained.append(rule)
        elif rule in desired_set and rule not in seen:
            retained.append(rule)
            seen.add(rule)
    rules = retained
    missing_high = [rule for rule in rendered(high) if rule not in seen]
    missing_normal = [rule for rule in rendered(normal) if rule not in seen]
    high_at = next((index for index, rule in enumerate(rules)
                    if rule.startswith("GEOSITE,") and rule != "GEOSITE,CN,DIRECT"),
                   next((index for index, rule in enumerate(rules) if rule == "GEOSITE,CN,DIRECT"), len(rules)))
    rules[high_at:high_at] = missing_high
    normal_at = next((index for index, rule in enumerate(rules) if rule == "GEOSITE,CN,DIRECT"), len(rules))
    rules[normal_at:normal_at] = missing_normal
    config["rules"] = rules
    return rule_sets


def before_match_index(rules):
    return next((index for index, rule in enumerate(rules)
                 if str(rule).upper().startswith("MATCH,")), len(rules))


def env():
    return dict(line.strip().split("=", 1) for line in ENV.read_text().splitlines()
                if "=" in line and not line.lstrip().startswith("#"))


def authenticated(value):
    try:
        user, password = base64.b64decode(value[6:], validate=True).decode().split(":", 1)
        values = env()
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(values["UI_PASSWORD_SALT"]), 210000).hex()
        return value.startswith("Basic ") and hmac.compare_digest(user, values["UI_USERNAME"]) and hmac.compare_digest(digest, values["UI_PASSWORD_HASH"])
    except (ValueError, KeyError, UnicodeDecodeError):
        return False


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def sources():
    data = read_json(SOURCES, DEFAULT_SOURCES)
    if not isinstance(data, list) or not data:
        return list(DEFAULT_SOURCES)
    valid = []
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        slot = item.get("slot", "")
        label = item.get("label", "")
        prefix = item.get("prefix", "")
        if (not isinstance(slot, str) or not re.fullmatch(r"(?:primary|backup[1-9][0-9]*)", slot)
                or slot in seen or not isinstance(label, str) or not isinstance(prefix, str)):
            continue
        valid.append({"slot": slot, "label": label[:40], "prefix": prefix[:40]})
        seen.add(slot)
    return valid or list(DEFAULT_SOURCES)


def source_map():
    return {item["slot"]: item for item in sources()}


def source_slots():
    return [item["slot"] for item in sources()]


def provider_path(slot):
    if slot not in source_map():
        raise ValueError("无效机场槽位")
    return PROVIDERS / f"{slot}.yaml"


def clean_provider(data):
    if data.lstrip().lower().startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        raise ValueError("订阅地址返回网页而非原生 Clash/Mihomo YAML；请在机场后台复制 Clash/Mihomo 原生订阅链接")
    try:
        documents = list(yaml.safe_load_all(data))
    except yaml.YAMLError as exc:
        raise ValueError("订阅内容不是可解析的 Clash/Mihomo YAML") from exc
    # Some providers prepend a metadata document before the actual Mihomo
    # configuration. Find the document that contains the proxy list.
    document = next((item for item in documents if isinstance(item, dict) and isinstance(item.get("proxies"), list)), None)
    proxies = document.get("proxies") if document else None
    if not isinstance(proxies, list):
        raise ValueError("仅接受机场原生 Clash/Mihomo YAML")
    kept = [item for item in proxies if isinstance(item, dict) and item.get("name") and not NOISE.search(str(item["name"]))]
    if not kept:
        raise ValueError("订阅中没有可用代理节点")
    # Airport profiles often include policy groups that reference traffic and
    # expiry notice entries. Only proxies belong in a Mihomo provider file.
    return yaml.safe_dump({"proxies": kept}, allow_unicode=True, sort_keys=False).encode(), len(kept)


def slot_state(slot):
    meta = PROVIDERS / f"{slot}.json"
    try:
        state = json.loads(meta.read_text())
    except (OSError, json.JSONDecodeError):
        state = {"slot": slot, "label": source_map()[slot]["label"], "imported": False, "nodes": 0}
    state["removable"] = slot != "primary"
    return state


def nodes():
    result = []
    sources_by_slot = source_map()
    for slot in source_slots():
        path = provider_path(slot)
        if not path.exists():
            continue
        document = yaml.safe_load(path.read_text()) or {}
        for item in document.get("proxies", []):
            name = str(item.get("name", ""))
            if name and not NOISE.search(name):
                result.append({"name": sources_by_slot[slot]["prefix"] + name, "raw": name,
                               "source": slot, "label": sources_by_slot[slot]["label"]})
    return result


def pools():
    try:
        data = json.loads(CANDIDATES.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    return {name: list(data.get(name, []))[:5] for name in POOLS}


def pool_settings():
    try:
        data = json.loads(POOL_SETTINGS.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    return validate_pool_settings(data)


def validate_pool_settings(value):
    value = value if isinstance(value, dict) else {}
    cleaned = {}
    for pool, spec in POOL_RUNTIME.items():
        mode = str((value.get(pool) or {}).get("type") or spec["default"])
        cleaned[pool] = {"type": mode if mode in POOL_MODES else spec["default"]}
    return cleaned


def suggestions():
    data = read_json(SUGGESTIONS, {})
    if data.get("schema") != SUGGESTION_SCHEMA:
        return {
            "pools": {name: [] for name in POOLS},
            "generated_at": None,
            "ready": False,
            "reason": "候选池标准已更新，请重新进行全量稳定性测速",
        }
    proposal = data.get("pools") if isinstance(data.get("pools"), dict) else {}
    return {
        "pools": {name: list(proposal.get(name, []))[:5] for name in POOLS},
        "generated_at": data.get("generated_at"),
        "ready": bool(data.get("ready")),
        "reason": data.get("reason"),
    }


def node_index():
    return {item["name"]: item for item in nodes()}


def pool_matches(pool, node):
    if pool == "其他-AI":
        return not HK_NODE.search(node["raw"]) and not any(
            pool_matches(regional_pool, node) for regional_pool in AI_REGIONAL_POOLS
        )
    return any(word.casefold() in node["raw"].casefold() for word in POOLS[pool])


def test_score(result):
    # Median latency is dominant; jitter only breaks close calls.
    return int(result["delay"]) + round(int(result["jitter"] or 0) * 0.35)


def rank_pool_candidates(entries):
    """Keep the five most stable nodes, independent of subscription source."""
    return [entry["name"] for entry in sorted(entries, key=lambda entry: (entry["score"], entry["name"]))[:5]]


def interleave_sources(entries):
    """Keep emergency scans source-diverse without changing active pool order."""
    buckets = {slot: [] for slot in source_slots()}
    for entry in entries:
        buckets.setdefault(entry["source"], []).append(entry["name"])
    ordered = []
    while any(buckets.values()):
        for slot in source_slots():
            if buckets.get(slot):
                ordered.append(buckets[slot].pop(0))
    return ordered


def emergency_catalog(selected=None):
    """Return unprobed, business-filtered cold reserves for hidden select groups."""
    selected = selected or pools()
    available = nodes()
    result = {}
    for spec in FAILSAFE_EXITS.values():
        active = {name for pool in spec["pools"] for name in selected.get(pool, [])}
        eligible = [
            node for node in available
            if node["name"] not in active
            and any(pool_matches(pool, node) for pool in spec["pools"])
        ]
        result[spec["emergency"]] = interleave_sources(eligible)
    return result


def build_suggestions(results):
    indexed = node_index()
    result_by_name = {item["name"]: item for item in results}
    proposed = {}
    for pool in POOLS:
        eligible = []
        for name, node in indexed.items():
            result = result_by_name.get(name)
            if not result or result.get("success") != 3 or result.get("delay") is None:
                continue
            if pool_matches(pool, node):
                eligible.append({"name": name, "source": node["source"], "score": test_score(result)})
        proposed[pool] = rank_pool_candidates(eligible)
    missing = [pool for pool, entries in proposed.items() if not entries]
    return {
        "pools": proposed,
        "generated_at": datetime.now().astimezone().isoformat(),
        "schema": SUGGESTION_SCHEMA,
        "ready": not missing,
        "reason": ("、".join(missing) + " 没有连续三次成功的节点") if missing else None,
    }


def seed_pools():
    available = nodes()
    seeded = {}
    for pool, words in POOLS.items():
        matches = [n for n in available if pool_matches(pool, n)]
        seeded[pool] = rank_pool_candidates([
            {"name": n["name"], "source": n["source"], "score": 0} for n in matches
        ])
    atomic_json(CANDIDATES, seeded)
    return seeded


def fallback(name, selected, url, interval, expected_status=None):
    group = {
        "name": name,
        "type": "fallback",
        "proxies": selected,
        # A subscription can legitimately be empty after it expires or is
        # removed. Keep domestic access usable instead of rejecting the entire
        # generated configuration in that state.
        "empty-fallback": "DIRECT",
        "url": url,
        "interval": interval,
        # Candidate pools are intentionally small. Keep their health state warm
        # so the first request after an idle period does not trigger discovery.
        "lazy": False,
        "timeout": 5000,
        "max-failed-times": 2,
    }
    if expected_status:
        group["expected-status"] = expected_status
    return group


def latency_aware_url_test(name, selected, url, interval, tolerance):
    return {
        "name": name,
        "type": "url-test",
        "proxies": selected,
        "empty-fallback": "DIRECT",
        "url": url,
        "interval": interval,
        # Keep the small candidate pool warm. The tolerance prevents a switch
        # for ordinary jitter while still moving away from a persistently slow
        # Telegram path.
        "lazy": False,
        "timeout": 5000,
        "tolerance": tolerance,
        "max-failed-times": 2,
    }


def candidate_pool_group(pool, selected, settings):
    spec = POOL_RUNTIME[pool]
    mode = settings[pool]["type"]
    if mode == "select":
        return {"name": spec["group"], "type": "select", "proxies": selected,
                "empty-fallback": "DIRECT"}
    if mode == "url-test":
        return latency_aware_url_test(
            spec["group"], selected, spec["url"], spec["interval"], spec.get("tolerance", 50)
        )
    return fallback(spec["group"], selected, spec["url"], spec["interval"], spec.get("expected_status"))


def wait_mihomo(timeout=20):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            version = proxy_api("/version")
            policy = proxy_api("/proxies/Proxy-Auto")
            if version and policy.get("now") and policy.get("all"):
                return
        except Exception as exc:
            last_error = exc
        time.sleep(1)
    raise ValueError("Mihomo 重启后未通过控制接口与策略组检查") from last_error


def restart_mihomo(verify=True):
    result = subprocess.run(["docker", "restart", "family-mihomo-fallback"], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError("Mihomo 重载失败")
    if verify:
        wait_mihomo()


def save_config_version(content, label):
    VERSIONS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = VERSIONS / f"{stamp}-{label}.yaml"
    path.write_bytes(content)
    os.chmod(path, 0o600)
    for old in sorted(VERSIONS.glob("*.yaml"), reverse=True)[5:]:
        old.unlink(missing_ok=True)
    return path


def generate_config(selected=None, settings=None):
    selected = selected or pools()
    selected = {name: list(selected.get(name, [])) for name in POOLS}
    settings = validate_pool_settings(settings if settings is not None else pool_settings())
    config = yaml.safe_load(MIHOMO_CONFIG.read_text())
    rule_sets = merge_managed_rule_sets(config)
    flattened = []
    sources_by_slot = source_map()
    for slot in source_slots():
        path = provider_path(slot)
        if not path.exists():
            continue
        document = yaml.safe_load(path.read_text()) or {}
        for original in document.get("proxies", []):
            if not isinstance(original, dict) or not original.get("name") or NOISE.search(str(original["name"])):
                continue
            item = dict(original)
            item["name"] = sources_by_slot[slot]["prefix"] + str(item["name"])
            flattened.append(item)
    config["proxies"] = flattened
    # Telegram mobile clients commonly connect to MTProto endpoints by IP.
    # Skipping those ranges avoids waiting for a TLS hostname that will never
    # arrive; either the managed Telegram IP set or the GEOIP fallback below
    # still selects the dedicated pool.
    sniffer = config.setdefault("sniffer", {})
    skipped = list(sniffer.get("skip-dst-address") or [])
    for cidr in ("149.154.160.0/20", "91.108.4.0/22", "91.108.56.0/22"):
        if cidr not in skipped:
            skipped.append(cidr)
    sniffer["skip-dst-address"] = skipped
    # Telegram clients commonly connect to Telegram IPs directly. Prefer the
    # managed MRS IP set and retain GEOIP only when that set is absent.
    rules = list(config.get("rules") or [])
    apple_ip_rule = "IP-CIDR,17.0.0.0/8,Apple,no-resolve"
    if apple_ip_rule not in rules:
        insert_at = next((index + 1 for index, rule in enumerate(rules)
                          if str(rule).startswith("GEOSITE,apple,")), 0)
        rules.insert(insert_at, apple_ip_rule)
    telegram_ip_rule = "GEOIP,telegram,Telegram,no-resolve"
    if has_telegram_ip_rule_set(rule_sets):
        rules = [rule for rule in rules if not str(rule).startswith("GEOIP,telegram,")]
    elif not any(str(rule).startswith("GEOIP,telegram,") for rule in rules):
        insert_at = next((index for index, rule in enumerate(rules)
                          if str(rule).startswith("GEOSITE,telegram,")), before_match_index(rules))
        rules.insert(insert_at, telegram_ip_rule)
    # The notification bot is control-plane traffic. Keep it separate from
    # normal Telegram client sessions so a failing regional TG route cannot
    # suppress an alert about that very failure.
    telegram_api_rule = "DOMAIN,api.telegram.org,TG-Notify"
    rules = [rule for rule in rules if str(rule) != telegram_api_rule]
    telegram_keys = telegram_rule_set_keys(rule_sets)
    telegram_prefixes = tuple(f"RULE-SET,family-{key}-" for key in telegram_keys)
    insert_at = next((index for index, rule in enumerate(rules)
                      if telegram_prefixes and str(rule).startswith(telegram_prefixes)),
                     next((index for index, rule in enumerate(rules)
                           if str(rule).startswith("GEOSITE,telegram,")), before_match_index(rules)))
    rules.insert(insert_at, telegram_api_rule)
    # GitHub uses long-lived HTTPS connections and large release/LFS transfers.
    # Keep its domains ahead of the broader Microsoft category. The internal
    # safety wrapper only switches to DIRECT after its candidate pool has been
    # continuously observed as unavailable.
    github_rules = (
        "DOMAIN-SUFFIX,github.com,GitHub-出口",
        "DOMAIN-SUFFIX,githubusercontent.com,GitHub-出口",
        "DOMAIN-SUFFIX,githubassets.com,GitHub-出口",
        "DOMAIN-SUFFIX,githubapp.com,GitHub-出口",
    )
    legacy_github_rules = tuple(
        variant for rule in github_rules for variant in (
            rule.replace(",GitHub-出口", ",Proxy-Auto"),
            rule.replace(",GitHub-出口", ",GitHub"),
            rule.replace(",GitHub-出口", ",GitHub-Auto"),
        )
    )
    # `GEOSITE,microsoft` includes GitHub. Remove only our default and legacy
    # exact rules, then reinsert the current defaults before that broader rule.
    rules = [rule for rule in rules if str(rule) not in (*github_rules, *legacy_github_rules)]
    insert_at = next((index for index, rule in enumerate(rules)
                      if str(rule).startswith("GEOSITE,microsoft,")), before_match_index(rules))
    rules[insert_at:insert_at] = github_rules
    # Cloudflare may reject an otherwise healthy generic exit for V2EX. Route
    # the site through a dedicated group whose own health check requires an
    # actual HTTP 200 from V2EX instead of a generic connectivity response.
    v2ex_rule = "DOMAIN-SUFFIX,v2ex.com,V2EX-Auto"
    rules = [rule for rule in rules if str(rule) != v2ex_rule]
    insert_at = next((index for index, rule in enumerate(rules)
                      if str(rule).startswith(("GEOSITE,CN,", "GEOIP,CN,"))), before_match_index(rules))
    rules.insert(insert_at, v2ex_rule)
    config["rules"] = rules
    hk, jp, sg, us, other_ai, tg, proxy = (selected[name] for name in POOLS)
    ai_groups = [group for pool, group in (("JP-AI", "JP-AI"), ("SG-AI", "SG-AI"),
                                             ("US-AI", "US-AI"), ("其他-AI", "其他-AI"))
                 if selected[pool]]
    ai_nodes = jp + sg + us + other_ai
    github = github_candidates(selected)
    v2ex = list(dict.fromkeys(proxy))
    emergency = emergency_catalog(selected)
    # Bot API needs a real HTTPS request, not merely a controller delay probe.
    # Prefer the separately verified backup Hysteria2 candidates. They are only
    # used by alerts and do not influence normal Telegram client routing.
    notify = list(dict.fromkeys(
        name for name in (jp + sg + us + other_ai + tg + proxy)
        if name.startswith("[备用2] ")
    ))[:5]
    if not notify:
        notify = us[:2] + jp[:1] + sg[:1]
    groups = [
        {"name": "Apple", "type": "select", "proxies": ["DIRECT", "Proxy-Auto"] + proxy},
        {"name": "MicroSoft", "type": "select", "proxies": ["DIRECT", "Proxy-Auto"] + proxy},
        candidate_pool_group("HK-视频", hk, settings),
        candidate_pool_group("JP-AI", jp, settings),
        candidate_pool_group("SG-AI", sg, settings),
        candidate_pool_group("US-AI", us, settings),
        candidate_pool_group("TG", tg, settings),
        fallback("TG-Notify", notify, "https://api.telegram.org", 300),
        candidate_pool_group("Proxy", proxy, settings),
        fallback("GitHub-Auto", github, "https://github.com/", 300, "200"),
        fallback("V2EX-Auto", v2ex, "https://www.v2ex.com/", 300, "200"),
        fallback("DNS-Resolve", proxy, "https://dns.google/dns-query", 300),
        fallback("AI-Auto", ai_groups, "https://chatgpt.com/cdn-cgi/trace", 180, "200"),
        *({"name": name, "type": "select", "proxies": entries,
           "empty-fallback": "DIRECT"} for name, entries in emergency.items()),
        {"name": "HK-视频-出口", "type": "select", "proxies": ["HK-视频", "HK-视频-应急", "DIRECT"],
         "default-selected": "HK-视频"},
        {"name": "AI-出口", "type": "select", "proxies": ["AI-Auto", "AI-应急", "DIRECT"],
         "default-selected": "AI-Auto"},
        {"name": "TG-出口", "type": "select", "proxies": ["TG-Auto", "TG-应急", "DIRECT"],
         "default-selected": "TG-Auto"},
        {"name": "Proxy-出口", "type": "select", "proxies": ["Proxy-Auto", "Proxy-应急", "DIRECT"],
         "default-selected": "Proxy-Auto"},
        {"name": "GitHub-出口", "type": "select", "proxies": ["GitHub-Auto", "GitHub-应急", "DIRECT"],
         "default-selected": "GitHub-Auto"},
        {"name": "AI", "type": "select", "proxies": ["AI-出口", "AI-Auto"] + ai_groups + ai_nodes},
        {"name": "Gemini", "type": "select", "proxies": ["AI-出口", "AI-Auto", "SG-AI", "JP-AI", "US-AI"] + (["其他-AI"] if other_ai else []) + sg + jp + us + other_ai},
        {"name": "Telegram", "type": "select", "proxies": ["TG-出口", "TG-Auto"] + tg},
        {"name": "TikTok", "type": "select", "proxies": ["Proxy-出口", "Proxy-Auto"] + proxy},
        {"name": "Youtube", "type": "select", "proxies": ["HK-视频-出口", "HK-视频"] + hk},
        {"name": "Google", "type": "select", "proxies": ["Proxy-出口", "Proxy-Auto"] + proxy},
        {"name": "GitHub", "type": "select", "proxies": ["GitHub-出口", "GitHub-Auto"] + github},
        {"name": "V2EX", "type": "select", "proxies": ["V2EX-Auto"] + v2ex},
        {"name": "Others", "type": "select", "proxies": ["Proxy-出口", "Proxy-Auto"] + proxy},
    ]
    if other_ai:
        groups.insert(6, candidate_pool_group("其他-AI", other_ai, settings))
    config["proxy-groups"] = groups
    previous = MIHOMO_CONFIG.read_bytes()
    temporary = MIHOMO_CONFIG.with_suffix(".candidate")
    temporary.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
    os.chmod(temporary, 0o640)
    copied = subprocess.run(["docker", "cp", str(temporary), "family-mihomo-fallback:/tmp/config-candidate.yaml"],
                            capture_output=True, text=True, timeout=15)
    if copied.returncode:
        temporary.unlink(missing_ok=True)
        raise ValueError("候选配置校验准备失败")
    check = subprocess.run(["docker", "exec", "family-mihomo-fallback", "/mihomo", "-t", "-f",
                            "/tmp/config-candidate.yaml"], capture_output=True, text=True, timeout=45)
    if check.returncode:
        temporary.unlink(missing_ok=True)
        raise ValueError("候选池生成的 Mihomo 配置校验失败: " + (check.stderr or check.stdout)[-500:])
    version = save_config_version(previous, "before-apply")
    os.replace(temporary, MIHOMO_CONFIG)
    try:
        restart_mihomo()
    except ValueError as exc:
        MIHOMO_CONFIG.write_bytes(previous)
        os.chmod(MIHOMO_CONFIG, 0o640)
        try:
            restart_mihomo()
        except ValueError as rollback_exc:
            raise ValueError(f"新配置失败且自动恢复异常；可使用 {version.name} 手动恢复") from rollback_exc
        raise ValueError("新配置运行检查失败，已自动恢复上一版本") from exc
    return version.name


def apply_provider(slot, cleaned, count):
    path = provider_path(slot)
    temporary = path.with_suffix(".candidate")
    temporary.write_bytes(cleaned)
    os.chmod(temporary, 0o600)
    subprocess.run(["docker", "cp", str(temporary), "family-mihomo-fallback:/tmp/sub.yaml"], check=True, timeout=15)
    check = subprocess.run(["docker", "exec", "family-mihomo-fallback", "/mihomo", "-t", "-f", "/tmp/sub.yaml"], capture_output=True, text=True, timeout=30)
    if check.returncode:
        temporary.unlink(missing_ok=True)
        raise ValueError("导入节点不被当前 Mihomo 支持")
    previous_provider = path.read_bytes() if path.exists() else None
    previous_candidates = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    previous_config = MIHOMO_CONFIG.read_bytes()
    os.replace(temporary, path)
    meta = {"slot": slot, "label": source_map()[slot]["label"], "imported": True, "nodes": count,
            "updated_at": datetime.now().astimezone().isoformat()}
    try:
        current = pools()
        valid = {node["name"] for node in nodes()}
        reconciled = {pool: [name for name in current[pool] if name in valid] for pool in POOLS}
        validate_pools(reconciled)
        generate_config(reconciled)
        PREVIOUS.write_bytes(previous_candidates)
        atomic_json(CANDIDATES, reconciled)
        SUGGESTIONS.unlink(missing_ok=True)
        atomic_json(PROVIDERS / f"{slot}.json", meta)
    except (ValueError, OSError):
        if previous_provider is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous_provider)
            os.chmod(path, 0o600)
        CANDIDATES.write_bytes(previous_candidates)
        if MIHOMO_CONFIG.read_bytes() != previous_config:
            MIHOMO_CONFIG.write_bytes(previous_config)
            os.chmod(MIHOMO_CONFIG, 0o640)
            restart_mihomo()
        raise
    return meta


def import_slot(slot, url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("仅接受 HTTPS 订阅链接")
    try:
        # Some subscription panels only return the actual Mihomo configuration
        # to recognized client profiles. ClashX Meta is compatible with Mihomo
        # and receives the complete YAML from those providers.
        with OPENER.open(Request(url, headers={"User-Agent": "ClashX Meta"}), timeout=75) as response:
            raw = response.read(MAX_BYTES + 1)
    except Exception as exc:
        raise ValueError("订阅直连拉取失败") from exc
    if len(raw) > MAX_BYTES:
        raise ValueError("订阅文件过大")
    cleaned, count = clean_provider(raw)
    return apply_provider(slot, cleaned, count)


def add_source():
    current = sources()
    used = {item["slot"] for item in current}
    number = 1
    while f"backup{number}" in used:
        number += 1
    source = {"slot": f"backup{number}", "label": f"备用机场 {number}", "prefix": f"[备用{number}] "}
    current.append(source)
    atomic_json(SOURCES, current)
    return {**source, "imported": False, "nodes": 0}


def clear_slot(slot):
    path = provider_path(slot)
    previous_provider = path.read_bytes() if path.exists() else b"proxies: []\n"
    previous_candidates = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    previous_config = MIHOMO_CONFIG.read_bytes()
    path.write_text("proxies: []\n")
    os.chmod(path, 0o600)
    try:
        current = pools()
        valid = {node["name"] for node in nodes()}
        reconciled = {pool: [name for name in current[pool] if name in valid] for pool in POOLS}
        validate_pools(reconciled)
        generate_config(reconciled)
        PREVIOUS.write_bytes(previous_candidates)
        atomic_json(CANDIDATES, reconciled)
        SUGGESTIONS.unlink(missing_ok=True)
        (PROVIDERS / f"{slot}.json").unlink(missing_ok=True)
    except (ValueError, OSError):
        path.write_bytes(previous_provider)
        os.chmod(path, 0o600)
        CANDIDATES.write_bytes(previous_candidates)
        if MIHOMO_CONFIG.read_bytes() != previous_config:
            MIHOMO_CONFIG.write_bytes(previous_config)
            os.chmod(MIHOMO_CONFIG, 0o640)
            restart_mihomo()
        raise
    return slot_state(slot)


def delete_source(slot):
    if slot == "primary":
        raise ValueError("主力机场不能删除")
    current = sources()
    if slot not in {item["slot"] for item in current}:
        raise ValueError("无效机场槽位")
    path = provider_path(slot)
    try:
        document = yaml.safe_load(path.read_text()) or {} if path.exists() else {}
        has_nodes = bool(document.get("proxies"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError("无法读取待删除机场的节点文件") from exc
    if has_nodes:
        # This validates all active candidate pools and rolls back on failure.
        clear_slot(slot)
    path.unlink(missing_ok=True)
    (PROVIDERS / f"{slot}.json").unlink(missing_ok=True)
    atomic_json(SOURCES, [item for item in current if item["slot"] != slot])
    SUGGESTIONS.unlink(missing_ok=True)
    return {"slot": slot, "removed": True}


def validate_pools(value):
    indexed = node_index()
    cleaned = {}
    for pool in POOLS:
        entries = value.get(pool, [])
        minimum = 0 if pool == "其他-AI" else 1
        if not isinstance(entries, list) or not minimum <= len(entries) <= 5 or len(entries) != len(set(entries)):
            raise ValueError(f"{pool} 必须是 {minimum} 至 5 个不重复节点")
        if any(item not in indexed for item in entries):
            raise ValueError(f"{pool} 含有不存在的节点")
        if any(not pool_matches(pool, indexed[item]) for item in entries):
            raise ValueError(f"{pool} 含有不符合地域规则的节点")
        cleaned[pool] = list(entries)
    return cleaned


def save_pools(value, settings=None):
    cleaned = validate_pools(value)
    cleaned_settings = validate_pool_settings(settings if settings is not None else pool_settings())
    previous = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    previous_settings = POOL_SETTINGS.read_bytes() if POOL_SETTINGS.exists() else b"{}"
    previous_config = MIHOMO_CONFIG.read_bytes()
    generate_config(cleaned, cleaned_settings)
    try:
        PREVIOUS.write_bytes(previous)
        PREVIOUS_POOL_SETTINGS.write_bytes(previous_settings)
        atomic_json(CANDIDATES, cleaned)
        atomic_json(POOL_SETTINGS, cleaned_settings)
    except OSError:
        MIHOMO_CONFIG.write_bytes(previous_config)
        os.chmod(MIHOMO_CONFIG, 0o640)
        restart_mihomo()
        raise
    return cleaned


def save_pool_settings(value):
    if not POOL_SETTINGS_LOCK.acquire(blocking=False):
        raise ValueError("候选池设置正在保存，请等待当前测速完成")
    try:
        previous_settings = pool_settings()
        settings = validate_pool_settings(value)
        selected = pools()
        newly_automatic = [pool for pool in POOLS if settings[pool]["type"] == "url-test"
                            and previous_settings[pool]["type"] != "url-test"]
        results = test_pool_candidates({pool: selected[pool] for pool in newly_automatic}) if newly_automatic else []
        for pool in newly_automatic:
            selected[pool] = rank_url_test_pool(pool, selected[pool], results)
        applied = save_pools(selected, settings)
        if results:
            persist_pool_probe_results(results)
        return {"pools": applied, "settings": pool_settings(), "reordered": newly_automatic}
    finally:
        POOL_SETTINGS_LOCK.release()


def rollback_pools():
    if not PREVIOUS.exists():
        raise ValueError("没有可回退的上一版候选池")
    current = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    current_settings = POOL_SETTINGS.read_bytes() if POOL_SETTINGS.exists() else b"{}"
    restored_bytes = PREVIOUS.read_bytes()
    restored = validate_pools(json.loads(restored_bytes))
    restored_settings = validate_pool_settings(
        json.loads(PREVIOUS_POOL_SETTINGS.read_text()) if PREVIOUS_POOL_SETTINGS.exists() else {}
    )
    generate_config(restored, restored_settings)
    CANDIDATES.write_bytes(restored_bytes)
    PREVIOUS.write_bytes(current)
    atomic_json(POOL_SETTINGS, restored_settings)
    PREVIOUS_POOL_SETTINGS.write_bytes(current_settings)
    return restored


def proxy_api(path, method="GET", data=None):
    body = json.dumps(data).encode() if data is not None else None
    request = Request("http://127.0.0.1:9091" + path, data=body, method=method,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=8) as response:
        return json.loads(response.read() or b"{}")


def test_one(name, url="https://www.gstatic.com/generate_204"):
    delays = []
    for _ in range(3):
        query = urlencode({"url": url, "timeout": 5000})
        try:
            data = proxy_api("/proxies/" + quote(name, safe="") + "/delay?" + query)
            if data.get("delay"):
                delays.append(int(data["delay"]))
        except Exception:
            pass
        time.sleep(0.15)
    return {
        "name": name,
        "delay": round(statistics.median(delays)) if delays else None,
        "jitter": max(delays) - min(delays) if len(delays) > 1 else 0 if delays else None,
        "success": len(delays),
        "ok": len(delays) >= 2,
    }


def test_nodes(names, progress=None, result_path=LAST_TESTS):
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(test_one, name) for name in names]
        results = []
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if progress:
                progress(completed, len(names))
    results = sorted(results, key=lambda item: (not item["ok"], item["delay"] or 999999,
                                                 item["jitter"] or 999999, item["name"]))
    atomic_json(result_path, {"tested_at": datetime.now().astimezone().isoformat(), "results": results})
    return results


def test_pool_candidates(selected, progress=None):
    """Confirm each pool against its own service, not one generic URL."""
    tasks = [(pool, name) for pool, entries in selected.items() for name in entries]
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(test_one, name, POOL_TEST_URLS[pool]): (pool, name)
            for pool, name in tasks
        }
        results = []
        for completed, future in enumerate(as_completed(futures), 1):
            pool, _ = futures[future]
            item = future.result()
            item["pool"] = pool
            results.append(item)
            if progress:
                progress(completed, len(tasks))
    return results


def github_candidates(selected):
    """Build the small GitHub-specific exit from visible business pools."""
    names = (selected.get("JP-AI", [])[:2] + selected.get("SG-AI", [])[:1]
             + selected.get("Proxy", [])[:1] + selected.get("US-AI", [])[:1])
    names = list(dict.fromkeys(names))
    records = read_json(POOL_PROBES, {}).get("pools", {})
    rows = (records.get("GitHub-Auto") or {}).get("results", [])
    by_name = {row.get("name"): row for row in rows if isinstance(row, dict)}
    if not by_name:
        return names

    def score(name):
        row = by_name.get(name) or {}
        return (
            row.get("success") != 3 or row.get("delay") is None,
            row.get("delay") if row.get("delay") is not None else 999999,
            row.get("jitter") if row.get("jitter") is not None else 999999,
            names.index(name),
        )

    return sorted(names, key=score)


def derived_exits(selected=None):
    selected = selected or pools()
    return {
        "GitHub-Auto": {
            "label": "GitHub 专用自动出口",
            "nodes": github_candidates(selected),
            "description": "由 JP-AI 前 2、SG-AI 前 1、Proxy 前 1、US-AI 前 1 自动组成；全量测速会额外访问 GitHub 并优先排列稳定节点。",
        }
    }


def rank_url_test_pool(pool, selected, results):
    by_name = {item["name"]: item for item in results if item.get("pool") == pool}
    stable = [name for name in selected if (by_name.get(name) or {}).get("success") == 3
              and (by_name.get(name) or {}).get("delay") is not None]
    if not stable:
        raise ValueError(f"{pool} 没有连续三次成功的节点，拒绝启用自动测速")

    def score(name):
        item = by_name.get(name) or {}
        return (
            item.get("success") != 3 or item.get("delay") is None,
            item.get("delay") or 999999,
            item.get("jitter") if item.get("jitter") is not None else 999999,
            name,
        )

    return sorted(selected, key=score)


def persist_pool_probe_results(results):
    stored = read_json(POOL_PROBES, {})
    entries = stored.get("pools", {}) if isinstance(stored.get("pools"), dict) else {}
    tested_at = datetime.now().astimezone().isoformat()
    for pool in {item.get("pool") for item in results if item.get("pool") in (*POOLS, *DERIVED_EXITS)}:
        entries[pool] = {
            "tested_at": tested_at,
            "results": [item for item in results if item.get("pool") == pool],
        }
    atomic_json(POOL_PROBES, {"pools": entries})


def probe_status():
    with POOL_PROBE_STATE_LOCK:
        return dict(POOL_PROBE_STATE)


def summarize_probe(pool, selected, record):
    rows = record.get("results", []) if isinstance(record, dict) else []
    rows = [row for row in rows if row.get("pool") == pool and row.get("name") in selected]
    stable = [row for row in rows if row.get("success") == 3 and row.get("delay") is not None]
    return {
        "target": POOL_TEST_URLS[pool],
        "protocol": urlparse(POOL_TEST_URLS[pool]).scheme.upper(),
        "location": "Z4Pro 经 Mihomo",
        "tested_at": record.get("tested_at") if rows and isinstance(record, dict) else None,
        "candidate_count": len(selected),
        "completed_count": len(rows),
        "stable_count": len(stable),
        "median_delay": round(statistics.median(row["delay"] for row in stable)) if stable else None,
        "max_jitter": max((row.get("jitter") or 0) for row in stable) if stable else None,
    }


def probe_report():
    active = pools()
    manual = read_json(POOL_PROBES, {}).get("pools", {})
    confirmed = read_json(CONFIRM_TESTS, {})
    result = {}
    for pool, selected in active.items():
        record = manual.get(pool)
        if not isinstance(record, dict):
            record = confirmed
        result[pool] = summarize_probe(pool, selected, record)
    for exit_name in DERIVED_EXITS:
        selected = github_candidates(active)
        record = manual.get(exit_name)
        if not isinstance(record, dict):
            record = confirmed
        result[exit_name] = summarize_probe(exit_name, selected, record)
    return {"pools": result, "running": probe_status()}


def start_pool_probe(pool):
    if pool not in (*POOLS, *DERIVED_EXITS):
        raise ValueError("无效业务池")
    active = pools()
    selected = github_candidates(active) if pool == "GitHub-Auto" else active.get(pool, [])
    if not selected:
        raise ValueError("该业务池没有已生效候选节点")
    # A full test and a service probe use the same local Mihomo API and exit path.
    # Serialize them so a manual probe remains representative instead of competing
    # with a potentially large all-node test.
    if not TEST_JOB_LOCK.acquire(blocking=False):
        raise ValueError("已有全量测速或业务复测正在进行")
    if not POOL_PROBE_LOCK.acquire(blocking=False):
        TEST_JOB_LOCK.release()
        return {"started": False, **probe_status()}
    now = datetime.now().astimezone().isoformat()
    with POOL_PROBE_STATE_LOCK:
        POOL_PROBE_STATE.update({"running": True, "pool": pool, "total": len(selected), "completed": 0,
                                 "started_at": now, "finished_at": None, "error": None})

    def update_progress(completed, _total):
        with POOL_PROBE_STATE_LOCK:
            POOL_PROBE_STATE["completed"] = completed

    def run():
        try:
            results = test_pool_candidates({pool: selected}, update_progress)
            persist_pool_probe_results(results)
            with POOL_PROBE_STATE_LOCK:
                POOL_PROBE_STATE.update({"running": False, "completed": len(selected),
                                         "finished_at": datetime.now().astimezone().isoformat()})
        except Exception as exc:
            with POOL_PROBE_STATE_LOCK:
                POOL_PROBE_STATE.update({"running": False, "error": str(exc),
                                         "finished_at": datetime.now().astimezone().isoformat()})
        finally:
            POOL_PROBE_LOCK.release()
            TEST_JOB_LOCK.release()

    threading.Thread(target=run, name=f"mihomo-pool-probe-{pool}", daemon=True).start()
    return {"started": True, **probe_status()}


def test_all(progress=None):
    return test_nodes([item["name"] for item in nodes()], progress)


def test_status():
    with TEST_STATE_LOCK:
        state = dict(TEST_STATE)
    latest = read_json(LAST_TESTS, {})
    state["last_tested_at"] = latest.get("tested_at")
    state["last_total"] = len(latest.get("results", []))
    state["last_ok"] = sum(1 for item in latest.get("results", []) if item.get("ok"))
    state["suggestions"] = suggestions()
    return state


def start_test_all():
    if not TEST_JOB_LOCK.acquire(blocking=False):
        return {"started": False, **test_status()}
    names = nodes()
    now = datetime.now().astimezone().isoformat()
    with TEST_STATE_LOCK:
        TEST_STATE.update({"running": True, "total": len(names), "completed": 0,
                           "started_at": now, "finished_at": None, "error": None,
                           "action": "full-test", "phase": "nodes", "proposal_ready": False, "applied": False})

    def update_progress(completed, total):
        with TEST_STATE_LOCK:
            TEST_STATE.update({"completed": completed, "total": total})

    def run():
        try:
            proposal = build_suggestions(test_all(update_progress))
            github = github_candidates(proposal["pools"])
            if github:
                with TEST_STATE_LOCK:
                    TEST_STATE.update({"phase": "github", "total": len(github), "completed": 0})

                def update_github_progress(completed, _total):
                    with TEST_STATE_LOCK:
                        TEST_STATE["completed"] = completed

                github_results = test_pool_candidates({"GitHub-Auto": github}, update_github_progress)
                persist_pool_probe_results(github_results)
            atomic_json(SUGGESTIONS, proposal)
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "completed": TEST_STATE["total"],
                                   "finished_at": datetime.now().astimezone().isoformat(),
                                   "proposal_ready": proposal["ready"]})
        except Exception as exc:
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "error": str(exc),
                                   "finished_at": datetime.now().astimezone().isoformat()})
        finally:
            TEST_JOB_LOCK.release()

    threading.Thread(target=run, name="mihomo-manual-speed-test", daemon=True).start()
    return {"started": True, **test_status()}


def start_replace_and_clear_slot(slot):
    """Safely replace a source's active nodes before clearing its provider."""
    if slot not in source_map():
        raise ValueError("无效机场槽位")
    if not TEST_JOB_LOCK.acquire(blocking=False):
        raise ValueError("已有测速或自动替换正在进行")
    remaining = [item["name"] for item in nodes() if item["source"] != slot]
    if not remaining:
        TEST_JOB_LOCK.release()
        raise ValueError("没有其他机场节点可用于自动替换")
    now = datetime.now().astimezone().isoformat()
    with TEST_STATE_LOCK:
        TEST_STATE.update({"running": True, "total": len(remaining), "completed": 0,
                           "started_at": now, "finished_at": None, "error": None,
                           "action": "replace-clear", "phase": "nodes",
                           "proposal_ready": False, "applied": False})

    def update_progress(completed, total):
        with TEST_STATE_LOCK:
            TEST_STATE.update({"completed": completed, "total": total})

    def run():
        path = provider_path(slot)
        previous_provider = path.read_bytes() if path.exists() else b"proxies: []\n"
        previous_candidates = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
        previous_config = MIHOMO_CONFIG.read_bytes()
        previous_suggestions = SUGGESTIONS.read_bytes() if SUGGESTIONS.exists() else None
        try:
            proposal = build_suggestions(test_nodes(remaining, update_progress))
            if not proposal["ready"]:
                raise ValueError("无法安全替换：" + str(proposal["reason"]))
            path.write_text("proxies: []\n")
            os.chmod(path, 0o600)
            replacement = validate_pools(proposal["pools"])
            generate_config(replacement)
            PREVIOUS.write_bytes(previous_candidates)
            atomic_json(CANDIDATES, replacement)
            atomic_json(SUGGESTIONS, {**proposal, "pools": replacement,
                                      "applied_at": datetime.now().astimezone().isoformat()})
            (PROVIDERS / f"{slot}.json").unlink(missing_ok=True)
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "completed": TEST_STATE["total"],
                                   "finished_at": datetime.now().astimezone().isoformat(),
                                   "proposal_ready": True, "applied": True})
        except Exception as exc:
            path.write_bytes(previous_provider)
            os.chmod(path, 0o600)
            CANDIDATES.write_bytes(previous_candidates)
            if previous_suggestions is None:
                SUGGESTIONS.unlink(missing_ok=True)
            else:
                SUGGESTIONS.write_bytes(previous_suggestions)
            if MIHOMO_CONFIG.read_bytes() != previous_config:
                MIHOMO_CONFIG.write_bytes(previous_config)
                os.chmod(MIHOMO_CONFIG, 0o640)
                try:
                    restart_mihomo()
                except Exception:
                    pass
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "error": str(exc),
                                   "finished_at": datetime.now().astimezone().isoformat()})
        finally:
            TEST_JOB_LOCK.release()

    threading.Thread(target=run, name=f"mihomo-replace-clear-{slot}", daemon=True).start()
    return {"started": True, **test_status()}


def start_retest_apply(value):
    if not suggestions()["ready"]:
        raise ValueError("请先完成全量稳定性测速并生成完整建议")
    selected = validate_pools(value)
    if not TEST_JOB_LOCK.acquire(blocking=False):
        return {"started": False, **test_status()}
    github = github_candidates(selected)
    total = sum(len(entries) for entries in selected.values())
    now = datetime.now().astimezone().isoformat()
    with TEST_STATE_LOCK:
        TEST_STATE.update({"running": True, "total": total, "completed": 0,
                           "started_at": now, "finished_at": None, "error": None,
                           "action": "retest-apply", "phase": "nodes", "proposal_ready": True, "applied": False})

    def update_progress(completed, total):
        with TEST_STATE_LOCK:
            TEST_STATE.update({"completed": completed, "total": total})

    def run():
        try:
            results = test_pool_candidates(selected, update_progress)
            if github:
                with TEST_STATE_LOCK:
                    TEST_STATE.update({"phase": "github", "total": len(github), "completed": 0})

                def update_github_progress(completed, _total):
                    update_progress(completed, len(github))
                github_results = test_pool_candidates({"GitHub-Auto": github}, update_github_progress)
                persist_pool_probe_results(github_results)
            atomic_json(CONFIRM_TESTS, {"tested_at": datetime.now().astimezone().isoformat(),
                                        "results": results})
            indexed = node_index()
            result_by_name = {(item["pool"], item["name"]): item for item in results}
            confirmed = {}
            for pool, entries in selected.items():
                stable = []
                for name in entries:
                    result = result_by_name.get((pool, name))
                    if result and result.get("success") == 3 and result.get("delay") is not None:
                        stable.append({"name": name, "source": indexed[name]["source"], "score": test_score(result)})
                confirmed[pool] = rank_pool_candidates(stable)
            final = validate_pools(confirmed)
            save_pools(final)
            atomic_json(SUGGESTIONS, {"pools": final, "generated_at": now, "ready": True,
                                      "reason": None, "applied_at": datetime.now().astimezone().isoformat()})
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "completed": TEST_STATE["total"],
                                   "finished_at": datetime.now().astimezone().isoformat(), "applied": True})
        except Exception as exc:
            with TEST_STATE_LOCK:
                TEST_STATE.update({"running": False, "error": str(exc),
                                   "finished_at": datetime.now().astimezone().isoformat()})
        finally:
            TEST_JOB_LOCK.release()

    threading.Thread(target=run, name="mihomo-candidate-confirmation", daemon=True).start()
    return {"started": True, **test_status()}


def resolve_leaf(name, depth=0):
    if not name or depth > 5:
        return name
    try:
        data = proxy_api("/proxies/" + quote(name, safe=""))
    except Exception:
        return name
    selected = data.get("now")
    if not selected or selected == name:
        return name
    return resolve_leaf(selected, depth + 1)


def source_label(name):
    for prefix, label in (("[主力] ", "主力"), ("[备用1] ", "备用 1"), ("[备用2] ", "备用 2")):
        if name and name.startswith(prefix):
            return label
    return "策略组"


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def alert_config():
    data = read_json(ALERT_CONFIG, {})
    return {
        "enabled": bool(data.get("enabled")),
        "token": str(data.get("token", "")).strip(),
        "chat_id": str(data.get("chat_id", "")).strip(),
        "notify_recovery": bool(data.get("notify_recovery", True)),
        "source_slots": [str(item) for item in data.get("source_slots", []) if isinstance(item, str)],
    }


def send_telegram_alert(message):
    config = alert_config()
    if not config["enabled"] or not config["token"] or not config["chat_id"]:
        return False, "未启用或未完成 Telegram 通知配置"
    try:
        response = subprocess.run([
            "curl", "-sS", "--max-time", "20", "--proxy", "http://127.0.0.1:7890",
            "--data-urlencode", "chat_id=" + config["chat_id"],
            "--data-urlencode", "text=" + message,
            "https://api.telegram.org/bot" + config["token"] + "/sendMessage",
        ], capture_output=True, text=True, timeout=25)
        result = json.loads(response.stdout or "{}")
        if response.returncode == 0 and result.get("ok"):
            return True, "已发送"
        return False, "Telegram 未确认接收"
    except Exception as exc:
        return False, f"Telegram 通知发送失败：{type(exc).__name__}"


def pool_is_all_down(proxies, group, prefix):
    data = proxies.get(group, {})
    names = [name for name in data.get("all", []) if name.startswith(prefix)]
    if not names:
        return False
    leaves = [proxies.get(name, {}) for name in names]
    # Mihomo owns the periodic health checks. The controller only consumes its
    # per-node alive state, so notifications do not add a second probe loop.
    return bool(leaves) and all(item.get("alive") is False for item in leaves)


def group_health_state(proxies, group):
    """Return up, down, or empty without probing DIRECT through an external URL."""
    data = proxies.get(group, {})
    names = [name for name in data.get("all", []) if name != "DIRECT"]
    if not names:
        return "empty"
    if data.get("alive") is False:
        return "down"
    leaves = [proxies.get(name, {}) for name in names]
    if leaves and all(item.get("alive") is False for item in leaves):
        return "down"
    return "up"


def selected_group_health(proxies, group):
    data = proxies.get(group, {})
    selected = data.get("now")
    if not selected:
        return "empty"
    leaf = proxies.get(selected, {})
    return "down" if leaf.get("alive") is False else "up"


def set_failsafe_exit(exit_name, target):
    data = proxy_api("/proxies/" + quote(exit_name, safe=""))
    if target not in data.get("all", []):
        raise ValueError(f"{exit_name} 缺少 {target} 出口")
    if data.get("now") != target:
        proxy_api("/proxies/" + quote(exit_name, safe=""), method="PUT", data={"name": target})


def probe_emergency_node(name, url, attempts=2):
    delays = []
    for _ in range(attempts):
        query = urlencode({"url": url, "timeout": 4000})
        try:
            data = proxy_api("/proxies/" + quote(name, safe="") + "/delay?" + query)
            if data.get("delay"):
                delays.append(int(data["delay"]))
        except Exception:
            pass
    return {
        "name": name,
        "success": len(delays),
        "delay": round(statistics.median(delays)) if delays else None,
        "jitter": max(delays) - min(delays) if len(delays) > 1 else 0 if delays else None,
    }


def probe_emergency_batch(names, url):
    with ThreadPoolExecutor(max_workers=EMERGENCY_SCAN_WORKERS) as executor:
        results = list(executor.map(lambda name: probe_emergency_node(name, url), names))
    return sorted(results, key=lambda item: (
        item["success"] < 2,
        item["delay"] if item["delay"] is not None else 999999,
        item["jitter"] if item["jitter"] is not None else 999999,
        item["name"],
    ))


def scan_emergency_exit(exit_name, spec):
    if not EMERGENCY_SCAN_LOCK.acquire(blocking=False):
        return None, {"error": "scan-busy", "results": []}
    try:
        data = proxy_api("/proxies/" + quote(spec["emergency"], safe=""))
        names = [name for name in data.get("all", []) if name != "DIRECT"][:EMERGENCY_SCAN_LIMIT]
        batches = (names[:EMERGENCY_WARM_LIMIT], names[EMERGENCY_WARM_LIMIT:])
        results = []
        for batch in batches:
            if not batch:
                continue
            tested = probe_emergency_batch(batch, spec["url"])
            results.extend(tested)
            stable = [item for item in tested if item["success"] >= 2 and item["delay"] is not None]
            if stable:
                winner = stable[0]["name"]
                report = {
                    "exit": exit_name,
                    "tested_at": datetime.now().astimezone().isoformat(),
                    "tested": len(results),
                    "catalog": len(data.get("all", [])),
                    "winner": winner,
                    "results": results,
                }
                scans = read_json(EMERGENCY_SCAN_STATE, {})
                scans[exit_name] = report
                atomic_json(EMERGENCY_SCAN_STATE, scans)
                return winner, report
        report = {
            "exit": exit_name,
            "tested_at": datetime.now().astimezone().isoformat(),
            "tested": len(results),
            "catalog": len(data.get("all", [])),
            "winner": None,
            "results": results,
        }
        scans = read_json(EMERGENCY_SCAN_STATE, {})
        scans[exit_name] = report
        atomic_json(EMERGENCY_SCAN_STATE, scans)
        return None, report
    finally:
        EMERGENCY_SCAN_LOCK.release()


def adopt_failsafe_wrappers():
    """Wrap automatic selections while preserving explicit leaf-node choices."""
    for exit_name, bindings in BUSINESS_WRAPPERS.items():
        for business_group, automatic_group in bindings:
            try:
                data = proxy_api("/proxies/" + quote(business_group, safe=""))
                if data.get("now") == automatic_group and exit_name in data.get("all", []):
                    proxy_api("/proxies/" + quote(business_group, safe=""), method="PUT",
                              data={"name": exit_name})
            except Exception:
                continue


def update_failsafes(proxies, events, now):
    state = read_json(FAILSAFE_STATE, {})
    now_epoch = time.time()
    for exit_name, spec in FAILSAFE_EXITS.items():
        watched = {group: group_health_state(proxies, group) for group in spec["watched"]}
        unavailable = bool(watched) and all(value in ("down", "empty") for value in watched.values())
        previous = state.get(exit_name, {})
        down_checks = int(previous.get("down_checks", 0)) + 1 if unavailable else 0
        up_checks = 0 if unavailable else int(previous.get("up_checks", 0)) + 1
        actual = (proxies.get(exit_name) or {}).get("now")
        active = actual if actual in (spec["primary"], spec["emergency"], "DIRECT") else previous.get("active", spec["primary"])
        desired = active
        phase = previous.get("phase", "normal")
        emergency_node = previous.get("emergency_node")
        activated_epoch = float(previous.get("activated_epoch") or 0)
        last_scan_epoch = float(previous.get("last_scan_epoch") or 0)
        last_error = None
        scan_report = None

        emergency_down = active == spec["emergency"] and selected_group_health(proxies, spec["emergency"]) == "down"
        emergency_down_checks = int(previous.get("emergency_down_checks", 0)) + 1 if emergency_down else 0
        needs_scan = (
            active == spec["primary"] and down_checks >= FAILSAFE_FAILURE_THRESHOLD
        ) or (
            active == spec["emergency"] and emergency_down_checks >= FAILSAFE_FAILURE_THRESHOLD
        )
        if needs_scan and now_epoch - last_scan_epoch >= EMERGENCY_SCAN_COOLDOWN:
            last_scan_epoch = now_epoch
            try:
                emergency_node, scan_report = scan_emergency_exit(exit_name, spec)
                if emergency_node:
                    set_failsafe_exit(spec["emergency"], emergency_node)
                    desired = spec["emergency"]
                    phase = "emergency"
                    activated_epoch = now_epoch
                    send_telegram_alert(
                        f"家庭旁路应急切换\n{exit_name} 常用候选池异常\n"
                        f"已切换应急节点：{emergency_node}\n时间：{now}")
                else:
                    phase = "exhausted"
                    last_error = "限量应急扫描未找到稳定节点"
                    if not previous.get("exhausted_alerted"):
                        send_telegram_alert(
                            f"家庭旁路告警\n{exit_name} 常用候选和应急扫描均不可用\n"
                            f"已保留原路径，未盲目切换 DIRECT\n时间：{now}")
            except Exception as exc:
                last_error = type(exc).__name__
        elif active == spec["emergency"]:
            dwell_complete = now_epoch - activated_epoch >= EMERGENCY_MIN_DWELL
            if not unavailable and up_checks >= FAILSAFE_RECOVERY_THRESHOLD and dwell_complete:
                desired = spec["primary"]
                phase = "normal"
                emergency_node = None
                send_telegram_alert(f"家庭旁路恢复\n{exit_name} 常用候选池已稳定恢复\n时间：{now}")
        elif active == "DIRECT":
            # The controller no longer selects DIRECT automatically. Preserve
            # an operator's explicit emergency choice until they change it.
            phase = "manual-direct"
        elif not unavailable:
            phase = "normal"

        transition = active != desired
        error = None
        try:
            set_failsafe_exit(exit_name, desired)
        except Exception as exc:
            error = type(exc).__name__
            desired = active
            transition = False
        if transition:
            events.append({
                "time": now,
                "group": exit_name,
                "from": active,
                "to": desired,
                "reason": ("常用候选池异常，按需选用应急节点"
                           if desired == spec["emergency"] else
                           "常用候选池连续恢复，自动回到代理"),
            })
        state[exit_name] = {
            "active": desired,
            "primary": spec["primary"],
            "emergency": spec["emergency"],
            "phase": phase,
            "emergency_node": emergency_node,
            "watched": watched,
            "down_checks": down_checks,
            "up_checks": up_checks,
            "emergency_down_checks": emergency_down_checks,
            "activated_epoch": activated_epoch,
            "last_scan_epoch": last_scan_epoch,
            "last_scan": scan_report,
            "exhausted_alerted": phase == "exhausted",
            "checked_at": now,
            "last_error": error or last_error,
        }
    atomic_json(FAILSAFE_STATE, state)
    return state


def monitor_once():
    previous = read_json(RUNTIME_STATE, {})
    events = read_json(RUNTIME_EVENTS, [])
    alert_state = read_json(ALERT_STATE, {})
    current = {}
    now = datetime.now().astimezone().isoformat()
    try:
        all_proxies = proxy_api("/proxies").get("proxies", {})
    except Exception:
        all_proxies = {}
    for group in MONITORED_GROUPS:
        try:
            data = proxy_api("/proxies/" + quote(group, safe=""))
            selected = data.get("now")
        except Exception:
            selected = None
        old_state = previous.get(group) or {}
        old = old_state.get("node")
        current[group] = {
            "node": selected,
            "checked_at": now,
            "since": old_state.get("since", now) if old == selected else now,
        }
        if old and selected and old != selected:
            events.append({"time": now, "group": group, "from": old, "to": selected,
                           "reason": "候选池健康检查触发自动切换"})
        if group in ALERT_GROUPS and all_proxies:
            config = alert_config()
            for slot in config["source_slots"]:
                source = source_map().get(slot)
                if not source:
                    continue
                key = f"{group}:{slot}"
                state = alert_state.get(key, {})
                title = f"{group} · {source['label']}"
                if pool_is_all_down(all_proxies, group, source["prefix"]):
                    checks = int(state.get("down_checks", 0)) + 1
                    alerted = bool(state.get("alerted"))
                    if checks >= ALERT_FAILURE_THRESHOLD and not alerted:
                        ok, detail = send_telegram_alert(
                            f"家庭旁路告警\n{title} 的候选节点全部不可用\n时间：{now}")
                        alerted = ok
                        state["last_error"] = None if ok else detail
                        state["alerted_at"] = now if ok else None
                    state.update({"down_checks": checks, "alerted": alerted, "checked_at": now})
                else:
                    if state.get("alerted") and config.get("notify_recovery"):
                        send_telegram_alert(f"家庭旁路恢复\n{title} 已恢复可用节点\n时间：{now}")
                    state = {"down_checks": 0, "alerted": False, "checked_at": now, "last_error": None}
                alert_state[key] = state
    if all_proxies:
        adopt_failsafe_wrappers()
        update_failsafes(all_proxies, events, now)
    atomic_json(RUNTIME_STATE, current)
    atomic_json(RUNTIME_EVENTS, events[-100:])
    atomic_json(ALERT_STATE, alert_state)


def monitor_loop():
    while True:
        try:
            monitor_once()
        except Exception:
            pass
        time.sleep(30)


def status():
    result = {}
    events = read_json(RUNTIME_EVENTS, [])
    runtime = read_json(RUNTIME_STATE, {})
    for group in ("AI", "AI-Auto", "AI-出口", "JP-AI", "SG-AI", "US-AI", "其他-AI", "Youtube", "HK-视频", "HK-视频-出口", "Telegram", "TG-Auto", "TG-出口", "Google", "GitHub", "GitHub-Auto", "GitHub-出口", "V2EX", "V2EX-Auto", "Others", "Proxy-Auto", "Proxy-出口"):
        try:
            data = proxy_api("/proxies/" + quote(group, safe=""))
            leaf = resolve_leaf(group)
            leaf_data = proxy_api("/proxies/" + quote(leaf, safe="")) if leaf else {}
            latest = next((event for event in reversed(events) if event.get("group") == group), None)
            result[group] = {"now": data.get("now"), "leaf": leaf, "source": source_label(leaf),
                             "type": (str(data.get("type") or "策略") + " · TCP 探针 · "
                                      + ("UDP 声明/QUIC 未验证" if leaf_data.get("udp")
                                         else "未声明 UDP")),
                             "history": data.get("history", [])[-3:],
                             "last_change": latest, "since": (runtime.get(group) or {}).get("since"),
                             "udp_declared": bool(leaf_data.get("udp")), "quic_verified": False}
        except Exception:
            result[group] = {"now": None, "leaf": None, "source": "不可用", "type": "unavailable",
                             "history": [], "last_change": None, "since": None,
                             "udp_declared": False, "quic_verified": False}
    return {"groups": result, "events": events[-20:], "failsafes": read_json(FAILSAFE_STATE, {}),
            "emergency_scans": read_json(EMERGENCY_SCAN_STATE, {}),
            "versions": [path.name for path in sorted(VERSIONS.glob("*.yaml"), reverse=True)[:5]]}


PAGE = r'''<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon href="data:,"><title>机场与候选池</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{max-width:1100px;margin:28px auto;padding:0 18px;background:#13171a;color:#edf2f3;font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:#92ddb0}.top{display:flex;justify-content:space-between;gap:12px;align-items:center}.tabs{display:flex;gap:8px;margin:22px 0;flex-wrap:wrap}.tabs button,.btn{border:1px solid #435159;background:#20272b;color:#e8edef;padding:9px 12px;border-radius:5px}.tabs .on,.primary{background:#62c77c!important;color:#082112!important;border-color:#62c77c!important;font-weight:650}.panel{display:none}.panel.on{display:block}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.card{padding:16px;border:1px solid #364147;background:#1c2226;border-radius:7px}.muted{color:#aab5ba;line-height:1.5}input,select{width:100%;padding:9px;background:#0f1417;color:#fff;border:1px solid #47555c;border-radius:5px}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.row>*{flex:1}.node{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid #303a3f}.node button{width:32px;height:30px;border:1px solid #46545a;background:#252e33;color:#fff;border-radius:4px}.status{padding:10px 0;color:#9fe1b8}.bad{color:#ffada3}.pill{display:inline-block;padding:3px 7px;margin:3px;border-radius:4px;background:#29343a}.delay{font-variant-numeric:tabular-nums;color:#8dd9ac}.event{padding:9px 0;border-bottom:1px solid #303a3f;font-size:13px}h1{font-size:26px}h2{font-size:18px;letter-spacing:0}@media(max-width:640px){body{margin-top:20px}.row{align-items:stretch;flex-direction:column}}</style><div class=top><a href="/">← 家庭旁路设备管理</a><a href="http://__FAMILY_PROXY_IP__:18089/">MetaCubeXD</a></div><h1>机场与候选池</h1><div class=tabs><button class=on onclick="tab('subs',this)">订阅来源</button><button onclick="tab('pools',this)">候选池</button><button onclick="tab('runtime',this)">自动切换状态</button></div><section id=subs class="panel on"><p class=muted>订阅由 NAS 直连拉取，不经过代理、Fake-IP 或第三方转换。链接不保存；导入和应用失败时保留现有可用配置。</p><div id=slots class=grid></div></section><section id=pools class=panel><div class=row><input id=filter placeholder="筛选节点名称"><button class="btn primary" onclick=testAll()>三次稳定性测速</button><button class=btn onclick=save()>校验并应用</button><button class=btn onclick=rollback()>回退上一版</button></div><div id=testStatus class=status></div><div id=poolGrid class=grid></div></section><section id=runtime class=panel><button class=btn onclick=loadStatus()>刷新状态</button><div id=runtimeGrid class=grid></div><h2>最近自动切换</h2><div id=events class=card></div></section><script>
const csrf='__CSRF__',poolNames=['HK-视频','JP-AI','SG-AI','US-AI','TG','Proxy'];let all=[],pools={},delays={};async function api(path,opt={}){let r=await fetch(new URL("/airport"+path,location.origin),{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error);return d}function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}function metric(name){let x=delays[name];return x?.delay!=null?` · ${x.delay} ms · 抖动 ${x.jitter} · ${x.success}/3`:''}function tab(id,b){document.querySelectorAll('.panel').forEach(x=>x.classList.remove('on'));document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('on'));document.querySelector('#'+id).classList.add('on');b.classList.add('on');if(id==='runtime')loadStatus()}function slotCard(s){return `<div class=card><h2>${s.label}</h2><p class=muted>${s.imported?`已导入 ${s.nodes} 个有效节点<br>${s.updated_at}`:'尚未导入'}</p><input id="url-${s.slot}" placeholder="HTTPS 原生 Clash/Mihomo 订阅链接"><button class="btn primary" onclick="imp('${s.slot}')">直连导入/替换</button><button class=btn onclick="dropSlot('${s.slot}')">清空</button><div id="msg-${s.slot}" class=status></div></div>`}async function load(){let d=await api('/api/state');document.querySelector('#slots').innerHTML=d.slots.map(slotCard).join('');all=d.nodes;pools=d.pools;delays=Object.fromEntries((d.tests?.results||[]).map(x=>[x.name,x]));if(d.tests?.tested_at)testStatus.textContent='上次稳定性测速：'+d.tests.tested_at;renderPools()}function options(pool){let q=document.querySelector('#filter')?.value.toLowerCase()||'';return all.filter(n=>!pools[pool].includes(n.name)&&n.name.toLowerCase().includes(q)).map(n=>`<option value="${encodeURIComponent(n.name)}">${esc(n.name)}${metric(n.name)}</option>`).join('')}function renderPools(){document.querySelector('#poolGrid').innerHTML=poolNames.map(pool=>`<div class=card><h2>${pool} <span class=muted>${pools[pool].length}/5</span></h2><div class=row><select id="sel-${pool}">${options(pool)}</select><button class=btn onclick="add('${pool}')">加入</button></div>${pools[pool].map((name,i)=>`<div class=node><span>${esc(name)} <b class=delay>${metric(name)}</b></span><span><button onclick="move('${pool}',${i},-1)">↑</button><button onclick="move('${pool}',${i},1)">↓</button><button onclick="removeNode('${pool}',${i})">×</button></span></div>`).join('')}</div>`).join('')}function add(p){if(pools[p].length>=5)return alert('每个池最多 5 个节点');let e=document.querySelector('#sel-'+p);if(e.value)pools[p].push(decodeURIComponent(e.value));renderPools()}function move(p,i,d){let j=i+d;if(j<0||j>=pools[p].length)return;[pools[p][i],pools[p][j]]=[pools[p][j],pools[p][i]];renderPools()}function removeNode(p,i){if(pools[p].length===1)return alert('候选池至少保留一个节点');pools[p].splice(i,1);renderPools()}document.querySelector('#filter').addEventListener('input',renderPools);async function imp(s){let m=document.querySelector('#msg-'+s);try{m.textContent='正在直连拉取、过滤、生成并验证...';await api('/api/import',{method:'POST',body:JSON.stringify({slot:s,url:document.querySelector('#url-'+s).value.trim()})});m.className='status';await load()}catch(e){m.textContent=e.message;m.className='status bad'}}async function dropSlot(s){if(confirm('清空后仍须保证每个业务池至少有一个节点，确定继续？')){try{await api('/api/remove',{method:'POST',body:JSON.stringify({slot:s})});await load()}catch(e){alert(e.message)}}}async function testAll(){try{testStatus.textContent='正在对每个节点连续测试三次；只在本次手工操作中执行...';let d=await api('/api/test-all',{method:'POST',body:'{}'});delays=Object.fromEntries(d.results.map(x=>[x.name,x]));testStatus.textContent=`测速完成：${d.results.filter(x=>x.ok).length}/${d.results.length} 稳定可用`;renderPools()}catch(e){testStatus.textContent=e.message;testStatus.className='status bad'}}async function save(){try{pools=await api('/api/pools',{method:'POST',body:JSON.stringify({pools})});testStatus.textContent='配置校验、重启验证均通过；主力节点已自动排在备用前';testStatus.className='status';renderPools();await loadStatus()}catch(e){testStatus.textContent=e.message;testStatus.className='status bad'}}async function rollback(){try{pools=await api('/api/rollback',{method:'POST',body:'{}'});testStatus.textContent='已验证并恢复上一版候选池';renderPools()}catch(e){alert(e.message)}}async function loadStatus(){let d=await api('/api/status');runtimeGrid.innerHTML=Object.entries(d.groups).map(([k,v])=>`<div class=card><h2>${esc(k)}</h2><p><span class=pill>${esc(v.type)}</span><span class=pill>${esc(v.source)}</span></p><p>策略：<b>${esc(v.now||'未选择')}</b></p><p>实际节点：<b>${esc(v.leaf||'未选择')}</b></p><p class=muted>${v.history.map(x=>x.delay+' ms').join(' · ')||'暂无探测记录'}</p></div>`).join('');events.innerHTML=d.events.length?d.events.slice().reverse().map(e=>`<div class=event><b>${esc(e.group)}</b>：${esc(e.from)} → ${esc(e.to)}<div class=muted>${esc(e.time)} · ${esc(e.reason)}</div></div>`).join(''):'<span class=muted>尚无自动切换记录</span>'}load()</script>'''


PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>机场与候选池</title><style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","PingFang SC","Segoe UI",sans-serif;background:#000;color:#f5f5f7;letter-spacing:0}*{box-sizing:border-box}body{margin:0;background:#000;color:#f5f5f7}.topbar{position:sticky;top:0;z-index:10;border-bottom:1px solid rgba(255,255,255,.1);background:rgba(18,18,20,.88);backdrop-filter:saturate(180%) blur(22px);-webkit-backdrop-filter:saturate(180%) blur(22px)}.topbar-inner{max-width:1120px;min-height:58px;margin:auto;padding:0 22px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-size:17px;font-weight:650;color:#fff;white-space:nowrap}.nav{display:flex;align-items:center;gap:4px;padding:3px;background:#2c2c2e;border-radius:8px}.nav a{padding:7px 11px;border-radius:6px;color:#aeaeb2;text-decoration:none;font-size:13px;white-space:nowrap}.nav a.active{background:#636366;color:#fff}.wrap{max-width:1120px;margin:auto;padding:38px 22px 68px}.intro{margin-bottom:22px}.eyebrow{font-size:13px;color:#8e8e93;margin-bottom:7px}.intro h1{font-size:30px;line-height:1.15;margin:0;font-weight:700;letter-spacing:0}.intro p{margin:9px 0 0;color:#98989d;font-size:14px;line-height:1.5}.tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:3px;max-width:520px;padding:3px;margin:24px 0;background:#2c2c2e;border-radius:8px}.tabs button{height:33px;border:0;border-radius:6px;background:transparent;color:#aeaeb2;font:600 13px inherit;cursor:pointer}.tabs button.on{background:#636366;color:#fff}.panel{display:none}.panel.on{display:block}.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:23px 2px 9px}.section-title h2{margin:0;color:#8e8e93;font-size:13px;font-weight:600}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:12px}.card{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.card-head{padding:15px 16px 12px}.card h2{font-size:16px;margin:0;letter-spacing:0}.muted{color:#8e8e93;font-size:12px;line-height:1.5;overflow-wrap:anywhere}.source-state{margin:6px 0 0;color:#30d158;font-size:13px}.source-state.empty{color:#8e8e93}.form{padding:0 16px 16px}.form input,.toolbar input,.add-node select{width:100%;height:38px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:14px inherit;outline:none}.form input:focus,.toolbar input:focus,.add-node select:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}.actions{display:flex;gap:8px;margin-top:10px}button{font:600 13px inherit;letter-spacing:0;cursor:pointer}.btn{height:36px;border:0;border-radius:7px;background:#3a3a3c;color:#f5f5f7;padding:0 13px}.btn:hover{background:#48484a}.btn.primary{background:#0a84ff;color:#fff}.btn.primary:hover{background:#409cff}.btn.danger{background:transparent;color:#ff453a}.status{min-height:0;margin-top:10px;color:#30d158;font-size:12px}.status:empty{display:none}.bad{color:#ff6961!important}.toolbar{display:grid;grid-template-columns:minmax(220px,1fr) auto auto auto;gap:8px;align-items:center;padding:13px 14px;border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e}.pool-card .card-head{display:flex;align-items:center;justify-content:space-between}.count{font-size:12px;color:#8e8e93}.add-node{display:grid;grid-template-columns:1fr auto;gap:8px;padding:0 14px 13px}.node{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:11px 14px;border-top:1px solid #38383a}.node-name{font-size:13px;line-height:1.45;overflow-wrap:anywhere}.node-tools{display:flex;gap:3px}.icon-btn{width:30px;height:30px;border:0;border-radius:6px;background:transparent;color:#0a84ff;font-size:15px}.icon-btn:hover{background:rgba(10,132,255,.12)}.icon-btn.remove{color:#ff453a}.delay{display:block;color:#30d158;font-size:11px;font-variant-numeric:tabular-nums;margin-top:3px}.runtime-card{padding:15px 16px}.pill{display:inline-block;padding:4px 7px;margin:7px 4px 8px 0;border-radius:6px;background:#2c2c2e;color:#aeaeb2;font-size:11px}.runtime-line{font-size:13px;line-height:1.55;margin-top:5px;overflow-wrap:anywhere}.events{border:1px solid #2c2c2e;border-radius:8px;background:#1c1c1e;overflow:hidden}.event{padding:12px 15px;border-top:1px solid #38383a;font-size:13px}.event:first-child{border-top:0}@media(max-width:760px){.topbar-inner{padding:10px 14px;align-items:flex-start;flex-direction:column;gap:8px}.nav{width:100%;display:grid;grid-template-columns:repeat(4,1fr)}.nav a{text-align:center;padding:7px 5px;white-space:normal}.wrap{padding:28px 14px 52px}.tabs{max-width:none}.grid{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr}.toolbar .btn{width:100%}.actions{display:grid;grid-template-columns:1fr 1fr}.add-node{grid-template-columns:1fr}.add-node .btn{width:100%}}
</style></head><body><header class="topbar"><div class="topbar-inner"><div class="brand">家庭旁路</div><nav class="nav"><a href="/">设备</a><a href="/rules">规则</a><a class="active" href="/airport/">机场与候选池</a><a href="http://__FAMILY_PROXY_IP__:18091/">DNS</a></nav></div></header><main class="wrap"><div class="intro"><div class="eyebrow">PROXY SOURCES</div><h1>机场与候选池</h1><p>订阅只负责导入节点；业务流量仅使用经过筛选的候选池。</p></div><div class="tabs"><button class="on" onclick="tab('subs',this)">订阅来源</button><button onclick="tab('pools',this)">候选池</button><button onclick="tab('runtime',this)">切换状态</button></div><section id="subs" class="panel on"><div class="section-title"><h2>订阅来源</h2></div><p class="muted">Z4Pro 使用本地网络直连拉取，不经过代理、Fake-IP 或第三方转换；订阅链接不会保存。</p><div id="slots" class="grid"></div></section><section id="pools" class="panel"><div class="toolbar"><input id="filter" placeholder="筛选节点名称"><button class="btn primary" onclick="testAll()">稳定性测速</button><button class="btn" onclick="save()">校验并应用</button><button class="btn" onclick="rollback()">回退上一版</button></div><div id="testStatus" class="status"></div><div class="section-title"><h2>业务候选池</h2></div><div id="poolGrid" class="grid"></div></section><section id="runtime" class="panel"><div class="toolbar"><div class="muted">显示 fallback 当前策略、实际叶子节点和最近自动切换。</div><button class="btn primary" onclick="loadStatus()">刷新状态</button></div><div class="section-title"><h2>当前出口</h2></div><div id="runtimeGrid" class="grid"></div><div class="section-title"><h2>最近自动切换</h2></div><div id="events" class="events"></div></section></main><script>
const csrf='__CSRF__',poolNames=['HK-视频','JP-AI','SG-AI','US-AI','TG','Proxy'];let all=[],pools={},delays={};async function api(path,opt={}){let r=await fetch(new URL("/airport"+path,location.origin),{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}function esc(s){return String(s??'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}function metric(name){let x=delays[name];return x&&x.delay!=null?x.delay+' ms · 抖动 '+x.jitter+' · '+x.success+'/3':''}function tab(id,b){document.querySelectorAll('.panel').forEach(function(x){x.classList.remove('on')});document.querySelectorAll('.tabs button').forEach(function(x){x.classList.remove('on')});document.querySelector('#'+id).classList.add('on');b.classList.add('on');if(id==='runtime')loadStatus()}function slotCard(s){let imported=s.imported;return '<article class="card"><div class="card-head"><h2>'+esc(s.label)+'</h2><div class="source-state '+(imported?'':'empty')+'">'+(imported?'已导入 '+s.nodes+' 个有效节点':'尚未导入')+'</div><div class="muted">'+(imported?esc(s.updated_at):'导入后可在候选池中选择节点')+'</div></div><div class="form"><input id="url-'+s.slot+'" type="url" autocomplete="off" placeholder="HTTPS 原生 Clash/Mihomo 订阅链接"><div class="actions"><button class="btn primary" onclick="imp(\''+s.slot+'\')">直连导入或替换</button><button class="btn danger" onclick="dropSlot(\''+s.slot+'\')">清空</button></div><div id="msg-'+s.slot+'" class="status"></div></div></article>'}async function load(){let d=await api('/api/state');document.querySelector('#slots').innerHTML=d.slots.map(slotCard).join('');all=d.nodes;pools=d.pools;delays=Object.fromEntries((d.tests&&d.tests.results||[]).map(function(x){return [x.name,x]}));if(d.tests&&d.tests.tested_at)document.querySelector('#testStatus').textContent='上次稳定性测速：'+d.tests.tested_at;renderPools()}function options(pool){let q=(document.querySelector('#filter')&&document.querySelector('#filter').value.toLowerCase())||'';return all.filter(function(n){return !pools[pool].includes(n.name)&&n.name.toLowerCase().includes(q)}).map(function(n){return '<option value="'+encodeURIComponent(n.name)+'">'+esc(n.name)+(metric(n.name)?' · '+metric(n.name):'')+'</option>'}).join('')}function renderPools(){document.querySelector('#poolGrid').innerHTML=poolNames.map(function(pool){let rows=pools[pool].map(function(name,i){return '<div class="node"><div class="node-name">'+esc(name)+(metric(name)?'<span class="delay">'+metric(name)+'</span>':'')+'</div><div class="node-tools"><button class="icon-btn" aria-label="上移" title="上移" onclick="move(\''+pool+'\','+i+',-1)">↑</button><button class="icon-btn" aria-label="下移" title="下移" onclick="move(\''+pool+'\','+i+',1)">↓</button><button class="icon-btn remove" aria-label="移除" title="移除" onclick="removeNode(\''+pool+'\','+i+')">×</button></div></div>'}).join('');return '<article class="card pool-card"><div class="card-head"><h2>'+esc(pool)+'</h2><span class="count">'+pools[pool].length+'/5</span></div><div class="add-node"><select id="sel-'+pool+'">'+options(pool)+'</select><button class="btn" onclick="add(\''+pool+'\')">加入</button></div>'+rows+'</article>'}).join('')}function add(p){if(pools[p].length>=5)return alert('每个池最多 5 个节点');let e=document.querySelector('#sel-'+p);if(e.value)pools[p].push(decodeURIComponent(e.value));renderPools()}function move(p,i,d){let j=i+d;if(j<0||j>=pools[p].length)return;let x=pools[p][i];pools[p][i]=pools[p][j];pools[p][j]=x;renderPools()}function removeNode(p,i){if(pools[p].length===1)return alert('候选池至少保留一个节点');pools[p].splice(i,1);renderPools()}document.querySelector('#filter').addEventListener('input',renderPools);async function imp(s){let m=document.querySelector('#msg-'+s);try{m.textContent='正在直连拉取、过滤并验证…';m.className='status';await api('/api/import',{method:'POST',body:JSON.stringify({slot:s,url:document.querySelector('#url-'+s).value.trim()})});m.textContent='导入和配置验证已完成';await load()}catch(e){m.textContent=e.message;m.className='status bad'}}async function dropSlot(s){if(!confirm('清空后仍须保证每个业务池至少有一个节点，确定继续？'))return;try{await api('/api/remove',{method:'POST',body:JSON.stringify({slot:s})});await load()}catch(e){alert(e.message)}}async function testAll(){let status=document.querySelector('#testStatus');try{status.textContent='正在对每个节点连续测试三次，本次操作完成后即停止…';status.className='status';let d=await api('/api/test-all',{method:'POST',body:'{}'});delays=Object.fromEntries(d.results.map(function(x){return [x.name,x]}));status.textContent='测速完成：'+d.results.filter(function(x){return x.ok}).length+'/'+d.results.length+' 稳定可用';renderPools()}catch(e){status.textContent=e.message;status.className='status bad'}}async function save(){let status=document.querySelector('#testStatus');try{pools=await api('/api/pools',{method:'POST',body:JSON.stringify({pools:pools})});status.textContent='配置校验和重启验证均通过，主力节点已排在备用前';status.className='status';renderPools();await loadStatus()}catch(e){status.textContent=e.message;status.className='status bad'}}async function rollback(){try{pools=await api('/api/rollback',{method:'POST',body:'{}'});document.querySelector('#testStatus').textContent='已验证并恢复上一版候选池';renderPools()}catch(e){alert(e.message)}}async function loadStatus(){let d=await api('/api/status');document.querySelector('#runtimeGrid').innerHTML=Object.entries(d.groups).map(function(entry){let k=entry[0],v=entry[1];return '<article class="card runtime-card"><h2>'+esc(k)+'</h2><div><span class="pill">'+esc(v.type)+'</span><span class="pill">'+esc(v.source)+'</span></div><div class="runtime-line muted">策略</div><div class="runtime-line"><b>'+esc(v.now||'未选择')+'</b></div><div class="runtime-line muted">实际节点</div><div class="runtime-line"><b>'+esc(v.leaf||'未选择')+'</b></div><div class="runtime-line muted">'+(v.history.map(function(x){return x.delay+' ms'}).join(' · ')||'暂无探测记录')+'</div></article>'}).join('');document.querySelector('#events').innerHTML=d.events.length?d.events.slice().reverse().map(function(e){return '<div class="event"><b>'+esc(e.group)+'</b>：'+esc(e.from)+' → '+esc(e.to)+'<div class="muted">'+esc(e.time)+' · '+esc(e.reason)+'</div></div>'}).join(''):'<div class="event muted">尚无自动切换记录</div>'}load()
</script></body></html>'''
PAGE = PAGE.replace('<div class="eyebrow">PROXY SOURCES</div>', '')
PAGE = PAGE.replace('href="http://__FAMILY_PROXY_IP__:18091/"', 'href="/dns/"')
PAGE = PAGE.replace(
    '<a href="/">设备</a><a href="/rules">规则</a><a class="active" href="/airport/">机场与候选池</a><a href="/dns/">DNS</a>',
    '<a href="/">设备</a><a href="/dns/">DNS</a><a class="active" href="/airport/">机场与候选池</a><a href="/rules">规则</a><a href="/mihomo-maintenance">维护</a>',
    1,
)
PAGE = PAGE.replace('</style>', '@media(max-width:760px){.nav{grid-template-columns:repeat(5,1fr)}}</style>', 1)
PAGE = PAGE.replace('</style>', '.probe-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.probe-card{padding:14px}.probe-card h3{margin:0;font-size:15px}.probe-target{margin-top:7px;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#aeaeb2;overflow-wrap:anywhere}.probe-meta{margin-top:10px;color:#8e8e93;font-size:12px;line-height:1.55}.probe-result{margin-top:7px;font-size:13px;font-variant-numeric:tabular-nums}.probe-actions{margin-top:12px}.probe-actions .btn{width:100%}</style>', 1)
_slot_card_start = PAGE.find("function slotCard(s){")
_slot_card_end = PAGE.find("async function load(){", _slot_card_start)
if _slot_card_start < 0 or _slot_card_end < 0:
    raise RuntimeError("subscription card template marker missing")
_slot_card_js = r'''function slotCard(s){let imported=s.imported;let removeButton=s.removable?'<button class="btn danger" onclick="deleteSource(\''+s.slot+'\')">删除机场</button>':'';return '<article class="card"><div class="card-head"><h2>'+esc(s.label)+'</h2><div class="source-state '+(imported?'':'empty')+'">'+(imported?'已导入 '+s.nodes+' 个有效节点':'尚未导入')+'</div><div class="muted">'+(imported?esc(s.updated_at):'导入后可在候选池中选择节点')+'</div></div><div class="form"><input id="url-'+s.slot+'" type="text" inputmode="url" autocapitalize="off" spellcheck="false" autocomplete="off" placeholder="HTTPS 原生 Clash/Mihomo 订阅链接"><div class="actions"><button class="btn primary" onclick="imp(\''+s.slot+'\')">直连导入或替换</button><button class="btn danger" onclick="dropSlot(\''+s.slot+'\')">清空节点</button>'+removeButton+'</div><div id="msg-'+s.slot+'" class="status"></div></div></article>'}'''
PAGE = PAGE[:_slot_card_start] + _slot_card_js + PAGE[_slot_card_end:]
PAGE = PAGE.replace('<div class="section-title"><h2>订阅来源</h2></div>',
                    '<div class="section-title"><h2>订阅来源</h2><button class="icon-btn" title="添加备用机场" aria-label="添加备用机场" onclick="addSource()">+</button></div>')
_history_marker = "<div class=\"runtime-line muted\">'+(v.history.map"
_stable_marker = "<div class=\"runtime-line muted\">稳定保持：'+esc(v.since||'等待记录')+'</div>"
if _history_marker not in PAGE:
    raise RuntimeError("runtime status marker missing from page template")
PAGE = PAGE.replace(_history_marker, _stable_marker + _history_marker, 1)
# Keep the subscription landing page small. The full node catalogue is only
# needed once the user opens the candidate-pool tab.
PAGE = PAGE.replace("if(id==='runtime')loadStatus()", "if(id==='pools')loadPools();if(id==='runtime')loadStatus()")
PAGE = PAGE.replace("let all=[],pools={},delays={};", "let all=[],pools={},activePools={},suggestion=null,delays={},catalogLoaded=false,testPoll=null,probePoll=null,probeData={};")
PAGE = PAGE.replace("poolNames=['HK-视频','JP-AI','SG-AI','US-AI','TG','Proxy']", "poolNames=['HK-视频','JP-AI','SG-AI','US-AI','其他-AI','TG','Proxy']")
PAGE = PAGE.replace("async function load(){let d=await api('/api/state');", "async function load(){let d=await api('/api/nodes');")
PAGE = PAGE.replace("renderPools()}function options", "catalogLoaded=true;renderPools()}async function loadSummary(){let d=await api('/api/state');document.querySelector('#slots').innerHTML=d.slots.map(slotCard).join('');pools=d.pools;if(d.tests&&d.tests.tested_at)document.querySelector('#testStatus').textContent='上次稳定性测速：'+d.tests.tested_at}async function loadPools(){if(catalogLoaded){await loadProbeReport();return}try{await load();await refreshTestStatus();await loadProbeReport()}catch(e){pageError(e)}}function pageError(e){let box=document.querySelector('#pageStatus');if(!box){box=document.createElement('div');box.id='pageStatus';box.className='status bad';document.querySelector('.intro').append(box)}box.innerHTML='页面数据加载失败。<button class=\"btn\" onclick=\"loadSummary().catch(pageError)\">重试</button>';console.error(e)}function options")
PAGE = PAGE.replace("}load()", "}loadSummary().catch(pageError)")
PAGE = PAGE.replace("async function imp(s){", "async function addSource(){try{await api('/api/sources',{method:'POST',body:'{}'});await loadSummary()}catch(e){pageError(e)}}async function deleteSource(s){if(!confirm('删除机场会清空该来源的节点；若节点正在被当前候选池使用，操作将被拒绝。确定删除？'))return;try{await api('/api/source-remove',{method:'POST',body:JSON.stringify({slot:s})});await loadSummary()}catch(e){alert(e.message)}}async function imp(s){")
PAGE = PAGE.replace("all=d.nodes;pools=d.pools;", "all=d.nodes;activePools=d.pools;suggestion=d.suggestions||null;pools=suggestion&&suggestion.generated_at?suggestion.pools:activePools;")
PAGE = PAGE.replace('<div class="toolbar"><input id="filter" placeholder="筛选节点名称">', '<div class="toolbar" id="poolToolbar"><input id="filter" placeholder="筛选节点名称">')
PAGE = PAGE.replace('<button class="btn primary" onclick="testAll()">稳定性测速</button><button class="btn" onclick="save()">校验并应用</button>', '<button class="btn primary" onclick="testAll()">全量稳定性测速</button><button class="btn" onclick="confirmApply()">复测并生效</button>')
PAGE = PAGE.replace(
    '</style></head>',
    '#poolToolbar{padding:0;border:0;background:transparent}.toolbar .btn{width:108px;padding:0 8px;white-space:nowrap}@media(max-width:760px){.toolbar .btn{width:100%;padding:0 13px}}</style></head>',
    1,
)
PAGE = PAGE.replace('<div class="section-title"><h2>业务候选池</h2></div>', '<div class="section-title"><h2>业务可达性报告</h2><span class="muted">只验证当前候选池，不改变排序或出口</span></div><div id="probeGrid" class="probe-grid"></div><div class="section-title"><h2>待生效候选池</h2><span class="muted">测速建议不会自动替换当前出口</span></div>')
_old_speed_test = "async function testAll(){let status=document.querySelector('#testStatus');try{status.textContent='正在对每个节点连续测试三次，本次操作完成后即停止…';status.className='status';let d=await api('/api/test-all',{method:'POST',body:'{}'});delays=Object.fromEntries(d.results.map(function(x){return [x.name,x]}));status.textContent='测速完成：'+d.results.filter(function(x){return x.ok}).length+'/'+d.results.length+' 稳定可用';renderPools()}catch(e){status.textContent=e.message;status.className='status bad'}}"
_new_speed_test = "function showTestStatus(d){let status=document.querySelector('#testStatus');clearTimeout(testPoll);if(d.running){status.textContent=(d.action==='retest-apply'?'候选池复测中：':'全量测速（含 GitHub 专项）中：')+d.completed+'/'+d.total+' 个节点已完成；可继续浏览页面';status.className='status';testPoll=setTimeout(refreshTestStatus,1000);return}if(d.error){status.textContent=(d.action==='retest-apply'?'复测未生效：':'测速未完成：')+d.error;status.className='status bad';return}if(d.finished_at&&d.action==='retest-apply'){status.textContent=d.applied?'复测、GitHub 专项、配置校验和运行验证均通过，候选池已生效':'复测完成，但未生效';status.className=d.applied?'status':'status bad';catalogLoaded=false;loadPools();return}if(d.finished_at&&d.action==='full-test'){status.textContent=d.suggestions&&d.suggestions.ready?'全量测速和 GitHub 专项已完成，已生成待生效建议；确认后点击“复测并生效”':'测速完成，但有业务池没有连续三次成功的节点';status.className=d.suggestions&&d.suggestions.ready?'status':'status bad';catalogLoaded=false;loadPools();return}if(d.suggestions&&d.suggestions.ready){status.textContent='已生成待生效建议；当前出口保持不变，点击“复测并生效”后才会更新';status.className='status';return}if(d.last_tested_at){status.textContent='上次稳定性测速：'+d.last_tested_at}}async function refreshTestStatus(){try{showTestStatus(await api('/api/test-status'))}catch(e){let status=document.querySelector('#testStatus');status.textContent='测速状态读取失败：'+e.message;status.className='status bad'}}async function testAll(){try{showTestStatus(await api('/api/test-all',{method:'POST',body:'{}'}))}catch(e){let status=document.querySelector('#testStatus');status.textContent=e.message;status.className='status bad'}}async function confirmApply(){let status=document.querySelector('#testStatus');try{showTestStatus(await api('/api/retest-apply',{method:'POST',body:JSON.stringify({pools:pools})}))}catch(e){status.textContent=e.message;status.className='status bad'}}"
_new_speed_test = _new_speed_test.replace(
    "status.textContent=(d.action==='retest-apply'?'候选池复测中：':'全量测速（含 GitHub 专项）中：')+d.completed+'/'+d.total",
    "status.textContent=(d.phase==='github'?'GitHub 专项测速中：':(d.action==='retest-apply'?'候选池复测中：':'全量测速中：'))+d.completed+'/'+d.total",
)
_new_speed_test = _new_speed_test.replace(
    "function showTestStatus(d){",
    "let handledTestCompletion='';function showTestStatus(d){",
    1,
)
_new_speed_test = _new_speed_test.replace(
    "status.className=d.applied?'status':'status bad';catalogLoaded=false;loadPools();return}",
    "status.className=d.applied?'status':'status bad';let completion=d.action+':'+d.finished_at;if(handledTestCompletion!==completion){handledTestCompletion=completion;catalogLoaded=false;loadPools()}return}",
    1,
)
_new_speed_test = _new_speed_test.replace(
    "status.className=d.suggestions&&d.suggestions.ready?'status':'status bad';catalogLoaded=false;loadPools();return}",
    "status.className=d.suggestions&&d.suggestions.ready?'status':'status bad';let completion=d.action+':'+d.finished_at;if(handledTestCompletion!==completion){handledTestCompletion=completion;catalogLoaded=false;loadPools()}return}",
    1,
)
if _old_speed_test not in PAGE:
    raise RuntimeError("speed test template marker missing")
PAGE = PAGE.replace(_old_speed_test, _new_speed_test, 1)
PAGE = PAGE.replace(
    "async function api(path,opt={}){let r=await fetch(new URL(\"/airport\"+path,location.origin),{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}}),d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}",
    "async function api(path,opt={}){let r;try{r=await fetch(location.protocol+'//'+location.host+'/airport'+path,{...opt,headers:{'Content-Type':'application/json','X-CSRF':csrf}})}catch(error){throw Error('浏览器未能提交请求；请刷新页面后重试')}let d=await r.json();if(!r.ok){if(r.status===403&&d.error==='request rejected'){location.reload();return new Promise(function(){})}throw Error(d.error||'请求失败')}return d}",
    1,
)
PAGE = PAGE.replace(
    "</style>",
    "#testStatus{min-height:36px;line-height:18px;font-variant-numeric:tabular-nums}</style>",
    1,
)
PAGE = PAGE.replace(
    "配置校验和重启验证均通过，主力节点已排在备用前",
    "配置校验和重启验证均通过，候选节点已按测速结果排序",
    1,
)
_auto_replace_clear_js = r'''const familyShowTestStatus=showTestStatus;showTestStatus=function(d){let status=document.querySelector('#testStatus');if(d.action==='replace-clear'){clearTimeout(testPoll);if(d.running){status.textContent='正在复测其余机场节点并自动替换候选池：'+d.completed+'/'+d.total+'；可继续浏览页面';status.className='status';testPoll=setTimeout(refreshTestStatus,1000);return}if(d.error){status.textContent='自动替换未执行：'+d.error;status.className='status bad';return}if(d.finished_at){status.textContent=d.applied?'已复测、替换候选池并清空该机场节点；配置校验和运行验证均通过':'自动替换未完成';status.className=d.applied?'status':'status bad';let completion=d.action+':'+d.finished_at;if(handledTestCompletion!==completion){handledTestCompletion=completion;catalogLoaded=false;loadPools()}return}}familyShowTestStatus(d)};async function dropSlot(s){if(!confirm('将自动复测其余机场节点、替换全部受影响业务池，验证成功后才清空此机场。确定继续？'))return;try{showTestStatus(await api('/api/replace-clear',{method:'POST',body:JSON.stringify({slot:s})}))}catch(e){let status=document.querySelector('#testStatus');status.textContent=e.message;status.className='status bad'}}'''
PAGE = PAGE.replace('</script></body></html>', _auto_replace_clear_js + '</script></body></html>', 1)

_probe_marker = "function options(pool){"
_probe_js = r'''function stampProbe(value){if(!value)return '尚无记录';let d=new Date(value);return isNaN(d.getTime())?value:d.toLocaleString()}function renderProbeReport(data){probeData=data||{};clearTimeout(probePoll);let grid=document.querySelector('#probeGrid');if(!grid)return;let running=probeData.running||{};grid.innerHTML=poolNames.map(function(pool){let item=(probeData.pools||{})[pool]||{},busy=Boolean(running.running&&running.pool===pool),latest=item.tested_at?'最近专项复测：'+stampProbe(item.tested_at):'尚无专项复测',result=item.stable_count?'连续三次通过 '+item.stable_count+'/'+item.candidate_count+' 个候选 · 中位 '+item.median_delay+' ms · 最大抖动 '+item.max_jitter+' ms':(item.completed_count?'本次没有连续三次成功的节点':'等待业务专项复测'),error=running.error&&running.pool===pool?'<div class="status bad">复测失败：'+esc(running.error)+'</div>':'';return '<article class="card probe-card"><div class="card-head"><h3>'+esc(pool)+'</h3><span class="count">'+(item.candidate_count||0)+'/5</span></div><div class="probe-target">'+esc(item.protocol||'HTTPS')+' · '+esc(item.target||'')+'</div><div class="probe-meta">发起位置：'+esc(item.location||'Z4Pro 经 Mihomo')+'<br>'+esc(latest)+'</div><div class="probe-result">'+esc(result)+'</div>'+error+'<div class="probe-actions"><button class="btn" '+(busy?'disabled':'')+' onclick="probePool(\''+pool+'\')">'+(busy?'正在复测 '+running.completed+'/'+running.total:'复测此业务池')+'</button></div></article>'}).join('');if(running.running)probePoll=setTimeout(loadProbeReport,1000)}async function loadProbeReport(){try{renderProbeReport(await api('/api/probes'))}catch(e){let grid=document.querySelector('#probeGrid');if(grid)grid.innerHTML='<div class="status bad">业务探针报告读取失败：'+esc(e.message)+'</div>'}}async function probePool(pool){try{let active=activePools[pool]||[];renderProbeReport({pools:probeData.pools||{},running:{running:true,pool:pool,total:active.length,completed:0}});renderProbeReport({pools:probeData.pools||{},running:await api('/api/pool-probe',{method:'POST',body:JSON.stringify({pool:pool})})})}catch(e){let grid=document.querySelector('#probeGrid');if(grid)grid.insertAdjacentHTML('afterbegin','<div class="status bad">无法开始专项复测：'+esc(e.message)+'</div>')}}'''
if _probe_marker not in PAGE:
    raise RuntimeError("probe template marker missing")
PAGE = PAGE.replace(_probe_marker, _probe_js + _probe_marker, 1)

PAGE = PAGE.replace(
    "</main><script>",
    '''<dialog id="poolEditor" class="pool-editor"><form method="dialog"><div class="editor-head"><h2 id="poolEditorTitle">编辑候选池</h2><button class="icon-btn" value="cancel" aria-label="关闭" title="关闭">&times;</button></div><p class="muted">切换为自动测速时，会按该业务连续三次测速的稳定性、延迟和抖动重排节点，再校验并重启 Mihomo。</p><label class="editor-label" for="poolMode">测速方式</label><select id="poolMode"><option value="select">手动选择</option><option value="url-test">自动测速（url-test）</option><option value="fallback">故障切换（fallback）</option></select><div id="poolEditorStatus" class="status" role="status" aria-live="polite"></div><div class="editor-actions"><button class="btn" value="cancel">取消</button><button id="poolEditorSave" class="btn primary" type="button" onclick="savePoolMode()">保存并应用</button></div></form></dialog></main><script>''',
    1,
)
PAGE = PAGE.replace(
    "</style>",
    ".pool-card .card-head{gap:8px}.pool-title{display:flex;align-items:center;gap:7px;min-width:0}.pool-title h2{overflow-wrap:anywhere}.mode-pill{display:inline-block;padding:3px 6px;border-radius:5px;background:#2c2c2e;color:#aeaeb2;font-size:11px;white-space:nowrap}.pool-editor{width:min(420px,calc(100vw - 28px));border:1px solid #48484a;border-radius:10px;background:#1c1c1e;color:#f5f5f7;padding:0;box-shadow:0 18px 50px rgba(0,0,0,.55)}.pool-editor::backdrop{background:rgba(0,0,0,.58)}.pool-editor form{padding:18px}.editor-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.editor-head h2{margin:0;font-size:17px}.editor-label{display:block;margin:18px 0 7px;font-size:13px;color:#aeaeb2}.pool-editor select{width:100%;height:38px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:14px inherit}.pool-editor .status{min-height:18px;margin-top:12px}.pool-editor button:disabled,.pool-editor select:disabled{cursor:wait;opacity:.55}.editor-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}</style>",
    1,
)
_render_start = PAGE.find("function renderPools(){")
_render_end = PAGE.find("function add(p){", _render_start)
if _render_start < 0 or _render_end < 0:
    raise RuntimeError("candidate pool template marker missing")
_pool_editor_js = r'''function poolModeLabel(mode){return ({select:'手动选择',fallback:'故障切换','url-test':'自动测速'})[mode]||'故障切换'}let editingPool=null,poolSaveInProgress=false;function setPoolEditorBusy(busy,message){let editor=document.querySelector('#poolEditor'),status=document.querySelector('#poolEditorStatus'),save=document.querySelector('#poolEditorSave');status.textContent=message||'';status.className='status'+(busy?'':'');save.disabled=busy;save.textContent=busy?'正在应用…':'保存并应用';editor.querySelectorAll('button[value="cancel"],select').forEach(function(control){control.disabled=busy})}function openPoolEditor(pool){if(poolSaveInProgress)return;editingPool=pool;document.querySelector('#poolEditorTitle').textContent='编辑 '+pool;document.querySelector('#poolMode').value=(poolSettings[pool]||{}).type||'fallback';setPoolEditorBusy(false,'');document.querySelector('#poolEditor').showModal()}async function savePoolMode(){if(!editingPool||poolSaveInProgress)return;let status=document.querySelector('#testStatus'),mode=document.querySelector('#poolMode').value,pool=editingPool,count=(pools[pool]||[]).length;poolSaveInProgress=true;setPoolEditorBusy(true,mode==='url-test'?'正在对 '+count+' 个候选连续测速 3 次，请勿重复点击…':'正在校验并应用设置，请勿重复点击…');try{status.textContent='正在校验、测速并应用 '+pool+' 的测速方式…';status.className='status';let next=Object.assign({},poolSettings);next[pool]={type:mode};let result=await api('/api/pool-settings',{method:'POST',body:JSON.stringify({settings:next})});poolSettings=result.settings;activePools=result.pools;pools=result.pools;document.querySelector('#poolEditor').close();status.textContent=pool+' 已切换为'+poolModeLabel(mode)+(result.reordered&&result.reordered.length?'；已按连续三次测速的稳定性、延迟和抖动重新排序':'')+'，配置校验和运行验证均通过';editingPool=null;renderPools();await loadStatus()}catch(e){status.textContent=e.message;status.className='status bad';setPoolEditorBusy(false,e.message)}finally{poolSaveInProgress=false;if(!document.querySelector('#poolEditor').open)setPoolEditorBusy(false,'')}}'''
_render_pools_js = r'''function derivedExitCard(name,exit){let rows=(exit.nodes||[]).map(function(node){return '<div class="node"><div class="node-name">'+esc(node)+(metric(node)?'<span class="delay">'+metric(node)+'</span>':'')+'</div></div>'}).join('');return '<article class="card pool-card"><div class="card-head"><div class="pool-title"><h2>'+esc(exit.label||name)+'</h2><span class="mode-pill">派生只读</span></div><span class="count">'+(exit.nodes||[]).length+'/5</span></div><div class="muted" style="padding:0 14px 12px">'+esc(exit.description||'由业务候选池自动组成；不能单独编辑。')+'</div>'+rows+'</article>'}function renderPools(){let cards=poolNames.map(function(pool){let rows=pools[pool].map(function(name,i){return '<div class="node"><div class="node-name">'+esc(name)+(metric(name)?'<span class="delay">'+metric(name)+'</span>':'')+'</div><div class="node-tools"><button class="icon-btn" aria-label="上移" title="上移" onclick="move(\''+pool+'\','+i+',-1)">&#8593;</button><button class="icon-btn" aria-label="下移" title="下移" onclick="move(\''+pool+'\','+i+',1)">&#8595;</button><button class="icon-btn remove" aria-label="移除" title="移除" onclick="removeNode(\''+pool+'\','+i+')">&times;</button></div></div>'}).join('');let mode=(poolSettings[pool]||{}).type||'fallback';return '<article class="card pool-card"><div class="card-head"><div class="pool-title"><h2>'+esc(pool)+'</h2><span class="mode-pill">'+esc(poolModeLabel(mode))+'</span></div><div><span class="count">'+pools[pool].length+'/5</span><button class="icon-btn" aria-label="编辑" title="编辑" onclick="openPoolEditor(\''+pool+'\')">&#9998;</button></div></div><div class="add-node"><select id="sel-'+pool+'">'+options(pool)+'</select><button class="btn" onclick="add(\''+pool+'\')">加入</button></div>'+rows+'</article>'});Object.keys(derivedExits).forEach(function(name){cards.push(derivedExitCard(name,derivedExits[name]))});document.querySelector('#poolGrid').innerHTML=cards.join('')}'''
PAGE = PAGE[:_render_start] + _pool_editor_js + _render_pools_js + PAGE[_render_end:]
PAGE = PAGE.replace("grid.innerHTML=poolNames.map(function(pool){", "grid.innerHTML=poolNames.concat(['GitHub-Auto']).map(function(pool){")
PAGE = PAGE.replace("<h3>'+esc(pool)+'</h3>", "<h3>'+esc(pool==='GitHub-Auto'?'GitHub 专用自动出口':pool)+'</h3>")
PAGE = PAGE.replace("let active=activePools[pool]||[];renderProbeReport", "let active=pool==='GitHub-Auto'?((derivedExits[pool]||{}).nodes||[]):(activePools[pool]||[]);renderProbeReport")
PAGE = PAGE.replace("let all=[],pools={},activePools={},suggestion=null,delays={}", "let all=[],pools={},activePools={},derivedExits={},poolSettings={},suggestion=null,delays={}")
PAGE = PAGE.replace("pools=d.pools;if(d.tests", "pools=d.pools;poolSettings=d.settings||poolSettings;if(d.tests")
PAGE = PAGE.replace("all=d.nodes;activePools=d.pools;suggestion=", "all=d.nodes;activePools=d.pools;derivedExits=d.derived_exits||{};poolSettings=d.settings||{};suggestion=")
PAGE = PAGE.replace(
    "async function rollback(){try{pools=await api('/api/rollback',{method:'POST',body:'{}'});document.querySelector('#testStatus').textContent='已验证并恢复上一版候选池';renderPools()}catch(e){alert(e.message)}}",
    "async function rollback(){try{await api('/api/rollback',{method:'POST',body:'{}'});document.querySelector('#testStatus').textContent='已验证并恢复上一版候选池';catalogLoaded=false;await loadPools()}catch(e){alert(e.message)}}",
    1,
)
PAGE = PAGE.replace(
    '<div class="section-title"><h2>当前出口</h2></div><div id="runtimeGrid" class="grid"></div>',
    '<div id="directFallbackStatus" class="status"></div><div class="section-title"><h2>当前出口</h2></div><div id="runtimeGrid" class="grid"></div>',
    1,
)
_status_marker = "async function loadStatus(){let d=await api('/api/status');"
_status_replacement = r'''function renderDirectFallbacks(entries){let target=document.querySelector('#directFallbackStatus');if(!target)return;let rows=Object.entries(entries||{}),emergency=rows.filter(function(entry){return entry[1]&&entry[1].phase==='emergency'}),exhausted=rows.filter(function(entry){return entry[1]&&entry[1].phase==='exhausted'}),manual=rows.filter(function(entry){return entry[1]&&entry[1].active==='DIRECT'});if(emergency.length){target.textContent='应急节点已生效：'+emergency.map(function(entry){return entry[0]+' · '+(entry[1].emergency_node||'待确认')}).join('、');target.className='status bad';return}if(exhausted.length){target.textContent='常用候选异常，限量应急扫描未找到稳定节点：'+exhausted.map(function(entry){return entry[0]}).join('、');target.className='status bad';return}if(manual.length){target.textContent='人工 DIRECT 正在生效：'+manual.map(function(entry){return entry[0]}).join('、');target.className='status bad';return}target.textContent='所有自动出口均使用常用候选池；冷备节点不做周期测速';target.className='status'}async function loadStatus(){let d=await api('/api/status');renderDirectFallbacks(d.failsafes);'''
if _status_marker not in PAGE:
    raise RuntimeError("runtime status load marker missing")
PAGE = PAGE.replace(_status_marker, _status_replacement, 1)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status_code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        try:
            if (self.client_address[0] == "127.0.0.1"
                    and hmac.compare_digest(self.headers.get("X-Family-Gateway", ""), GATEWAY_SECRET_PATH.read_text().strip())):
                return True
        except OSError:
            pass
        if authenticated(self.headers.get("Authorization", "")):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Family subscription import"')
        self.end_headers()
        return False

    def do_GET(self):
        if not self.auth():
            return
        path = urlparse(self.path).path
        if path == "/api/state":
            tests = read_json(LAST_TESTS, {})
            self.reply(200, {"slots": [slot_state(s) for s in source_slots()], "pools": pools(),
                             "settings": pool_settings(), "derived_exits": derived_exits(), "tests": {"tested_at": tests.get("tested_at")},
                             "suggestions": suggestions()})
        elif path == "/api/nodes":
            self.reply(200, {"slots": [slot_state(s) for s in source_slots()], "nodes": nodes(), "pools": pools(),
                             "settings": pool_settings(), "derived_exits": derived_exits(), "tests": read_json(LAST_TESTS, {}),
                             "suggestions": suggestions()})
        elif path == "/api/test-status":
            self.reply(200, test_status())
        elif path == "/api/probes":
            self.reply(200, probe_report())
        elif path == "/api/status":
            self.reply(200, status())
        elif path == "/":
            body = PAGE.replace("__CSRF__", CSRF).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if not self.auth() or self.headers.get("X-CSRF") != CSRF:
            self.reply(403, {"error": "request rejected"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or "{}")
            path = urlparse(self.path).path
            if path == "/api/import": result = import_slot(body["slot"], body.get("url", ""))
            elif path == "/api/remove": result = clear_slot(body["slot"])
            elif path == "/api/replace-clear": result = start_replace_and_clear_slot(body["slot"])
            elif path == "/api/sources": result = add_source()
            elif path == "/api/source-remove": result = delete_source(body["slot"])
            elif path == "/api/pools": result = save_pools(body.get("pools", {}))
            elif path == "/api/pool-settings": result = save_pool_settings(body.get("settings", {}))
            elif path == "/api/retest-apply": result = start_retest_apply(body.get("pools", {}))
            elif path == "/api/rollback": result = rollback_pools()
            elif path == "/api/test-all": result = start_test_all()
            elif path == "/api/pool-probe": result = start_pool_probe(body.get("pool", ""))
            else: raise ValueError("not found")
            self.reply(200, result)
        except (ValueError, KeyError, OSError, yaml.YAMLError, subprocess.SubprocessError) as exc:
            self.reply(400, {"error": str(exc)})


def migrate():
    PROVIDERS.mkdir(parents=True, exist_ok=True)
    if not SOURCES.exists():
        atomic_json(SOURCES, DEFAULT_SOURCES)
    if not POOL_SETTINGS.exists():
        atomic_json(POOL_SETTINGS, pool_settings())
    for slot in source_slots():
        path = provider_path(slot)
        if path.exists():
            cleaned, count = clean_provider(path.read_bytes())
            path.write_bytes(cleaned)
            meta = slot_state(slot)
            if meta.get("imported"):
                meta["nodes"] = count
                atomic_json(PROVIDERS / f"{slot}.json", meta)
    selected = pools() if CANDIDATES.exists() else seed_pools()
    generate_config(selected)


if __name__ == "__main__":
    if "--apply-current" in sys.argv:
        selected = validate_pools(pools())
        settings = pool_settings()
        generate_config(selected, settings)
        atomic_json(CANDIDATES, selected)
        atomic_json(POOL_SETTINGS, settings)
        print("current candidate pools validated and applied")
    elif "--migrate" in sys.argv:
        migrate()
    else:
        PROVIDERS.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=monitor_loop, name="mihomo-runtime-monitor", daemon=True).start()
        ThreadingHTTPServer(("127.0.0.1", 18090), Handler).serve_forever()
