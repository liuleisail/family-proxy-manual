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
    "TG": ("jp", "日本", "jpn", "sg", "新加坡", "sgp"),
    "Proxy": ("hk", "香港", "hkg"),
}
AI_REGIONAL_POOLS = ("JP-AI", "SG-AI", "US-AI")
HK_NODE = re.compile(r"(?:香港|hong[ -]?kong|(?<![a-z])hkg?(?![a-z]))", re.I)
SUGGESTION_SCHEMA = 2
CANDIDATES = PROVIDERS / "candidates.json"
PREVIOUS = PROVIDERS / "candidates.previous.json"
LAST_TESTS = PROVIDERS / "last-tests.json"
CONFIRM_TESTS = PROVIDERS / "last-confirm-tests.json"
SUGGESTIONS = PROVIDERS / "pool-suggestions.json"
SOURCES = PROVIDERS / "sources.json"
RUNTIME_STATE = PROVIDERS / "runtime-state.json"
RUNTIME_EVENTS = PROVIDERS / "runtime-events.json"
VERSIONS = BASE / "family-mihomo-fallback/config-versions"
MAX_BYTES = 12 * 1024 * 1024
CSRF = secrets.token_urlsafe(32)
NOISE = re.compile(
    r"traffic|expire|reset|流量|到期|剩余|套餐|重置|官网|客服|公告|通知|"
    r"订阅地址|使用说明|请勿|禁止|有效期|过期时间|官方群|加入群|距离下次",
    re.I,
)
OPENER = build_opener(ProxyHandler({}))
MONITORED_GROUPS = ("HK-视频", "JP-AI", "SG-AI", "US-AI", "其他-AI", "TG-Auto", "Proxy-Auto")
TEST_JOB_LOCK = threading.Lock()
TEST_STATE_LOCK = threading.Lock()
TEST_STATE = {
    "running": False,
    "total": 0,
    "completed": 0,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "action": None,
    "proposal_ready": False,
    "applied": False,
}


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
    document = yaml.safe_load(data) or {}
    proxies = document.get("proxies")
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


def suggestions():
    data = read_json(SUGGESTIONS, {})
    if data.get("schema") != SUGGESTION_SCHEMA:
        return {
            "pools": {name: [] for name in POOLS},
            "generated_at": None,
            "ready": False,
            "reason": "AI 候选地域规则已更新，请重新进行全量稳定性测速",
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
    """Keep stable primary nodes first, then fill with stable backups."""
    chosen = []
    for position, source in enumerate(source_slots()):
        limit = 3 if position == 0 else 1
        chosen.extend(sorted((entry for entry in entries if entry["source"] == source),
                             key=lambda entry: (entry["score"], entry["name"]))[:limit])
    for entry in sorted(entries, key=lambda entry: (source_rank(entry["name"]), entry["score"], entry["name"])):
        if entry not in chosen and len(chosen) < 5:
            chosen.append(entry)
    return [entry["name"] for entry in sorted(chosen, key=lambda entry: (source_rank(entry["name"]), entry["score"], entry["name"]))[:5]]


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


def source_rank(name):
    return next((rank for rank, source in enumerate(sources()) if name.startswith(source["prefix"])), 99)


def fallback(name, selected, url, interval, expected_status=None):
    if not selected:
        raise ValueError(f"{name} 没有候选节点，拒绝生成可能直连泄漏的配置")
    group = {
        "name": name,
        "type": "fallback",
        "proxies": selected,
        "url": url,
        "interval": interval,
        "lazy": True,
        "timeout": 5000,
        "max-failed-times": 2,
    }
    if expected_status:
        group["expected-status"] = expected_status
    return group


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


def generate_config(selected=None):
    selected = selected or pools()
    selected = {name: list(selected.get(name, [])) for name in POOLS}
    config = yaml.safe_load(MIHOMO_CONFIG.read_text())
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
    hk, jp, sg, us, other_ai, tg, proxy = (selected[name] for name in POOLS)
    ai_groups = ["JP-AI", "SG-AI", "US-AI"] + (["其他-AI"] if other_ai else [])
    ai_nodes = jp + sg + us + other_ai
    groups = [
        {"name": "Apple", "type": "select", "proxies": ["DIRECT", "Proxy-Auto"] + proxy},
        {"name": "MicroSoft", "type": "select", "proxies": ["DIRECT", "Proxy-Auto"] + proxy},
        fallback("HK-视频", hk, "https://www.youtube.com/generate_204", 300, "204"),
        fallback("JP-AI", jp, "https://chatgpt.com/cdn-cgi/trace", 180, "200"),
        fallback("SG-AI", sg, "https://chatgpt.com/cdn-cgi/trace", 180, "200"),
        fallback("US-AI", us, "https://chatgpt.com/cdn-cgi/trace", 180, "200"),
        fallback("TG-Auto", tg, "https://core.telegram.org", 300),
        fallback("Proxy-Auto", proxy, "https://www.gstatic.com/generate_204", 300, "204"),
        fallback("DNS-Resolve", proxy, "https://dns.google/dns-query", 300),
        fallback("AI-Auto", ai_groups, "https://chatgpt.com/cdn-cgi/trace", 180, "200"),
        {"name": "AI", "type": "select", "proxies": ["AI-Auto"] + ai_groups + ai_nodes},
        {"name": "Gemini", "type": "select", "proxies": ["AI-Auto", "SG-AI", "JP-AI", "US-AI"] + (["其他-AI"] if other_ai else []) + sg + jp + us + other_ai},
        {"name": "Telegram", "type": "select", "proxies": ["TG-Auto"] + tg},
        {"name": "TikTok", "type": "select", "proxies": ["Proxy-Auto"] + proxy},
        {"name": "Youtube", "type": "select", "proxies": ["HK-视频"] + hk},
        {"name": "Google", "type": "select", "proxies": ["Proxy-Auto"] + proxy},
        {"name": "Others", "type": "select", "proxies": ["Proxy-Auto"] + proxy},
    ]
    if other_ai:
        groups.insert(6, fallback("其他-AI", other_ai, "https://chatgpt.com/cdn-cgi/trace", 180, "200"))
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
        with OPENER.open(Request(url, headers={"User-Agent": "Mihomo-Direct-Subscription"}), timeout=75) as response:
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
        cleaned[pool] = sorted(entries, key=source_rank)
    return cleaned


def save_pools(value):
    cleaned = validate_pools(value)
    previous = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    previous_config = MIHOMO_CONFIG.read_bytes()
    generate_config(cleaned)
    try:
        PREVIOUS.write_bytes(previous)
        atomic_json(CANDIDATES, cleaned)
    except OSError:
        MIHOMO_CONFIG.write_bytes(previous_config)
        os.chmod(MIHOMO_CONFIG, 0o640)
        restart_mihomo()
        raise
    return cleaned


def rollback_pools():
    if not PREVIOUS.exists():
        raise ValueError("没有可回退的上一版候选池")
    current = CANDIDATES.read_bytes() if CANDIDATES.exists() else b"{}"
    restored_bytes = PREVIOUS.read_bytes()
    restored = validate_pools(json.loads(restored_bytes))
    generate_config(restored)
    CANDIDATES.write_bytes(restored_bytes)
    PREVIOUS.write_bytes(current)
    return restored


def proxy_api(path, method="GET", data=None):
    body = json.dumps(data).encode() if data is not None else None
    request = Request("http://127.0.0.1:9091" + path, data=body, method=method,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=8) as response:
        return json.loads(response.read() or b"{}")


def test_one(name):
    delays = []
    for _ in range(3):
        query = urlencode({"url": "https://www.gstatic.com/generate_204", "timeout": 5000})
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
                           "action": "full-test", "proposal_ready": False, "applied": False})

    def update_progress(completed, total):
        with TEST_STATE_LOCK:
            TEST_STATE.update({"completed": completed, "total": total})

    def run():
        try:
            proposal = build_suggestions(test_all(update_progress))
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


def start_retest_apply(value):
    if not suggestions()["ready"]:
        raise ValueError("请先完成全量稳定性测速并生成完整建议")
    selected = validate_pools(value)
    if not TEST_JOB_LOCK.acquire(blocking=False):
        return {"started": False, **test_status()}
    names = list(dict.fromkeys(name for entries in selected.values() for name in entries))
    now = datetime.now().astimezone().isoformat()
    with TEST_STATE_LOCK:
        TEST_STATE.update({"running": True, "total": len(names), "completed": 0,
                           "started_at": now, "finished_at": None, "error": None,
                           "action": "retest-apply", "proposal_ready": True, "applied": False})

    def update_progress(completed, total):
        with TEST_STATE_LOCK:
            TEST_STATE.update({"completed": completed, "total": total})

    def run():
        try:
            results = test_nodes(names, update_progress, CONFIRM_TESTS)
            indexed = node_index()
            result_by_name = {item["name"]: item for item in results}
            confirmed = {}
            for pool, entries in selected.items():
                stable = []
                for name in entries:
                    result = result_by_name.get(name)
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


def monitor_once():
    previous = read_json(RUNTIME_STATE, {})
    events = read_json(RUNTIME_EVENTS, [])
    current = {}
    now = datetime.now().astimezone().isoformat()
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
                           "reason": "健康检查触发 fallback"})
    atomic_json(RUNTIME_STATE, current)
    atomic_json(RUNTIME_EVENTS, events[-100:])


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
    for group in ("AI", "AI-Auto", "JP-AI", "SG-AI", "US-AI", "其他-AI", "Youtube", "HK-视频", "Telegram", "TG-Auto", "Google", "Others", "Proxy-Auto"):
        try:
            data = proxy_api("/proxies/" + quote(group, safe=""))
            leaf = resolve_leaf(group)
            latest = next((event for event in reversed(events) if event.get("group") == group), None)
            result[group] = {"now": data.get("now"), "leaf": leaf, "source": source_label(leaf),
                             "type": data.get("type"), "history": data.get("history", [])[-3:],
                             "last_change": latest, "since": (runtime.get(group) or {}).get("since")}
        except Exception:
            result[group] = {"now": None, "leaf": None, "source": "不可用", "type": "unavailable",
                             "history": [], "last_change": None, "since": None}
    return {"groups": result, "events": events[-20:], "versions": [path.name for path in sorted(VERSIONS.glob("*.yaml"), reverse=True)[:5]]}


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
    '<a href="/">设备</a><a href="/dns/">DNS</a><a class="active" href="/airport/">机场与候选池</a><a href="/rules">规则</a>',
    1,
)
_slot_card_start = PAGE.find("function slotCard(s){")
_slot_card_end = PAGE.find("async function load(){", _slot_card_start)
if _slot_card_start < 0 or _slot_card_end < 0:
    raise RuntimeError("subscription card template marker missing")
_slot_card_js = r'''function slotCard(s){let imported=s.imported;let removeButton=s.removable?'<button class="btn danger" onclick="deleteSource(\''+s.slot+'\')">删除机场</button>':'';return '<article class="card"><div class="card-head"><h2>'+esc(s.label)+'</h2><div class="source-state '+(imported?'':'empty')+'">'+(imported?'已导入 '+s.nodes+' 个有效节点':'尚未导入')+'</div><div class="muted">'+(imported?esc(s.updated_at):'导入后可在候选池中选择节点')+'</div></div><div class="form"><input id="url-'+s.slot+'" type="url" autocomplete="off" placeholder="HTTPS 原生 Clash/Mihomo 订阅链接"><div class="actions"><button class="btn primary" onclick="imp(\''+s.slot+'\')">直连导入或替换</button><button class="btn danger" onclick="dropSlot(\''+s.slot+'\')">清空节点</button>'+removeButton+'</div><div id="msg-'+s.slot+'" class="status"></div></div></article>'}'''
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
PAGE = PAGE.replace("let all=[],pools={},delays={};", "let all=[],pools={},activePools={},suggestion=null,delays={},catalogLoaded=false,testPoll=null;")
PAGE = PAGE.replace("poolNames=['HK-视频','JP-AI','SG-AI','US-AI','TG','Proxy']", "poolNames=['HK-视频','JP-AI','SG-AI','US-AI','其他-AI','TG','Proxy']")
PAGE = PAGE.replace("async function load(){let d=await api('/api/state');", "async function load(){let d=await api('/api/nodes');")
PAGE = PAGE.replace("renderPools()}function options", "catalogLoaded=true;renderPools()}async function loadSummary(){let d=await api('/api/state');document.querySelector('#slots').innerHTML=d.slots.map(slotCard).join('');pools=d.pools;if(d.tests&&d.tests.tested_at)document.querySelector('#testStatus').textContent='上次稳定性测速：'+d.tests.tested_at}async function loadPools(){if(catalogLoaded)return;try{await load();await refreshTestStatus()}catch(e){pageError(e)}}function pageError(e){let box=document.querySelector('#pageStatus');if(!box){box=document.createElement('div');box.id='pageStatus';box.className='status bad';document.querySelector('.intro').append(box)}box.innerHTML='页面数据加载失败。<button class=\"btn\" onclick=\"loadSummary().catch(pageError)\">重试</button>';console.error(e)}function options")
PAGE = PAGE.replace("}load()", "}loadSummary().catch(pageError)")
PAGE = PAGE.replace("async function imp(s){", "async function addSource(){try{await api('/api/sources',{method:'POST',body:'{}'});await loadSummary()}catch(e){pageError(e)}}async function deleteSource(s){if(!confirm('删除机场会清空该来源的节点；若节点正在被当前候选池使用，操作将被拒绝。确定删除？'))return;try{await api('/api/source-remove',{method:'POST',body:JSON.stringify({slot:s})});await loadSummary()}catch(e){alert(e.message)}}async function imp(s){")
PAGE = PAGE.replace("all=d.nodes;pools=d.pools;", "all=d.nodes;activePools=d.pools;suggestion=d.suggestions||null;pools=suggestion&&suggestion.generated_at?suggestion.pools:activePools;")
PAGE = PAGE.replace('<button class="btn primary" onclick="testAll()">稳定性测速</button><button class="btn" onclick="save()">校验并应用</button>', '<button class="btn primary" onclick="testAll()">全量稳定性测速</button><button class="btn" onclick="confirmApply()">复测并生效</button>')
PAGE = PAGE.replace('<div class="section-title"><h2>业务候选池</h2></div>', '<div class="section-title"><h2>待生效候选池</h2><span class="muted">测速建议不会自动替换当前出口</span></div>')
_old_speed_test = "async function testAll(){let status=document.querySelector('#testStatus');try{status.textContent='正在对每个节点连续测试三次，本次操作完成后即停止…';status.className='status';let d=await api('/api/test-all',{method:'POST',body:'{}'});delays=Object.fromEntries(d.results.map(function(x){return [x.name,x]}));status.textContent='测速完成：'+d.results.filter(function(x){return x.ok}).length+'/'+d.results.length+' 稳定可用';renderPools()}catch(e){status.textContent=e.message;status.className='status bad'}}"
_new_speed_test = "function showTestStatus(d){let status=document.querySelector('#testStatus');clearTimeout(testPoll);if(d.running){status.textContent=(d.action==='retest-apply'?'候选池复测中：':'全量测速中：')+d.completed+'/'+d.total+' 个节点已完成；可继续浏览页面';status.className='status';testPoll=setTimeout(refreshTestStatus,1000);return}if(d.error){status.textContent=(d.action==='retest-apply'?'复测未生效：':'测速未完成：')+d.error;status.className='status bad';return}if(d.finished_at&&d.action==='retest-apply'){status.textContent=d.applied?'复测、配置校验和运行验证均通过，候选池已生效':'复测完成，但未生效';status.className=d.applied?'status':'status bad';catalogLoaded=false;loadPools();return}if(d.finished_at&&d.action==='full-test'){status.textContent=d.suggestions&&d.suggestions.ready?'全量测速完成，已生成待生效建议；确认后点击“复测并生效”':'测速完成，但有业务池没有连续三次成功的节点';status.className=d.suggestions&&d.suggestions.ready?'status':'status bad';catalogLoaded=false;loadPools();return}if(d.suggestions&&d.suggestions.ready){status.textContent='已生成待生效建议；当前出口保持不变，点击“复测并生效”后才会更新';status.className='status';return}if(d.last_tested_at){status.textContent='上次稳定性测速：'+d.last_tested_at}}async function refreshTestStatus(){try{showTestStatus(await api('/api/test-status'))}catch(e){let status=document.querySelector('#testStatus');status.textContent='测速状态读取失败：'+e.message;status.className='status bad'}}async function testAll(){try{showTestStatus(await api('/api/test-all',{method:'POST',body:'{}'}))}catch(e){let status=document.querySelector('#testStatus');status.textContent=e.message;status.className='status bad'}}async function confirmApply(){let status=document.querySelector('#testStatus');try{showTestStatus(await api('/api/retest-apply',{method:'POST',body:JSON.stringify({pools:pools})}))}catch(e){status.textContent=e.message;status.className='status bad'}}"
if _old_speed_test not in PAGE:
    raise RuntimeError("speed test template marker missing")
PAGE = PAGE.replace(_old_speed_test, _new_speed_test, 1)


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
                             "tests": {"tested_at": tests.get("tested_at")}, "suggestions": suggestions()})
        elif path == "/api/nodes":
            self.reply(200, {"slots": [slot_state(s) for s in source_slots()], "nodes": nodes(), "pools": pools(),
                             "tests": read_json(LAST_TESTS, {}), "suggestions": suggestions()})
        elif path == "/api/test-status":
            self.reply(200, test_status())
        elif path == "/api/status":
            self.reply(200, status())
        elif path == "/":
            body = PAGE.replace("__CSRF__", CSRF).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
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
            elif path == "/api/sources": result = add_source()
            elif path == "/api/source-remove": result = delete_source(body["slot"])
            elif path == "/api/pools": result = save_pools(body.get("pools", {}))
            elif path == "/api/retest-apply": result = start_retest_apply(body.get("pools", {}))
            elif path == "/api/rollback": result = rollback_pools()
            elif path == "/api/test-all": result = start_test_all()
            else: raise ValueError("not found")
            self.reply(200, result)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
            self.reply(400, {"error": str(exc)})


def migrate():
    PROVIDERS.mkdir(parents=True, exist_ok=True)
    if not SOURCES.exists():
        atomic_json(SOURCES, DEFAULT_SOURCES)
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
        generate_config(selected)
        atomic_json(CANDIDATES, selected)
        print("current candidate pools validated and applied")
    elif "--migrate" in sys.argv:
        migrate()
    else:
        PROVIDERS.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=monitor_loop, name="mihomo-runtime-monitor", daemon=True).start()
        ThreadingHTTPServer(("127.0.0.1", 18090), Handler).serve_forever()
