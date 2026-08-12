#!/usr/bin/env python3
"""Regression checks for the LAN-only first-run setup flow."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
os.environ["FAMILY_LAN_CIDR"] = "192.168.10.0/24"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATEWAY = load_module("family_proxy_gateway_setup", ROOT / "runtime" / "family-proxy-gateway.py")
PREPARE = load_module("family_proxy_prepare_config", ROOT / "scripts" / "prepare-config.py")
UI_SOURCE = (ROOT / "runtime" / "family-proxy-ui.py").read_text(encoding="utf-8")
DASHBOARD_SOURCE = (ROOT / "runtime" / "mosdns" / "dashboard.html").read_text(encoding="utf-8")


class FirstRunSetupTests(unittest.TestCase):
    def test_health_contract_uses_unified_gated_probe(self):
        self.assertEqual(GATEWAY.HEALTH_PORT, 18088)
        self.assertEqual(GATEWAY.HEALTH_BACKEND_PATH, "/api/health/gated")
        self.assertEqual(GATEWAY.LEGACY_HEALTH_PORT, 18087)

    def test_ui_health_contract_contains_hysteresis_and_build_identity(self):
        self.assertIn('BUILD_VERSION = "0.11.9"', UI_SOURCE)
        self.assertIn('BUILD_INFO_PATH = Path("/opt/family-proxy-ui/build-info.json")', UI_SOURCE)
        self.assertIn('if HEALTH_GATE["successes"] >= 2:', UI_SOURCE)
        self.assertIn('if HEALTH_GATE["failures"] >= 2:', UI_SOURCE)
        self.assertIn('HEALTH_GATE = {"ready": False, "failures": 0, "successes": 0}', UI_SOURCE)
        self.assertIn('path in {"/api/health", "/api/health/gated"}', UI_SOURCE)

    def test_ui_deploy_installs_runtime_helpers(self):
        script = (ROOT / "scripts" / "deploy-family-proxy-ui").read_text(encoding="utf-8")
        self.assertIn("apply-runtime-mode", script)
        self.assertIn("family-mihomo-tproxy-auto", script)
        self.assertIn("refresh-mihomo-geodata.py", script)
        self.assertIn('install -m 644 "$SOURCE_DIR/VERSION" "$TARGET_DIR/VERSION"', script)

    def test_z4pro_sync_uses_content_checksums_without_delete(self):
        script = (ROOT / "scripts" / "sync-z4pro-source").read_text(encoding="utf-8")
        self.assertIn("rsync -azc", script)
        self.assertIn("runtime/family-proxy-gateway.py", script)
        self.assertIn("mktemp -d /tmp/family-proxy-source", script)
        self.assertIn('ssh "$TARGET" sudo rsync', script)
        self.assertNotIn("--delete", script)

    def test_mosdns_dashboard_keeps_upstreams_line_based_and_race_discoverable(self):
        self.assertIn('data-race-group="domestic"', DASHBOARD_SOURCE)
        self.assertIn('data-race-group="foreign"', DASHBOARD_SOURCE)
        self.assertIn("function raceItems(group)", DASHBOARD_SOURCE)
        self.assertIn("function upstreamLine(item)", DASHBOARD_SOURCE)
        self.assertIn('class="race-popover" data-race-panel="domestic"', DASHBOARD_SOURCE)
        self.assertIn('class="race-panel-row ${index === 0 ? \'best\' : \'\'}"', DASHBOARD_SOURCE)
        self.assertIn('胜率 ${winRate.toFixed(1)}%', DASHBOARD_SOURCE)
        self.assertIn('P95 ${ms(item.p95_ms)} · P99 ${ms(item.p99_ms)}', DASHBOARD_SOURCE)
        self.assertNotIn("上游${index ? ` ${index + 1}` : ''}", DASHBOARD_SOURCE)
        self.assertNotIn("${label} ${index + 1}", DASHBOARD_SOURCE)
        self.assertNotIn("names.join('、')", DASHBOARD_SOURCE)
        self.assertNotIn("values.map(upstreamLabel).join('、')", DASHBOARD_SOURCE)

    def test_gateway_keeps_http_handler_lifecycle_setup_method(self):
        self.assertIs(GATEWAY.Handler.setup, BaseHTTPRequestHandler.setup)

    def test_legacy_entry_uses_the_devices_layout(self):
        self.assertEqual(GATEWAY.layout_page_for_path("/"), "devices")
        self.assertEqual(GATEWAY.layout_page_for_path("/legacy"), "devices")

    def test_layout_settings_button_uses_inline_icon(self):
        html = '<html><head></head><body><header><div class="topbar-inner"><nav></nav></div></header></body></html>'
        rendered = GATEWAY.inject_page_layout(html, "devices")
        self.assertIn('class="family-layout-settings"', rendered)
        self.assertIn("<svg ", rendered)
        self.assertNotIn("⚙", rendered)

    def test_legacy_airport_navigation_keeps_maintenance_entry(self):
        html = '<header><nav class="nav"><a href="/">设备</a><a class="active" href="/airport/">机场与候选池</a></nav></header>'
        rendered = GATEWAY.inject_legacy_navigation(html, "airport")
        self.assertIn('<a class="active" href="/airport/">机场与候选池</a>', rendered)
        self.assertIn('<a href="/mihomo-maintenance">维护</a>', rendered)
        self.assertEqual(rendered.count('<nav class="nav">'), 1)

    def form(self, **overrides):
        values = {
            "token": ["setup-token"],
            "router_mode": ["auto"],
            "router_host": ["192.168.10.1"],
            "router_user": ["family_proxy"],
            "router_password": ["router-secret"],
            "ui_username": ["admin"],
            "ui_password": ["a-long-ui-password"],
            "ui_password_confirm": ["a-long-ui-password"],
            "dns_username": ["dns-user"],
            "dns_password": ["dns-secret"],
            "mosdns_api_url": ["http://127.0.0.1:9099"],
            "geodata_proxy": ["http://127.0.0.1:7890"],
            "router_cn_auto_sync": ["on"],
            "geodata_auto_update": ["on"],
        }
        values.update({key: [value] for key, value in overrides.items()})
        return values

    def test_setup_updates_hash_password_and_encodes_dns_auth(self):
        with patch.object(GATEWAY, "probe_routeros"):
            updates = GATEWAY.setup_updates(self.form())
        self.assertNotIn("UI_PASSWORD", updates)
        self.assertEqual(updates["ROUTER_PASSWORD"], "router-secret")
        self.assertEqual(updates["DNS_UPSTREAM_AUTH_B64"], "ZG5zLXVzZXI6ZG5zLXNlY3JldA==")
        self.assertEqual(len(updates["UI_PASSWORD_SALT"]), 32)
        self.assertEqual(len(updates["UI_PASSWORD_HASH"]), 64)
        self.assertEqual(updates["SETUP_PENDING"], "false")

    def test_auto_mode_without_routeros_credentials_resolves_standalone(self):
        updates = GATEWAY.setup_updates(self.form(router_user="", router_password=""))
        self.assertEqual(updates["ROUTER_MODE"], "standalone")
        self.assertEqual(updates["ROUTER_HOST"], "")
        self.assertEqual(updates["ROUTER_CN_AUTO_SYNC"], "false")

    def test_explicit_standalone_mode_does_not_probe_routeros(self):
        with patch.object(GATEWAY, "probe_routeros") as probe:
            updates = GATEWAY.setup_updates(self.form(router_mode="standalone", router_user="", router_password=""))
        probe.assert_not_called()
        self.assertEqual(updates["ROUTER_MODE"], "standalone")

    def test_auto_mode_requires_all_routeros_credentials_once_started(self):
        with self.assertRaisesRegex(ValueError, "必须同时填写"):
            GATEWAY.setup_updates(self.form(router_user="family_proxy", router_password=""))

    def test_setup_rejects_weak_or_inconsistent_credentials(self):
        with patch.object(GATEWAY, "probe_routeros"):
            with self.assertRaisesRegex(ValueError, "至少需要 12"):
                GATEWAY.setup_updates(self.form(ui_password="short", ui_password_confirm="short"))
            with self.assertRaisesRegex(ValueError, "不一致"):
                GATEWAY.setup_updates(self.form(ui_password_confirm="different-password"))
            with self.assertRaisesRegex(ValueError, "服务地址"):
                GATEWAY.setup_updates(self.form(mosdns_api_url="not-a-url"))

    def test_merge_env_removes_plaintext_password_and_preserves_other_values(self):
        source = "# keep this\nUI_USERNAME=setup\nUI_PASSWORD=temporary\nOTHER=value\n"
        merged = GATEWAY.merge_env_text(
            source,
            {"UI_USERNAME": "admin", "UI_PASSWORD_HASH": "hash"},
            remove=("UI_PASSWORD",),
        )
        self.assertIn("# keep this", merged)
        self.assertIn("OTHER=value", merged)
        self.assertIn("UI_USERNAME=admin", merged)
        self.assertIn("UI_PASSWORD_HASH=hash", merged)
        self.assertNotIn("UI_PASSWORD=", merged)

    def test_setup_token_is_one_time_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "setup-state.json"
            state_path.write_text(json.dumps({"pending": True, "token": "setup-token"}))
            with patch.object(GATEWAY, "SETUP_STATE_PATH", state_path):
                self.assertTrue(GATEWAY.setup_pending())
                self.assertTrue(GATEWAY.setup_token_valid("setup-token"))
                self.assertFalse(GATEWAY.setup_token_valid("wrong-token"))
                GATEWAY.write_setup_state({"pending": False, "completed_at": 1, "version": 1})
                self.assertFalse(GATEWAY.setup_pending())
                self.assertFalse(GATEWAY.setup_token_valid("setup-token"))

    def test_prepare_config_allows_router_credentials_during_pending_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "router.env"
            path.write_text(
                "\n".join([
                    "FAMILY_LAN_CIDR=192.168.10.0/24",
                    "FAMILY_LAN_PREFIX=192.168.10.",
                    "FAMILY_PROXY_IP=192.168.10.10",
                    "FAMILY_ROUTER_IP=192.168.10.1",
                    "FAMILY_DOCKER_ROOT=/var/lib/family-proxy/docker",
                    "ROUTER_MODE=auto",
                    "ROUTER_HOST=192.168.10.1",
                    "ROUTER_USER=setup",
                    "ROUTER_PASSWORD=",
                    "UI_USERNAME=setup",
                    "UI_PASSWORD=temporary-bootstrap-password",
                    "SETUP_PENDING=true",
                ]) + "\n"
            )
            with patch.object(sys, "argv", ["prepare-config.py", str(path)]):
                PREPARE.main()
            content = path.read_text()
            self.assertNotIn("UI_PASSWORD=", content)
            self.assertIn("UI_PASSWORD_HASH=", content)

    def test_prepare_config_rejects_unresolved_auto_mode_after_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "router.env"
            path.write_text(
                "\n".join([
                    "FAMILY_LAN_CIDR=192.168.10.0/24",
                    "FAMILY_LAN_PREFIX=192.168.10.",
                    "FAMILY_PROXY_IP=192.168.10.10",
                    "FAMILY_ROUTER_IP=192.168.10.1",
                    "FAMILY_DOCKER_ROOT=/var/lib/family-proxy/docker",
                    "ROUTER_MODE=auto",
                    "ROUTER_HOST=192.168.10.1",
                    "ROUTER_USER=setup",
                    "ROUTER_PASSWORD=secret",
                    "UI_USERNAME=admin",
                    "UI_PASSWORD_SALT=00",
                    "UI_PASSWORD_HASH=00",
                    "SETUP_PENDING=false",
                ]) + "\n"
            )
            with patch.object(sys, "argv", ["prepare-config.py", str(path)]):
                with self.assertRaisesRegex(SystemExit, "must be resolved"):
                    PREPARE.main()


if __name__ == "__main__":
    unittest.main()
