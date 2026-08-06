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


class FirstRunSetupTests(unittest.TestCase):
    def test_gateway_keeps_http_handler_lifecycle_setup_method(self):
        self.assertIs(GATEWAY.Handler.setup, BaseHTTPRequestHandler.setup)

    def form(self, **overrides):
        values = {
            "token": ["setup-token"],
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
        updates = GATEWAY.setup_updates(self.form())
        self.assertNotIn("UI_PASSWORD", updates)
        self.assertEqual(updates["ROUTER_PASSWORD"], "router-secret")
        self.assertEqual(updates["DNS_UPSTREAM_AUTH_B64"], "ZG5zLXVzZXI6ZG5zLXNlY3JldA==")
        self.assertEqual(len(updates["UI_PASSWORD_SALT"]), 32)
        self.assertEqual(len(updates["UI_PASSWORD_HASH"]), 64)
        self.assertEqual(updates["SETUP_PENDING"], "false")

    def test_setup_rejects_weak_or_inconsistent_credentials(self):
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


if __name__ == "__main__":
    unittest.main()
