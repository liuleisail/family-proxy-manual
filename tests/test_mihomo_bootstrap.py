#!/usr/bin/env python3
"""Regression checks for first-import bootstrap and state preservation."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "family_mihomo_sub_import_bootstrap",
    ROOT / "runtime" / "family-mihomo-sub-import.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MihomoBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        providers = root / "providers"
        providers.mkdir()
        (providers / "sources.json").write_text(json.dumps(MODULE.DEFAULT_SOURCES))
        (providers / "primary.yaml").write_text("proxies: []\n")
        self.paths = {
            "PROVIDERS": providers,
            "SOURCES": providers / "sources.json",
            "CANDIDATES": providers / "candidates.json",
            "PREVIOUS": providers / "candidates.previous.json",
            "SUGGESTIONS": providers / "pool-suggestions.json",
            "MIHOMO_CONFIG": root / "config.yaml",
            "VERSIONS": root / "config-versions",
        }
        self.paths["MIHOMO_CONFIG"].write_text("proxies: []\n")
        self.patch_paths = patch.multiple(MODULE, **self.paths)
        self.patch_paths.start()
        self.addCleanup(self.patch_paths.stop)
        self.addCleanup(self.directory.cleanup)

    def apply_import(self, node_name):
        cleaned = f"proxies:\n  - name: {node_name}\n".encode()
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(MODULE.subprocess, "run", return_value=completed), \
             patch.object(MODULE, "generate_config"):
            return MODULE.apply_provider("primary", cleaned, 1)

    def test_first_import_creates_generic_bootstrap_pool_without_speed_test(self):
        self.apply_import("Edge Node")

        selected = json.loads(self.paths["CANDIDATES"].read_text())
        self.assertEqual(selected["Proxy"], ["[主力] Edge Node"])
        self.assertEqual(selected["其他-AI"], ["[主力] Edge Node"])
        self.assertEqual(selected["HK-视频"], [])
        self.assertEqual(
            MODULE.validate_pools(selected, allow_empty=True, allow_generic_proxy=True),
            selected,
        )

    def test_existing_candidate_state_is_retained_when_imported_node_still_exists(self):
        self.paths["PROVIDERS"].joinpath("primary.yaml").write_text(
            "proxies:\n  - name: Edge Node\n"
        )
        selected = {name: [] for name in MODULE.POOLS}
        selected["Proxy"] = ["[主力] Edge Node"]
        selected["其他-AI"] = ["[主力] Edge Node"]
        self.paths["CANDIDATES"].write_text(json.dumps(selected))

        self.apply_import("Edge Node")

        self.assertEqual(json.loads(self.paths["CANDIDATES"].read_text()), selected)

    def test_generated_config_routes_empty_business_pools_through_proxy_bootstrap(self):
        node = "[主力] Edge Node"
        selected = {name: [] for name in MODULE.POOLS}
        selected["Proxy"] = [node]
        base = {
            "proxies": [],
            "proxy-groups": [],
            "rules": ["MATCH,DIRECT"],
        }
        self.paths["MIHOMO_CONFIG"].write_text(MODULE.yaml.safe_dump(base, allow_unicode=True))
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(MODULE.subprocess, "run", return_value=completed), \
             patch.object(MODULE, "restart_mihomo"):
            MODULE.generate_config(selected)

        config = MODULE.yaml.safe_load(self.paths["MIHOMO_CONFIG"].read_text())
        groups = {item["name"]: item for item in config["proxy-groups"]}
        self.assertIn("Proxy-Auto", groups["HK-视频"]["proxies"])
        self.assertIn("Proxy-Auto", groups["TG-Auto"]["proxies"])
        self.assertEqual(groups["AI-Auto"]["proxies"], ["Proxy-Auto"])

    def test_container_installer_has_non_overwrite_guard_for_runtime_config(self):
        script = (ROOT / "scripts" / "install-mihomo-container.sh").read_text()
        self.assertIn('if [[ ! -s "$dir/config.yaml" ]]; then', script)
        self.assertIn("Preserving existing Mihomo config.yaml", script)

    def test_base_config_declares_all_named_rule_targets(self):
        config = MODULE.yaml.safe_load(
            (ROOT / "deploy" / "mihomo-config.base.yaml").read_text()
        )
        groups = {item["name"] for item in config["proxy-groups"]}
        targets = {rule.split(",", 2)[2] for rule in config["rules"]}
        self.assertTrue({"Apple", "Telegram"}.issubset(groups))
        builtins = {"DIRECT", "REJECT", "PASS", "Others", "Apple", "Telegram", "V2EX-Auto"}
        self.assertTrue(targets.difference(builtins).issubset(groups))

    def test_server_installer_creates_audit_log_for_systemd_namespace(self):
        script = (ROOT / "scripts" / "install-server.sh").read_text()
        self.assertIn("install -m 600 /dev/null /var/log/family-proxy-ui-audit.jsonl", script)

    def test_container_installer_precreates_cache_file(self):
        script = (ROOT / "scripts" / "install-mihomo-container.sh").read_text()
        self.assertIn('install -m 640 /dev/null "$dir/cache.db"', script)
        self.assertIn('cache.db exists but is not a regular file', script)


if __name__ == "__main__":
    unittest.main()
