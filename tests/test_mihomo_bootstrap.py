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
            "POOL_SOURCE_SELECTION": providers / "pool-source-selection.json",
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
        self.assertEqual(selected["HK-视频"], ["[主力] Edge Node"])
        self.assertEqual(selected["Proxy"], ["[主力] Edge Node"])
        self.assertEqual(selected["其他-AI"], ["[主力] Edge Node"])
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

    def test_source_pool_candidates_prefer_recently_tested_source_nodes(self):
        records = [
            {"name": "[备用1] 美国慢", "raw": "美国慢", "source": "backup1"},
            {"name": "[备用1] 美国快", "raw": "美国快", "source": "backup1"},
            {"name": "[主力] 美国节点", "raw": "美国节点", "source": "primary"},
        ]
        tests = {"results": [
            {"name": "[备用1] 美国慢", "success": 3, "delay": 220, "jitter": 20},
            {"name": "[备用1] 美国快", "success": 3, "delay": 80, "jitter": 4},
        ]}
        with patch.object(MODULE, "nodes", return_value=records), \
             patch.object(MODULE, "source_slots", return_value=["primary", "backup1"]), \
             patch.object(MODULE, "read_json", return_value=tests):
            result = MODULE.source_pool_candidates("US-AI", "backup1")

        self.assertEqual(result, ["[备用1] 美国快", "[备用1] 美国慢"])

    def test_video_pool_accepts_mixed_regions_and_preserves_proxy_region_filter(self):
        nodes = [
            {"name": "[主力] 香港视频", "raw": "香港视频", "source": "primary"},
            {"name": "[主力] 日本视频", "raw": "日本视频", "source": "primary"},
            {"name": "[备用1] 美国视频", "raw": "美国视频", "source": "backup1"},
        ]
        with patch.object(MODULE, "nodes", return_value=nodes), \
             patch.object(MODULE, "source_slots", return_value=["primary", "backup1"]), \
             patch.object(MODULE, "read_json", return_value={"results": [
                 {"name": "[主力] 香港视频", "success": 3, "delay": 120, "jitter": 10},
                 {"name": "[主力] 日本视频", "success": 3, "delay": 90, "jitter": 30},
                 {"name": "[备用1] 美国视频", "success": 3, "delay": 80, "jitter": 5},
             ]}):
            result = MODULE.source_pool_candidates("HK-视频", "all")

        self.assertEqual(
            result,
            ["[备用1] 美国视频", "[主力] 日本视频", "[主力] 香港视频"],
        )
        self.assertTrue(MODULE.pool_matches("HK-视频", nodes[1]))
        self.assertFalse(MODULE.pool_matches("Proxy", nodes[1]))

    def test_video_suggestions_rank_mixed_candidates_by_latency_and_jitter(self):
        current = {name: [] for name in MODULE.POOLS}
        records = [
            {"name": "[主力] 日本视频", "raw": "日本视频", "source": "primary"},
            {"name": "[备用1] 美国视频", "raw": "美国视频", "source": "backup1"},
            {"name": "[备用1] 新加坡视频", "raw": "新加坡视频", "source": "backup1"},
        ]
        results = [
            {"name": "[主力] 日本视频", "pool": "HK-视频", "success": 3, "delay": 105, "jitter": 4},
            {"name": "[备用1] 美国视频", "pool": "HK-视频", "success": 3, "delay": 105, "jitter": 10},
            {"name": "[备用1] 新加坡视频", "pool": "HK-视频", "success": 3, "delay": 100, "jitter": 5},
        ]
        scopes = {pool: None for pool in MODULE.POOLS}
        scopes["HK-视频"] = "all"
        with patch.object(MODULE, "nodes", return_value=records):
            proposal = MODULE.build_suggestions(results, scopes, current)

        self.assertEqual(
            proposal["pools"]["HK-视频"],
            ["[备用1] 新加坡视频", "[主力] 日本视频", "[备用1] 美国视频"],
        )

    def test_video_scope_supports_location_filter_and_legacy_airport_string(self):
        self.paths["POOL_SOURCE_SELECTION"].write_text(json.dumps({
            "pools": {"HK-视频": "primary"},
        }))
        self.assertEqual(
            MODULE.source_selections()["HK-视频"],
            {"source": "primary", "location": "all"},
        )
        records = [
            {"name": "[主力] 香港视频", "raw": "香港视频", "source": "primary"},
            {"name": "[主力] 日本视频", "raw": "日本视频", "source": "primary"},
            {"name": "[备用1] 日本视频", "raw": "日本视频", "source": "backup1"},
        ]
        with patch.object(MODULE, "nodes", return_value=records), \
             patch.object(MODULE, "source_slots", return_value=["primary", "backup1"]):
            selected = MODULE.scoped_pool_nodes(
                "HK-视频", {"source": "all", "location": "jp"}
            )
            self.assertEqual(selected, ["[主力] 日本视频", "[备用1] 日本视频"])
            with self.assertRaisesRegex(ValueError, "机场或地点"):
                MODULE.validate_source_scoped_pools(
                    {"HK-视频": ["[主力] 香港视频"]},
                    {"HK-视频": {"source": "all", "location": "jp"}},
                )

    def test_source_scoped_suggestions_keep_unselected_pool_unchanged(self):
        current = {name: [] for name in MODULE.POOLS}
        current["HK-视频"] = ["[主力] 香港旧节点"]
        records = [
            {"name": "[备用1] 美国稳定", "raw": "美国稳定", "source": "backup1"},
            {"name": "[主力] 香港旧节点", "raw": "香港旧节点", "source": "primary"},
        ]
        results = [{"name": "[备用1] 美国稳定", "pool": "US-AI", "success": 3,
                    "delay": 80, "jitter": 4}]
        scopes = {pool: None for pool in MODULE.POOLS}
        scopes["US-AI"] = "backup1"
        with patch.object(MODULE, "nodes", return_value=records), \
             patch.object(MODULE, "pools", return_value=current):
            proposal = MODULE.build_suggestions(results, scopes, current)

        self.assertEqual(proposal["pools"]["US-AI"], ["[备用1] 美国稳定"])
        self.assertEqual(proposal["pools"]["HK-视频"], ["[主力] 香港旧节点"])
        self.assertEqual(proposal["source_selections"]["US-AI"], "backup1")
        self.assertIsNone(proposal["source_selections"]["HK-视频"])

    def test_airport_source_selector_is_exposed_in_legacy_pool_page(self):
        self.assertIn("/api/pool-source-scope", MODULE.PAGE)
        self.assertIn("锁定机场范围", MODULE.PAGE)
        self.assertIn("sourceOptions", MODULE.PAGE)
        self.assertIn("familyVideoLocations", MODULE.PAGE)
        self.assertIn("编辑 视频", MODULE.PAGE)

    def test_new_vue_airport_page_exposes_source_scope_and_pending_apply_flow(self):
        app = (ROOT / "frontend" / "src" / "App.vue").read_text(encoding="utf-8")
        self.assertIn("/api/pool-source-scope", app)
        self.assertIn("airportSourceSelections", app)
        self.assertIn("测速机场范围", app)
        self.assertIn("地点范围", app)
        self.assertIn("airportVideoLocations", app)
        self.assertIn("先全量测速，再复测并生效", app)
        self.assertIn("!suggestion.applied_at", app)

    def test_container_installer_has_non_overwrite_guard_for_runtime_config(self):
        script = (ROOT / "scripts" / "install-mihomo-container.sh").read_text()
        self.assertIn('if [[ ! -s "$dir/config.yaml" ]]; then', script)
        self.assertIn("Preserving existing Mihomo config.yaml", script)

    def test_base_config_declares_all_named_rule_targets(self):
        config = MODULE.yaml.safe_load(
            (ROOT / "deploy" / "mihomo-config.base.yaml").read_text()
        )
        groups = {item["name"] for item in config["proxy-groups"]}
        targets = {
            parts[2].split(",", 1)[0]
            for rule in config["rules"]
            for parts in [rule.split(",", 2)]
            if len(parts) >= 3
        }
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
