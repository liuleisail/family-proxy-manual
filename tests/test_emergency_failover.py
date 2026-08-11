#!/usr/bin/env python3
"""Focused regression checks for bounded, on-demand emergency failover."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "runtime" / "family-mihomo-sub-import.py"
SPEC = importlib.util.spec_from_file_location("family_mihomo_sub_import", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EmergencyFailoverTests(unittest.TestCase):
    def setUp(self):
        self.spec = {
            "primary": "TG-Auto",
            "emergency": "TG-应急",
            "watched": ("TG-Auto",),
            "pools": ("TG",),
            "url": "https://api.telegram.org",
        }
        self.proxies = {
            "TG-出口": {"now": "TG-Auto"},
            "TG-Auto": {"all": ["bad"], "alive": False},
            "bad": {"alive": False},
            "TG-应急": {"now": "reserve", "all": ["reserve"]},
            "reserve": {"alive": True},
        }

    def test_catalog_excludes_active_and_interleaves_sources(self):
        records = [
            {"name": "[主力] 香港 A", "raw": "香港 A", "source": "primary", "label": "主力"},
            {"name": "[主力] 香港 B", "raw": "香港 B", "source": "primary", "label": "主力"},
            {"name": "[备用2] 香港 C", "raw": "香港 C", "source": "backup2", "label": "备用2"},
            {"name": "[主力] 日本 A", "raw": "日本 A", "source": "primary", "label": "主力"},
        ]
        selected = {name: [] for name in MODULE.POOLS}
        selected["HK-视频"] = ["[主力] 香港 A"]
        selected["Proxy"] = ["[主力] 香港 A"]
        with patch.object(MODULE, "nodes", return_value=records), \
             patch.object(MODULE, "source_slots", return_value=["primary", "backup2"]):
            catalog = MODULE.emergency_catalog(selected)
        self.assertEqual(catalog["HK-视频-应急"], ["[主力] 香港 B", "[备用2] 香港 C"])
        self.assertNotIn("[主力] 香港 A", catalog["Proxy-应急"])
        self.assertTrue(all("香港" not in name for name in catalog["AI-应急"]))

    def run_state(self, previous, proxies=None, winner="[backup] reserve"):
        choices = []
        alerts = []
        writes = []
        with patch.object(MODULE, "FAILSAFE_EXITS", {"TG-出口": self.spec}), \
             patch.object(MODULE, "read_json", return_value={"TG-出口": previous}), \
             patch.object(MODULE, "atomic_json", side_effect=lambda path, data: writes.append(data)), \
             patch.object(MODULE, "set_failsafe_exit", side_effect=lambda group, target: choices.append((group, target))), \
             patch.object(MODULE, "scan_emergency_exit", return_value=(winner, {"tested": 8, "winner": winner})), \
             patch.object(MODULE, "send_telegram_alert", side_effect=lambda text: alerts.append(text) or (True, "ok")), \
             patch.object(MODULE.time, "time", return_value=2000.0):
            state = MODULE.update_failsafes(proxies or self.proxies, [], "now")
        return state["TG-出口"], choices

    def test_failed_primary_uses_verified_emergency_node(self):
        state, choices = self.run_state({
            "active": "TG-Auto", "phase": "normal", "down_checks": 1, "last_scan_epoch": 0,
        })
        self.assertEqual(state["active"], "TG-应急")
        self.assertEqual(state["phase"], "emergency")
        self.assertIn(("TG-应急", "[backup] reserve"), choices)
        self.assertIn(("TG-出口", "TG-应急"), choices)

    def test_exhausted_scan_keeps_proxy_instead_of_direct(self):
        state, choices = self.run_state({
            "active": "TG-Auto", "phase": "normal", "down_checks": 1, "last_scan_epoch": 0,
        }, winner=None)
        self.assertEqual(state["active"], "TG-Auto")
        self.assertEqual(state["phase"], "exhausted")
        self.assertNotIn("DIRECT", [target for _, target in choices])

    def test_recovery_waits_for_three_checks_and_minimum_dwell(self):
        healthy = {
            "TG-出口": {"now": "TG-应急"},
            "TG-Auto": {"all": ["good"], "alive": True},
            "good": {"alive": True},
            "TG-应急": {"now": "reserve", "all": ["reserve"]},
            "reserve": {"alive": True},
        }
        state, _ = self.run_state({
            "active": "TG-应急", "phase": "emergency", "up_checks": 2,
            "activated_epoch": 1000, "last_scan_epoch": 1900, "emergency_node": "reserve",
        }, proxies=healthy)
        self.assertEqual(state["active"], "TG-Auto")
        self.assertEqual(state["phase"], "normal")

    def test_manual_direct_is_preserved(self):
        direct = dict(self.proxies)
        direct["TG-出口"] = {"now": "DIRECT"}
        state, _ = self.run_state({
            "active": "DIRECT", "phase": "manual-direct", "up_checks": 99, "activated_epoch": 0,
        }, proxies=direct)
        self.assertEqual(state["active"], "DIRECT")
        self.assertEqual(state["phase"], "manual-direct")


if __name__ == "__main__":
    unittest.main()
