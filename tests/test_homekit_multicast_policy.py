#!/usr/bin/env python3
"""Regression checks for the managed-device multicast direct rule."""

import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "runtime" / "family-proxy-ui.py"
CSRF_PATH = Path("/etc/family-proxy-ui/csrf-token")
ORIGINAL_READ_TEXT = Path.read_text


def load_module():
    source = ORIGINAL_READ_TEXT(MODULE_PATH, encoding="utf-8")
    source = source.replace('"__FAMILY_LAN_CIDR__"', '"192.168.2.0/24"')
    source = source.replace('"__FAMILY_PROXY_IP__"', '"192.168.2.156"')
    source = source.replace('"__FAMILY_ROUTER_IP__"', '"192.168.2.1"')
    source = source.replace('"__FAMILY_RESERVED_GATEWAY_IP__"', '"192.168.2.141"')

    def read_text(path, *args, **kwargs):
        if path == CSRF_PATH:
            return "x" * 64
        return ORIGINAL_READ_TEXT(path, *args, **kwargs)

    module = types.ModuleType("family_proxy_ui_multicast")
    module.__file__ = str(MODULE_PATH)
    with patch.object(Path, "read_text", new=read_text):
        exec(compile(source, str(MODULE_PATH), "exec"), module.__dict__)
    return module


class FakeRouterOS:
    def __init__(self, module):
        self.module = module
        self.calls = []
        self.data = {
            "/routing/table": [{".id": "table", "name": module.SHARED_TABLE}],
            "/ip/firewall/mangle": [
                {".id": "route-to-z4pro", "comment": module.SHARED_TAG + " route to z4pro"},
                {".id": "mark", "comment": module.SHARED_TAG + " mark connection"},
                {".id": "anchor", "comment": "family-mihomo-auto anchor"},
            ],
            "/ip/route": [{".id": "shared-route", "comment": module.SHARED_TAG + " route"}],
            "/ip/firewall/nat": [
                {".id": "dns-tcp", "comment": module.SHARED_TAG + " DNS TCP"},
                {".id": "dns-udp", "comment": module.SHARED_TAG + " DNS UDP"},
                {".id": "nat-anchor", "comment": "family-mihomo-auto DNS anchor"},
            ],
            "/ip/firewall/filter": [
                {".id": "fasttrack-exclude", "comment": module.SHARED_TAG + " FastTrack exclude"},
                {".id": "quic", "comment": module.SHARED_TAG + " QUIC fast fallback"},
            ],
            "/ipv6/firewall/filter": [
                {".id": "v6", "comment": "family-mihomo-auto IPv6 drop",
                 "action": "reject", "reject-with": "icmp-admin-prohibited"},
            ],
        }

    def print(self, path):
        return [dict(item) for item in self.data.get(path, [])]

    def add(self, path, **props):
        item = {".id": f"added-{len(self.calls)}", **props}
        self.data.setdefault(path, []).append(item)
        self.calls.append(("add", path, item))

    def set(self, path, item_id, **props):
        for item in self.data[path]:
            if item[".id"] == item_id:
                item.update(props)
                self.calls.append(("set", path, item_id, props))
                return
        raise AssertionError(item_id)

    def talk(self, path, payload):
        self.calls.append(("talk", path, payload))
        if path.endswith("/move"):
            items = self.data[path.removesuffix("/move")]
            item = next(item for item in items if item[".id"] == payload["numbers"])
            destination = next(index for index, value in enumerate(items)
                               if value[".id"] == payload["destination"])
            items.remove(item)
            items.insert(destination, item)


class HomeKitMulticastPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_adds_multicast_direct_before_connection_marker(self):
        api = FakeRouterOS(self.module)
        self.module.ensure_shared_policy(api)
        rules = api.data["/ip/firewall/mangle"]
        multicast = next(item for item in rules
                         if item.get("comment") == self.module.SHARED_TAG + " multicast direct")
        marker = next(item for item in rules
                      if item.get("comment") == self.module.SHARED_TAG + " mark connection")
        self.assertEqual(multicast["action"], "accept")
        self.assertEqual(multicast["dst-address"], "224.0.0.0/4")
        self.assertLess(rules.index(multicast), rules.index(marker))

    def test_repairs_existing_multicast_rule_and_keeps_order(self):
        api = FakeRouterOS(self.module)
        api.data["/ip/firewall/mangle"].insert(2, {
            ".id": "multicast", "comment": self.module.SHARED_TAG + " multicast direct",
            "action": "mark-connection", "dst-address": "192.168.2.0/24",
        })
        self.module.ensure_shared_policy(api)
        rules = api.data["/ip/firewall/mangle"]
        multicast = next(item for item in rules if item[".id"] == "multicast")
        marker = next(item for item in rules
                      if item.get("comment") == self.module.SHARED_TAG + " mark connection")
        self.assertEqual(multicast["action"], "accept")
        self.assertEqual(multicast["dst-address"], "224.0.0.0/4")
        self.assertLess(rules.index(multicast), rules.index(marker))

    def test_routeros_template_places_rule_before_marker(self):
        script = (ROOT / "routeros" / "02-prepare-controller.rsc").read_text(encoding="utf-8")
        self.assertIn('" multicast direct"', script)
        self.assertIn("dst-address=224.0.0.0/4", script)
        self.assertIn("place-before=$connectionMarker", script)
        self.assertIn("move $multicastRule destination=$connectionMarker", script)


if __name__ == "__main__":
    unittest.main()
