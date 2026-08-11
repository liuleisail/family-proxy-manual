#!/usr/bin/env python3
"""Regression checks for the RouterOS remote-access WireGuard flow."""

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

    module = types.ModuleType("family_proxy_ui_remote_wireguard")
    module.__file__ = str(MODULE_PATH)
    with patch.object(Path, "read_text", new=read_text):
        exec(compile(source, str(MODULE_PATH), "exec"), module.__dict__)
    return module


class FakeRouterOS:
    def __init__(self, module, wan=True):
        self.module = module
        self.wan = wan
        self.calls = []
        self.data = {
            "/system/resource": [{"version": "7.21.5"}],
            "/interface/wireguard": [],
            "/interface/wireguard/peers": [],
            "/ip/address": [],
            "/ip/route": [],
            "/interface/list/member": [{"list": "WAN", "interface": "ether1"}] if wan else [],
            "/ip/firewall/filter": [],
            "/ip/firewall/nat": [],
        }

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def print(self, path):
        return [dict(item) for item in self.data.get(path, [])]

    def add(self, path, **props):
        item = {".id": f"*{len(self.calls) + 1}", **props}
        if path == "/interface/wireguard/peers":
            item.setdefault("public-key", "client-public-key")
            item.setdefault("private-key", "client-private-key")
        self.data.setdefault(path, []).append(item)
        self.calls.append(("add", path, item))
        return [{"ret": item[".id"]}]

    def set(self, path, item_id, **props):
        item = next(item for item in self.data[path] if item[".id"] == item_id)
        item.update(props)
        self.calls.append(("set", path, item_id, props))

    def remove(self, path, item_id):
        self.data[path] = [item for item in self.data.get(path, []) if item.get(".id") != item_id]
        self.calls.append(("remove", path, item_id))

    def talk(self, path, payload=None):
        self.calls.append(("talk", path, payload or {}))
        if path.endswith("/show-client-config"):
            return [{"ret": "[Interface]\nAddress = 10.66.0.2/32\nPrivateKey = client-private-key\n\n[Peer]\nPublicKey = server-public-key\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n"}]
        if path.endswith("/peers/print"):
            return self.print("/interface/wireguard/peers")
        if path.endswith("/move"):
            return []
        return []


class RemoteWireGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def config(self):
        return {
            "ROUTER_MODE": "routeros",
            "ROUTER_HOST": "192.168.2.1",
            "ROUTER_USER": "family_proxy",
            "ROUTER_PASSWORD": "secret",
            "FAMILY_ROUTER_IP": "192.168.2.1",
            "WIREGUARD_REMOTE_INTERFACE": "family-remote-wg",
            "WIREGUARD_REMOTE_PORT": "51820",
            "WIREGUARD_REMOTE_ADDRESS": "10.66.0.1/24",
        }

    def test_endpoint_validation_rejects_private_ip_and_accepts_domain(self):
        with self.assertRaisesRegex(self.module.RouterError, "公网"):
            self.module.validate_public_endpoint("192.168.2.1")
        self.assertEqual(self.module.validate_public_endpoint("vpn.example.com"), "vpn.example.com")

    def test_create_builds_full_tunnel_peer_without_touching_existing_wg(self):
        api = FakeRouterOS(self.module)
        with patch.object(self.module, "RouterOS", return_value=api), \
                patch.object(self.module, "load_config", return_value=self.config()), \
                patch.object(self.module, "standalone_mode", return_value=False), \
                patch.object(self.module, "audit"):
            result = self.module.create_remote_wireguard_client({
                "name": "iPhone 16 Pro Max",
                "endpoint": "vpn.example.com",
                "port": 51820,
                "dns": "192.168.2.1",
            })
        self.assertIn("[Interface]", result["config"])
        self.assertIn("AllowedIPs = 0.0.0.0/0", result["config"])
        peer_add = next(call for call in api.calls if call[0:2] == ("add", "/interface/wireguard/peers"))
        self.assertEqual(peer_add[2]["private-key"], "auto")
        self.assertEqual(peer_add[2]["client-allowed-address"], "0.0.0.0/0")
        self.assertEqual(len(api.data["/interface/wireguard"]), 1)
        self.assertEqual(len(api.data["/interface/wireguard/peers"]), 1)

    def test_missing_wan_list_rolls_back_interface_and_address(self):
        api = FakeRouterOS(self.module, wan=False)
        with patch.object(self.module, "RouterOS", return_value=api), \
                patch.object(self.module, "load_config", return_value=self.config()), \
                patch.object(self.module, "standalone_mode", return_value=False), \
                patch.object(self.module, "audit"):
            with self.assertRaisesRegex(self.module.RouterError, "WAN 接口列表"):
                self.module.create_remote_wireguard_client({"name": "iPad", "endpoint": "vpn.example.com"})
        self.assertEqual(api.data["/interface/wireguard"], [])
        self.assertEqual(api.data["/ip/address"], [])
        self.assertEqual(api.data["/interface/wireguard/peers"], [])

    def test_standalone_mode_does_not_offer_routeros_access(self):
        with patch.object(self.module, "standalone_mode", return_value=True), \
                patch.object(self.module, "load_config", return_value=self.config()):
            status = self.module.remote_wireguard_status()
        self.assertEqual(status["mode"], "standalone")
        self.assertFalse(status["supported"])
        self.assertEqual(status["clients"], [])


if __name__ == "__main__":
    unittest.main()
