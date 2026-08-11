import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "runtime" / "family-proxy-ui.py"
family_proxy_ui = type("FamilyProxyUI", (), {})()
source = MODULE_PATH.read_text(encoding="utf-8").replace(
    "__FAMILY_LAN_CIDR__", "192.168.2.0/24"
)
exec(compile(source, str(MODULE_PATH), "exec"), family_proxy_ui.__dict__)


class FakeRouterAPI:
    def __init__(self, connections, failures=None):
        self.connections = connections
        self.failures = failures or {}
        self.removed = []

    def print(self, path):
        self.assert_path(path)
        return self.connections

    def remove(self, path, item_id):
        self.assert_path(path)
        if item_id in self.failures:
            raise self.failures[item_id]
        self.removed.append(item_id)

    @staticmethod
    def assert_path(path):
        if path != "/ip/firewall/connection":
            raise AssertionError(f"unexpected RouterOS path: {path}")


class ClearDeviceConnectionsTests(unittest.TestCase):
    def test_expired_connection_is_ignored_and_cleanup_continues(self):
        api = FakeRouterAPI(
            [
                {".id": "*1", "src-address": "192.168.2.189:50000"},
                {".id": "*2", "reply-dst-address": "192.168.2.189:50001"},
            ],
            {"*1": family_proxy_ui.RouterError("no such item (4)")},
        )

        removed = family_proxy_ui.clear_device_connections(api, "192.168.2.189")

        self.assertEqual(removed, 1)
        self.assertEqual(api.removed, ["*2"])

    def test_unrelated_router_error_is_propagated(self):
        api = FakeRouterAPI(
            [{".id": "*1", "src-address": "192.168.2.189:50000"}],
            {"*1": family_proxy_ui.RouterError("permission denied")},
        )

        with self.assertRaisesRegex(family_proxy_ui.RouterError, "permission denied"):
            family_proxy_ui.clear_device_connections(api, "192.168.2.189")


if __name__ == "__main__":
    unittest.main()
