import unittest
from pathlib import Path


SCRIPT = (Path(__file__).resolve().parents[1] / "routeros" / "04-health-netwatch.rsc").read_text(
    encoding="utf-8"
)


class RouterOSHealthNetwatchTests(unittest.TestCase):
    def test_uses_current_gateway_and_shared_policy_selectors(self):
        self.assertIn("port=18088", SCRIPT)
        self.assertIn("new-connection-mark=family_mihomo_conn", SCRIPT)
        self.assertIn("new-routing-mark=family_mihomo_shared", SCRIPT)
        self.assertIn("jump-target=", SCRIPT)
        self.assertIn("family_mihomo_auto_v6", SCRIPT)

    def test_does_not_retain_legacy_probe_or_device_targets(self):
        for stale_value in ("18087", "192.168.2.105", "192.168.2.107"):
            self.assertNotIn(stale_value, SCRIPT)

    def test_quotes_value_selectors_and_requires_live_proxy_ip(self):
        self.assertEqual(SCRIPT.count(r'to-ports=\"53\"'), 2)
        self.assertEqual(SCRIPT.count(r'connection-mark=\"family_mihomo_conn\"'), 4)
        self.assertEqual(SCRIPT.count(r'jump-target=\"family_mihomo_auto_v6\"'), 2)
        self.assertIn(':local proxyIp ""', SCRIPT)
        self.assertIn('Set proxyIp to the live Z4Pro address before import.', SCRIPT)
        self.assertNotIn('192.168.10.10', SCRIPT)


if __name__ == "__main__":
    unittest.main()
