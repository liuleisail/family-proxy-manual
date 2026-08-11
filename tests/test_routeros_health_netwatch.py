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
        self.assertIn("jump-target=family_mihomo_auto_v6", SCRIPT)

    def test_does_not_retain_legacy_probe_or_device_targets(self):
        for stale_value in ("18087", "192.168.2.105", "192.168.2.107"):
            self.assertNotIn(stale_value, SCRIPT)


if __name__ == "__main__":
    unittest.main()
