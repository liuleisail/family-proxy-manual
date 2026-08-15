import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "runtime" / "family-proxy-gateway.py").read_text()


class GatewayHealthRoutingTests(unittest.TestCase):
    def test_health_probe_does_not_override_authenticated_homepage(self):
        condition = (
            'and self.client_address[0] == "__FAMILY_ROUTER_IP__"'
            ' and not valid_session(self.headers.get("Cookie", ""))'
        )
        normalized = " ".join(SOURCE.split())
        self.assertIn(condition, normalized)


if __name__ == "__main__":
    unittest.main()
