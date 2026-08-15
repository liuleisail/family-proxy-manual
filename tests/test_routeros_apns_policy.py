import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "routeros" / "02-prepare-controller.rsc").read_text(encoding="utf-8")
RULES_PAGE = (ROOT / "runtime" / "rules.html").read_text(encoding="utf-8")
APP = (ROOT / "frontend" / "src" / "App.vue").read_text(encoding="utf-8")


class AppleApnsPolicyTests(unittest.TestCase):
    def test_routeros_does_not_bypass_apple_push_before_mihomo(self):
        self.assertIn("Apple APNs direct", SCRIPT)
        self.assertIn('list="family_apple_direct"', SCRIPT)
        self.assertIn("remove $appleDirectRule", SCRIPT)
        self.assertIn("remove $appleDirectEntry", SCRIPT)
        self.assertNotIn('add list=$appleDirectList address=17.0.0.0/8', SCRIPT)

    def test_both_rule_editors_offer_apns_classical_text_proxy_preset(self):
        url = "https://raw.githubusercontent.com/mrbruce516/apns-fix/refs/heads/main/Apple_APNs.list"
        for source in (RULES_PAGE, APP):
            self.assertIn(url, source)
            self.assertIn("apple-apns-classical", source)
            self.assertIn("classical", source)
            self.assertIn("text", source)
            self.assertIn("Proxy-Auto", source)


if __name__ == "__main__":
    unittest.main()
