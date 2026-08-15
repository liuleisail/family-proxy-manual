import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "runtime" / "mosdns" / "updater.py"
SPEC = importlib.util.spec_from_file_location("family_mosdns_updater", MODULE_PATH)
family_mosdns_updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(family_mosdns_updater)


class MosdnsTagTests(unittest.TestCase):
    def test_latest_tag_ignores_openwrt_and_lite_tags(self):
        tags = [
            {"name": "openwrt-v0.7.3-r2"},
            {"name": "v0.7.1"},
            {"name": "lite-v0.1.9"},
            {"name": "v0.7.3"},
        ]

        self.assertEqual(family_mosdns_updater.latest_project_tag(tags), "v0.7.3")

    def test_release_source_is_mosdns_t(self):
        self.assertEqual(family_mosdns_updater.PROJECT_TAGS_URL, "https://github.com/jasonxtt/mosdns/tags")
        self.assertNotIn("IrineSistiana", family_mosdns_updater.PROJECT_TAGS_API)

    def test_status_normalizes_legacy_official_release_metadata(self):
        payload = {
            "phase": "up_to_date",
            "current_version": "v0.7.1-20260719-ca220de",
            "latest_image": "sha256:third-party",
            "release_source": "MosDNS 上游 GitHub Release",
            "release_url": "https://github.com/IrineSistiana/mosdns/releases",
            "release_version": "v5.4",
        }

        with patch.object(family_mosdns_updater, "load_json", return_value=payload):
            result = family_mosdns_updater.status()

        self.assertEqual(result["release_source"], "MosDNS-T 第三方项目 Tags")
        self.assertEqual(result["latest_version"], "sha256:third-party")
        self.assertEqual(result["release_version"], "")
        self.assertNotIn("IrineSistiana", result["release_url"])


if __name__ == "__main__":
    unittest.main()
