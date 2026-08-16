import importlib.util
import tempfile
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

    def test_image_pull_prefers_daemon_mirror_after_a_transient_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(family_mosdns_updater, "COMPOSE_DIR", Path(directory)), \
                    patch.object(family_mosdns_updater, "command", side_effect=[RuntimeError("mirror timeout"), "", "sha256:new"]), \
                    patch.object(family_mosdns_updater, "crane_command") as crane, \
                    patch.object(family_mosdns_updater.time, "sleep"):
                self.assertEqual(family_mosdns_updater.download_latest_image(), "sha256:new")
                crane.assert_not_called()

    def test_image_pull_reports_crane_fallback_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(family_mosdns_updater, "COMPOSE_DIR", Path(directory)), \
                    patch.object(family_mosdns_updater, "command", side_effect=RuntimeError("daemon unavailable")), \
                    patch.object(family_mosdns_updater, "crane_command", side_effect=RuntimeError("proxy timeout")), \
                    patch.object(family_mosdns_updater.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "Docker daemon 2 次，crane 2 次"):
                    family_mosdns_updater.download_latest_image()

    def test_set_status_preserves_failure_until_success(self):
        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            with patch.object(family_mosdns_updater, "STATUS_PATH", status_path):
                family_mosdns_updater.set_status("rolled_back", "镜像拉取失败", backup="/tmp/backup.tar.gz")
                result = family_mosdns_updater.set_status("available", "发现可用更新", update_available=True)
                self.assertEqual(result["last_failure"]["message"], "镜像拉取失败")
                result = family_mosdns_updater.set_status("updated", "升级完成")
                self.assertNotIn("last_failure", result)

    def test_scheduled_check_does_not_apply_update(self):
        with patch.object(family_mosdns_updater, "do_check"), \
                patch.object(family_mosdns_updater, "status", return_value={"phase": "available", "update_available": True}), \
                patch.object(family_mosdns_updater, "do_update") as apply:
            family_mosdns_updater.auto_check_task()
            apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
