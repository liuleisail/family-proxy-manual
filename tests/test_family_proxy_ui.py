import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "runtime" / "family-proxy-ui.py"
TEST_STATE_DIR = tempfile.TemporaryDirectory(prefix="family-proxy-ui-test-")
family_proxy_ui = type("FamilyProxyUI", (), {})()
source = MODULE_PATH.read_text(encoding="utf-8").replace(
    "__FAMILY_LAN_CIDR__", "192.168.2.0/24"
).replace(
    'CSRF_TOKEN_PATH = Path("/etc/family-proxy-ui/csrf-token")',
    f'CSRF_TOKEN_PATH = Path({str(Path(TEST_STATE_DIR.name) / "csrf-token")!r})',
)
family_proxy_ui.__dict__["__file__"] = str(MODULE_PATH)
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


class LegacyDashboardWarningTests(unittest.TestCase):
    def test_auto_failover_has_explanatory_warning_tooltip(self):
        page = family_proxy_ui.PAGE

        self.assertIn('<small>自动回退<span class="dash-warning"', page)
        self.assertIn('RouterOS Netwatch 连续探测异常时', page)
        self.assertIn('.dash-warning:hover:after', page)


class MaintenanceReleaseInfoTests(unittest.TestCase):
    def test_legacy_maintenance_includes_remote_wireguard_access(self):
        page = family_proxy_ui.MIHOMO_MAINTENANCE_PAGE

        for marker in (
            'id="remote-wg-form"',
            'id="remote-wg-name"',
            'id="remote-wg-endpoint"',
            'id="remote-wg-port"',
            'id="remote-wg-dns"',
            'id="remote-wg-dialog"',
            'src="/assets/qrcode-browser.js"',
            "/api/wireguard/remote-access",
            "/api/wireguard/remote-access/generate",
            "/api/wireguard/remote-access/revoke",
        ):
            self.assertIn(marker, page)

        self.assertEqual(page.count('src="/assets/qrcode-browser.js"'), 1)
        self.assertNotIn('private-key', page)
        self.assertNotIn('preshared-key', page)

    def test_all_component_cards_have_shared_release_info_controls(self):
        page = family_proxy_ui.MIHOMO_MAINTENANCE_PAGE

        for component in ("mihomo", "mosdns", "routeros", "z4pro"):
            self.assertIn(f'id="{component}-release-open"', page)
        self.assertEqual(page.count('class="info-button"'), 4)
        self.assertIn("function openComponentRelease", page)
        self.assertIn("releaseRecords[prefix]=item", page)

    def test_release_sources_are_scoped_to_component_pages(self):
        page = family_proxy_ui.MIHOMO_MAINTENANCE_PAGE

        for source in (
            "https://github.com/MetaCubeX/mihomo/releases",
            "https://github.com/jasonxtt/mosdns/tags",
            "https://mikrotik.com/download/changelogs?channelFilter=stable",
            "https://download.zspace.cn/",
        ):
            self.assertIn(source, page)
        self.assertIn("MosDNS-T</h2>", page)
        self.assertNotIn("IrineSistiana/mosdns", page)

    def test_component_release_metadata_has_consistent_contract(self):
        metadata = family_proxy_ui.component_release_metadata(
            "routeros", "当前已是最新", "官方通道没有可用更新", "2026-08-12T10:00:00Z"
        )

        self.assertEqual(metadata["release_source"], "MikroTik RouterOS 官方稳定版 Changelog")
        self.assertEqual(metadata["release_notes"], "官方通道没有可用更新")
        self.assertTrue(metadata["release_url"].startswith("https://mikrotik.com/download/changelogs"))

    def test_mosdns_release_metadata_is_third_party_scoped(self):
        metadata = family_proxy_ui.component_release_metadata("mosdns")

        self.assertEqual(metadata["release_source"], "MosDNS-T 第三方项目 Tags")
        self.assertEqual(metadata["release_url"], "https://github.com/jasonxtt/mosdns/tags")
        self.assertIn("不与官方 MosDNS 5.x 版本比较", metadata["release_notes"])

    def test_mosdns_status_ignores_legacy_official_release_metadata(self):
        payload = {
            "phase": "up_to_date",
            "current_version": "0.7.1",
            "latest_image": "sha256:third-party",
            "release_source": "MosDNS 上游 GitHub Release",
            "release_url": "https://github.com/IrineSistiana/mosdns/releases",
            "release_version": "v5.4",
            "release_notes": "official notes",
        }

        with patch.object(family_proxy_ui.Path, "read_text", return_value=json.dumps(payload)):
            result = family_proxy_ui.mosdns_component_update_status()

        self.assertEqual(result["release_source"], "MosDNS-T 第三方项目 Tags")
        self.assertEqual(result["release_version"], "")
        self.assertNotIn("IrineSistiana", result["release_url"])

    def test_mosdns_status_exposes_last_failure_for_maintenance_page(self):
        payload = {
            "phase": "available",
            "update_available": True,
            "last_failure": {"phase": "rolled_back", "message": "镜像拉取失败"},
        }

        with patch.object(family_proxy_ui.Path, "read_text", return_value=json.dumps(payload)):
            result = family_proxy_ui.mosdns_component_update_status()

        self.assertEqual(result["last_failure"]["message"], "镜像拉取失败")

    def test_platform_status_cleans_legacy_mosdns_release_metadata(self):
        payload = {
            "checked_at": 123,
            "mosdns": {
                "available": True,
                "latest_image": "sha256:third-party",
                "release_source": "MosDNS 上游 GitHub Release",
                "release_url": "https://github.com/IrineSistiana/mosdns/releases",
                "release_version": "v5.4",
            },
        }

        with patch.object(family_proxy_ui.Path, "read_text", return_value=json.dumps(payload)):
            result = family_proxy_ui.read_platform_update_status()

        self.assertTrue(result["mosdns"]["available"])
        self.assertEqual(result["mosdns"]["latest_version"], "sha256:third-party")
        self.assertEqual(result["mosdns"]["release_version"], "")
        self.assertNotIn("IrineSistiana", result["mosdns"]["release_url"])


if __name__ == "__main__":
    unittest.main()
