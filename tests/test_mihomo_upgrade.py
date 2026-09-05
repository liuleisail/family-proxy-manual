#!/usr/bin/env python3
"""Regression checks for the backup-first Mihomo image upgrade flow."""

import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = (ROOT / "scripts" / "family-mihomo-upgrade").read_text(encoding="utf-8")


class MihomoUpgradeScriptTests(unittest.TestCase):
    def test_upgrade_uses_docker_pull_before_recreating_the_container(self):
        self.assertIn('if ! docker pull "$target"; then', SCRIPT)
        self.assertIn('docker compose -f "$compose" run --rm --no-deps', SCRIPT)
        self.assertIn('docker compose -f "$compose" up -d --no-deps --force-recreate "$container"', SCRIPT)
        self.assertNotIn("docker compose -f \"$compose\" down", SCRIPT)
        self.assertNotIn("--volumes", SCRIPT)

    def test_upgrade_backups_config_cache_and_mount_metadata(self):
        self.assertIn('mkdir -p -m 700 "$backup"', SCRIPT)
        self.assertIn('cp -a "$workdir/config.yaml" "$compose" "$backup/"', SCRIPT)
        self.assertIn('cp -a "$workdir/cache.db" "$backup/"', SCRIPT)
        self.assertIn('docker inspect "$container" > "$backup/container.inspect.json"', SCRIPT)
        self.assertIn('container_mounts > "$backup/mounts.before"', SCRIPT)
        self.assertIn('container_data_source()', SCRIPT)
        self.assertIn('volumes.insert(0, f"{volume_source}:/root/.config/mihomo")', SCRIPT)
        self.assertIn('mounts_match "$backup/mounts.before"', SCRIPT)

    def test_pull_failure_leaves_the_existing_container_and_data_untouched(self):
        self.assertIn("镜像拉取失败；现有容器未重建，配置与数据未改动。", SCRIPT)
        self.assertIn('cp -a "$backup/docker-compose.yml" "$compose"', SCRIPT)
        self.assertIn('set_compose_image "$rollback_tag" "$data_volume"', SCRIPT)
        self.assertIn("配置与数据挂载保持不变", SCRIPT)

    def test_success_status_refreshes_the_running_version(self):
        self.assertIn('write_status success', SCRIPT)
        self.assertIn('"$(running_version)"', SCRIPT)

    def test_recover_uses_the_backup_rollback_tag_and_original_data_source(self):
        self.assertIn('recover() {', SCRIPT)
        self.assertIn('rollback_tag="family-mihomo-rollback:$(basename "$backup")"', SCRIPT)
        self.assertIn('set_compose_image "$rollback_tag" "$data_source"', SCRIPT)
        self.assertIn('recover) recover "${2:-}" ;;', SCRIPT)


if __name__ == "__main__":
    unittest.main()
