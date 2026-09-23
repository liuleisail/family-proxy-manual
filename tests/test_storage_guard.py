import errno
import fcntl
import importlib.machinery
import importlib.util
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from test_homekit_multicast_policy import load_module
from test_mosdns_updater import family_mosdns_updater as updater

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('storage_guard', str(ROOT / 'scripts/family-storage-guard'))
spec = importlib.util.spec_from_loader(loader.name, loader)
guard = importlib.util.module_from_spec(spec)
loader.exec_module(guard)


class StorageGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, value in [('CONFIG_DIR', self.root), ('STATE_DIR', self.root)]:
            p = patch.object(guard, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.unit = 'family-proxy-ui'

    def inspect(self, errors, repair=True, state=None, pid=123):
        with patch.object(guard, 'service_pid', return_value=pid), \
             patch.object(guard, 'service_paths', return_value=[self.root / 'config']), \
             patch.object(guard, 'probe', side_effect=errors), \
             patch.object(guard, 'api_check', return_value=True), \
             patch.object(guard, 'backup', return_value='/safe/backup') as backup, \
             patch.object(guard, 'command') as command:
            result = guard.inspect_service(self.unit, repair, state or {})
            backup.assert_not_called()
            command.assert_not_called()
            return result['state']

    def test_healthy_service_is_never_restarted(self):
        self.assertEqual(self.inspect([0, 0]), 'healthy')

    def test_host_storage_failure_is_not_misdiagnosed_as_service_failure(self):
        self.assertEqual(self.inspect([errno.ENOTCONN]), 'host_unavailable')

    def test_permission_missing_timeout_errors_do_not_trigger_restart(self):
        for error in [errno.EACCES, errno.ENOENT, -1]:
            self.assertEqual(self.inspect([0, error]), 'read_failed')

    def test_read_only_mode_reports_stale_without_changes(self):
        self.assertEqual(self.inspect([0, errno.ENOTCONN], repair=False), 'stale_mount')

    def test_inactive_service_is_not_started(self):
        self.assertEqual(self.inspect([], pid=0), 'inactive')

    def test_recent_failed_recovery_is_rate_limited(self):
        state = {self.unit: {'last_attempt': int(guard.time.time())}}
        self.assertEqual(self.inspect([0, errno.ESTALE], state=state), 'cooldown')

    def test_inflight_mutation_defers_restart(self):
        with (self.root / (self.unit + '.maintenance.lock')).open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            self.assertEqual(self.inspect([0, errno.ENOTCONN]), 'busy')

    def test_pid_change_aborts_recovery(self):
        with patch.object(guard, 'service_pid', side_effect=[123, 456]), \
             patch.object(guard, 'service_paths', return_value=['config']), \
             patch.object(guard, 'probe', side_effect=[0, errno.ENOTCONN]), \
             patch.object(guard, 'backup') as backup:
            self.assertEqual(guard.inspect_service(self.unit, True, {})['state'], 'changed_during_check')
            backup.assert_not_called()

    def test_recovery_backs_up_before_restart_and_checks_new_namespace_and_api(self):
        events = []
        with patch.object(guard, 'service_pid', side_effect=[123, 123, 456]), \
             patch.object(guard, 'service_paths', return_value=['config']), \
             patch.object(guard, 'probe', side_effect=[0, errno.ENOTCONN, 0, errno.ENOTCONN, 0]), \
             patch.object(guard, 'backup', side_effect=lambda *args: events.append('backup') or '/safe/backup'), \
             patch.object(guard, 'command', side_effect=lambda args, **kw: events.append(args)), \
             patch.object(guard, 'api_check', return_value=True) as api:
            result = guard.inspect_service(self.unit, True, {})
        self.assertEqual(result['state'], 'recovered')
        self.assertEqual(events, ['backup', ['systemctl', 'restart', self.unit]])
        api.assert_called_once_with(self.unit)
        self.assertIn('last_attempt', json.loads((self.root / 'storage-guard.json').read_text())[self.unit])

    def test_probe_actually_reads_and_never_returns_file_contents(self):
        path = self.root / 'config'
        path.write_text('private material must not appear')
        result = subprocess.run(['python3', '-c', guard.PROBE, str(path)], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), {'errno': 0})
        self.assertNotIn('private', result.stdout)
        missing = subprocess.run(['python3', '-c', guard.PROBE, str(path / 'absent')], capture_output=True, text=True, check=True)
        self.assertNotEqual(json.loads(missing.stdout)['errno'], 0)

    def test_ui_mutation_holds_shared_lock_and_declines_during_recovery(self):
        ui = load_module()
        class Request:
            calls = 0
            replies = []
            def reply(self, code, value):
                self.replies.append((code, value))
        request = Request()
        root = self.root
        with patch.object(ui, 'CONFIG_PATH', self.root / 'router.env'):
            @ui.maintenance_request
            def operation(self):
                self.calls += 1
                with (root / (self.unit + '.maintenance.lock')).open('a') as guard_lock:
                    with self_case.assertRaises(BlockingIOError):
                        fcntl.flock(guard_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            request.unit = self.unit
            self_case = self
            operation(request)
            with (self.root / (self.unit + '.maintenance.lock')).open('a') as guard_lock:
                fcntl.flock(guard_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                operation(request)
        self.assertEqual(request.calls, 1)
        self.assertEqual(request.replies[-1][0], 503)

    def test_mosdns_worker_holds_lock_for_entire_background_job(self):
        started, finish, finished = threading.Event(), threading.Event(), threading.Event()
        lock_path = self.root / 'dns.lock'
        def job():
            started.set()
            finish.wait(3)
        with patch.object(updater, 'MAINTENANCE_LOCK_PATH', lock_path), \
             patch.object(updater.subprocess, 'run', side_effect=lambda *a, **kw: finished.set()):
            self.assertTrue(updater.start_worker(job))
            self.assertTrue(started.wait(2))
            with lock_path.open('a') as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finish.set()
            self.assertTrue(finished.wait(2))
            with lock_path.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse(updater.start_worker(job))

    def test_mosdns_management_failure_does_not_rollback_healthy_new_core(self):
        with patch.object(updater, 'LOCK_PATH', self.root / 'lock'), \
             patch.object(updater, 'COMPOSE_DIR', self.root / 'missing-mount'), \
             patch.object(updater, 'running_image_id', return_value='old'), \
             patch.object(updater, 'backup_config', return_value='backup'), \
             patch.object(updater, 'download_latest_image', return_value='new'), \
             patch.object(updater, 'verify_new_image'), \
             patch.object(updater, 'wait_healthy'), \
             patch.object(updater, 'set_status') as status, \
             patch.object(updater, 'command') as command:
            updater.do_update()
        recreates = [call for call in command.call_args_list if '--force-recreate' in call.args[0]]
        self.assertEqual(len(recreates), 1)
        self.assertEqual(status.call_args.args[0], 'error')
        self.assertIn('核心已更新且运行正常', status.call_args.args[1])

    def test_config_error_distinguishes_stale_mount_from_invalid_yaml(self):
        ui = load_module()
        with patch.object(Path, 'read_text', side_effect=OSError(errno.ENOTCONN, 'private path')):
            with self.assertRaisesRegex(ui.RouterError, '存储连接已失效'):
                ui.load_mihomo_config()
        with patch.object(Path, 'read_text', return_value='rules: ['):
            with self.assertRaisesRegex(ui.RouterError, '格式错误'):
                ui.load_mihomo_config()


class UpgradeStorageGateTests(unittest.TestCase):
    def run_apply(self, guard_failure):
        source = (ROOT / 'scripts/family-mihomo-upgrade').read_text()
        function = source[source.index('apply() {'):source.index('\nrecover() {')]
        function = function.replace('/usr/local/sbin/family-storage-guard --repair', 'storage_guard')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.yaml').write_text('rules: []')
            (root / 'docker-compose.yml').write_text('services: {}')
            script = '''set -Eeuo pipefail
workdir=$1; compose=$1/docker-compose.yml; lock_file=$1/lock; container=core; stable_image=new; calls=0
require_layout(){ :; }
flock(){ :; }
image(){ echo old; }
image_id(){ echo "$1-id"; }
container_mounts(){ echo mounts; }
container_data_source(){ echo /data; }
set_compose_image(){ :; }
healthy(){ return 0; }
mounts_match(){ return 0; }
running_version(){ echo v-test; }
write_status(){ echo "STATUS:$1:$2"; }
docker(){ echo "DOCKER:$*"; }
storage_guard(){ calls=$((calls+1)); [[ $calls != FAILURE ]]; }
'''.replace('FAILURE', str(guard_failure)) + function + '\napply\n'
            return subprocess.run(['bash', '-c', script, 'test', directory], text=True, capture_output=True)

    def test_precheck_failure_never_pulls_or_recreates(self):
        result = self.run_apply(1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('DOCKER:', result.stdout)
        self.assertIn('STATUS:failed', result.stdout)

    def test_postcheck_failure_does_not_rollback_healthy_core(self):
        result = self.run_apply(2)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout.count('up -d --no-deps --force-recreate'), 1)
        self.assertIn('未回滚核心', result.stdout)
        self.assertNotIn('STATUS:success', result.stdout)

    def test_success_requires_both_management_checks(self):
        result = self.run_apply(99)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('STATUS:success', result.stdout)
