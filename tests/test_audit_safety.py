import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from test_homekit_multicast_policy import load_module
from test_mosdns_updater import family_mosdns_updater as updater


ROOT = Path(__file__).resolve().parents[1]


class AuditSafetyTests(unittest.TestCase):
    def setUp(self):
        self.ui = load_module()

    def test_cleanup_matches_complete_device_tag(self):
        ui = self.ui
        class Router:
            removed = []
            def print(self, path):
                if path == '/ipv6/firewall/filter':
                    return [{'.id': ip, 'comment': ui.managed_tag(ip) + ' IPv6 bypass guard'}
                            for ip in ('192.168.2.11', '192.168.2.112', '192.168.2.115')]
                if path == '/ip/firewall/mangle':
                    return [{'.id': 'legacy11', 'comment': 'family-mihomo-11 route to z4pro'},
                            {'.id': 'legacy112', 'comment': 'family-mihomo-112 route to z4pro'}]
                return []
            def remove(self, path, item_id):
                self.removed.append(item_id)
        api = Router()
        ui.cleanup_device_rules(api, '192.168.2.11')
        self.assertEqual(set(api.removed), {'192.168.2.11', 'legacy11'})

    def test_device_transaction_serializes_read_modify_write(self):
        ui = self.ui
        errors = []
        with tempfile.TemporaryDirectory() as directory, patch.object(ui, 'MANAGED_IPS_PATH', Path(directory) / 'managed-ips'):
            @ui.device_transaction
            def add(ip):
                values = ui.managed_ips()
                time.sleep(0.01)
                ui.save_managed_ips(values | {ip})
            def worker(ip):
                try:
                    add(ip)
                except Exception as exc:
                    errors.append(exc)
            threads = [threading.Thread(target=worker, args=(f'192.168.2.{n}',)) for n in range(11, 16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(ui.managed_ips(), {f'192.168.2.{n}' for n in range(11, 16)})

    def test_disabled_rules_do_not_satisfy_egress(self):
        ui = self.ui
        class Router:
            def print(self, path):
                return [{'comment': ui.SHARED_TAG + ' route', 'disabled': 'true', 'active': 'false'}]
        contract = ui.egress_policy_contract(Router(),
            [{'comment': ui.SHARED_TAG + name, 'disabled': 'true'} for name in (' mark connection', ' route to z4pro')],
            [{'comment': ui.SHARED_TAG + ' DNS ' + p, 'disabled': 'true'} for p in ('TCP', 'UDP')], [])
        result = ui.device_egress('192.168.2.112', 'AA', True, [], contract)
        self.assertEqual(result['mode'], 'degraded')
        self.assertFalse(contract['mark_rule'])

    def test_enable_prepares_receiver_before_router_and_rolls_back_on_failure(self):
        ui = self.ui
        ip = '192.168.2.112'
        for fail in (False, True):
            events = []
            class Router:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def print(self, path):
                    return [{'address': ip, 'mac-address': 'AA', '.id': 'lease', 'dynamic': 'false'}]
                def add(self, path, **props):
                    events.append('router-add')
                    if fail:
                        raise ui.RouterError('write failed')
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                mocks = {
                    'MANAGED_IPS_PATH': Path(directory) / 'managed-ips', 'RouterOS': Router,
                }
                for key, value in mocks.items(): stack.enter_context(patch.object(ui, key, value))
                values = {'standalone_mode': False, 'local_health': {'ready': True}, 'address_list_managed': set(),
                          'conflicting_policy': None, 'ensure_static_dhcp_lease': None, 'ensure_shared_policy': None,
                          'verify_device_rules': None, 'clear_device_connections': 0, 'audit': None,
                          'forwarding_status': {'ready': True, 'managed': [ip]}}
                for key, value in values.items(): stack.enter_context(patch.object(ui, key, return_value=value))
                stack.enter_context(patch.object(ui, 'sync_tproxy', side_effect=lambda: events.append('sync')))
                stack.enter_context(patch.object(ui, 'remove_shared_membership', side_effect=lambda *args: events.append('detach')))
                if fail:
                    with self.assertRaisesRegex(ui.RouterError, 'write failed'): ui.enable_device(ip)
                    self.assertEqual(ui.managed_ips(), set())
                    self.assertEqual(events[-2:], ['detach', 'sync'])
                else:
                    ui.enable_device(ip)
                    self.assertEqual(ui.managed_ips(), {ip})
                self.assertLess(events.index('sync'), events.index('router-add'))

    def test_traffic_requires_recent_marked_counter_increase(self):
        ui = self.ui
        ip = '192.168.2.112'
        item = {'.id': '*1', 'src-address': ip + ':5000', 'orig-packets': '100'}
        self.assertFalse(ui.recent_marked_traffic(ip, [item], now=1))
        item['connection-mark'] = ui.SHARED_CONN_MARK
        self.assertTrue(ui.recent_marked_traffic(ip, [item], now=2))
        self.assertTrue(ui.recent_marked_traffic(ip, [item], now=30))
        self.assertFalse(ui.recent_marked_traffic(ip, [item], now=63))
        ui.DEVICE_TRAFFIC.clear()
        self.assertFalse(ui.recent_marked_traffic(ip, [item], now=1))

    def test_dead_policy_or_broken_forwarding_is_unhealthy(self):
        ui = self.ui
        for alive, forwarding in ((False, True), (True, False)):
            with self.subTest(alive=alive), patch.object(ui, 'standalone_mode', return_value=False), \
                    patch.object(ui, 'mihomo_request', side_effect=[{'version': 'test'}, {'now': 'node', 'all': ['node'], 'alive': alive}]), \
                    patch.object(ui, 'dns_probe', return_value=True), patch.object(ui, 'build_info', return_value={}), \
                    patch.object(ui, 'forwarding_status', return_value={'ready': forwarding}):
                self.assertFalse(ui.local_health()['ready'])

    def test_forwarding_status_checks_actual_kernel_objects(self):
        ui = self.ui
        rules = [{'table': ui.SHARED_TABLE, 'fwmark': '0x2000'}]
        routes = [{'type': 'local', 'dst': 'default', 'dev': 'lo'}]
        members = {'nftables': [{'set': {'elem': ['192.168.2.112']}}]}
        chain = {'nftables': [{'chain': {'hook': 'prerouting', 'type': 'filter'}}] + [
            {'rule': {'expr': [
                {'match': {'right': '@managed4'}},
                {'match': {'left': {'meta': {'key': 'l4proto'}}, 'right': protocol}},
                {'tproxy': {'port': 7893}},
                {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': 8192}},
            ]}} for protocol in ('tcp', 'udp')]}
        def run(args, **kwargs):
            if args[0] == 'ss':
                value = 'tcp LISTEN 0 5 *:7893 *:*\nudp UNCONN 0 0 *:7893 *:*\n'
            else:
                value = json.dumps(rules if 'rule' in args else routes if 'route' in args else members if 'set' in args else chain)
            return subprocess.CompletedProcess(args, 0, value)
        with patch.object(ui.subprocess, 'run', side_effect=run), patch.object(ui, 'managed_ips', return_value={'192.168.2.112'}):
            self.assertTrue(ui.forwarding_status()['ready'])
            routes.clear()
            self.assertFalse(ui.forwarding_status()['ready'])
            routes.append({'type': 'local', 'dst': 'default', 'dev': 'lo'})
            members['nftables'][0]['set']['elem'] = []
            self.assertFalse(ui.forwarding_status()['ready'])
            members['nftables'][0]['set']['elem'] = ['192.168.2.112']
            chain['nftables'].pop()
            self.assertFalse(ui.forwarding_status()['ready'])

    def test_mosdns_pre_switch_failures_never_recreate(self):
        for failure in ('backup_config', 'download_latest_image'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, \
                    patch.object(updater, 'LOCK_PATH', Path(directory) / 'lock'), \
                    patch.object(updater, 'running_image_id', return_value='old'), \
                    patch.object(updater, 'backup_config', return_value='backup'), \
                    patch.object(updater, 'download_latest_image', return_value='new'), \
                    patch.object(updater, failure, side_effect=RuntimeError('failed')), \
                    patch.object(updater, 'set_status'), patch.object(updater, 'command') as command:
                updater.do_update()
                command.assert_not_called()

    def test_mosdns_post_switch_failure_still_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(updater, 'LOCK_PATH', Path(directory) / 'lock'), \
                patch.object(updater, 'running_image_id', return_value='old'), \
                patch.object(updater, 'backup_config', return_value='backup'), \
                patch.object(updater, 'download_latest_image', return_value='new'), \
                patch.object(updater, 'verify_new_image'), patch.object(updater, 'core_version', return_value='old'), \
                patch.object(updater, 'wait_healthy', side_effect=[RuntimeError('unhealthy'), None]), \
                patch.object(updater, 'set_status') as status, patch.object(updater, 'command') as command:
            updater.do_update()
            recreates = [call for call in command.call_args_list if '--force-recreate' in call.args[0]]
            self.assertEqual(len(recreates), 2)
            self.assertEqual(status.call_args.args[0], 'rolled_back')

    def test_apns_cleanup_has_explicit_address_list_path(self):
        source = (ROOT / 'routeros/02-prepare-controller.rsc').read_text()
        self.assertIn('in=[/ip firewall address-list find where list="family_apple_direct"', source)
        self.assertIn('/ip firewall address-list remove $appleDirectEntry', source)

    def test_docker_recovery_only_starts_allowed_names_and_respects_pause(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allow, exclude, calls, pause = [root / name for name in ('allow', 'exclude', 'calls', 'pause')]
            allow.write_text('family-mihomo-fallback\nfamily-mosdns-t\n')
            exclude.write_text('family-mosdns-t\n')
            env = {**os.environ, 'FAMILY_DOCKER_RECOVER_ALLOW': str(allow),
                   'FAMILY_DOCKER_RECOVER_EXCLUDE': str(exclude),
                   'FAMILY_DOCKER_RECOVER_PAUSE': str(pause), 'CALLS': str(calls)}
            script = '''docker() {
                case "$1" in
                  info) return 0;;
                  ps) printf 'a\\nb\\nc\\n';;
                  inspect) if [[ "$3" == *RestartPolicy* ]]; then echo unless-stopped;
                    else case "$4" in a) echo /family-mihomo-fallback;; b) echo /family-mosdns-t;; c) echo /unrelated;; esac; fi;;
                  start) echo "$2" >> "$CALLS";;
                esac
            }
            export -f docker
            bash "$1"
            '''
            args = ['bash', '-c', script, 'test', str(ROOT / 'scripts/family-docker-recover')]
            subprocess.run(args, env=env, check=True, capture_output=True)
            self.assertEqual(calls.read_text(), 'a\n')
            pause.touch()
            subprocess.run(args, env=env, check=True, capture_output=True)
            self.assertEqual(calls.read_text(), 'a\n')


if __name__ == '__main__':
    unittest.main()
