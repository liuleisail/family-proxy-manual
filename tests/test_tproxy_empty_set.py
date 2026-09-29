"""Exercise the production shell generator without changing network state."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TproxyManagedSetTests(unittest.TestCase):
    def render(self, addresses):
        source = (ROOT / 'scripts/family-mihomo-tproxy-auto').read_text()
        validator = source[source.index('valid_ip() {'):source.index('clear_legacy_runtime() {')]
        generator = source[source.index('write_nft_rules() {'):source.index('sync_rules() {')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'managed').write_text(addresses)
            (root / 'cn').write_text(''.join(f'10.{n // 256}.{n % 256}.0/24\n' for n in range(1001)))
            script = '''set -Eeuo pipefail
STATE="$1/managed"
CN_LIST="$1/cn"
FAMILY_LAN_PREFIX=192.168.2.
FAMILY_PROXY_IP=192.168.2.156
FAMILY_CAPTURE_INTERFACE=test0
NFT_TABLE=family_mihomo_direct
MARK=0x2000
'''
            subprocess.run(['bash', '-c', script + validator + generator + '\nwrite_nft_rules "$1/out.nft"',
                            'generator-test', directory], check=True, capture_output=True, text=True)
            return (root / 'out.nft').read_text()

    def test_last_device_removed_produces_empty_typed_set(self):
        text = self.render('')
        block = text.split('set managed4 {', 1)[1].split('set cn4', 1)[0]
        self.assertIn('type ipv4_addr;', block)
        self.assertNotIn('elements', block)
        self.assertNotRegex(text, r'elements\s*=\s*\{\s*\}')
        self.assertIn('meta l4proto tcp counter tproxy ip to :7893', text)
        self.assertIn('meta l4proto udp counter tproxy ip to :7893', text)

    def test_no_valid_addresses_also_produces_empty_set(self):
        text = self.render('\n192.168.3.112\ninvalid\n192.168.2.999\n')
        block = text.split('set managed4 {', 1)[1].split('set cn4', 1)[0]
        self.assertNotIn('elements', block)

    def test_single_and_multiple_members_are_preserved(self):
        for addresses in [('192.168.2.194',), ('192.168.2.112', '192.168.2.115', '192.168.2.194')]:
            with self.subTest(addresses=addresses):
                text = self.render('\n'.join(addresses) + '\n')
                block = text.split('set managed4 {', 1)[1].split('set cn4', 1)[0]
                self.assertEqual(re.findall(r'192\.168\.2\.\d+', block), list(addresses))
                self.assertIn('elements = { ' + ', '.join(addresses) + ' }', block)
