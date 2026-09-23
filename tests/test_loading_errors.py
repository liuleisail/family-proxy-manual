"""Execute the actual legacy page error handlers with failing API responses."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LoadingErrorsTests(unittest.TestCase):
    def run_javascript(self, source):
        result = subprocess.run(['node', '--input-type=module', '-e', source], capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_rules_failure_ends_loading(self):
        source = (ROOT / 'runtime/rules.html').read_text()
        start = source.index('    async function reloadRules()')
        function = source[start:source.index('\n', start)]
        result = self.run_javascript('''
const dirty=false, rules=[], countEl={}, statusEl={}, empty={};
const document={querySelector:()=>empty};
const api=async()=>{throw new Error('storage offline')};
function applyData(){throw new Error('must not apply failing response')}
function setStatus(message,ok){statusEl.message=message;statusEl.ok=ok}
''' + function + '''
await reloadRules();
console.log(JSON.stringify({count:countEl.textContent,empty:empty.innerHTML,...statusEl}));
''')
        self.assertEqual(result['count'], '读取失败')
        self.assertIn('重新载入', result['empty'])
        self.assertEqual(result['message'], 'storage offline')
        self.assertFalse(result['ok'])

    def test_filter_failure_is_visible_even_during_silent_refresh(self):
        source = (ROOT / 'runtime/mosdns/dashboard.html').read_text()
        function = source[source.index('    async function loadAdblock('):source.index('    async function pollAdblock(')]
        result = self.run_javascript('''
const state={}, elements={};
const $=id=>elements[id]||(elements[id]={});
const maintenanceApi=async()=>{throw new Error('storage offline')};
function toast(){throw new Error('silent refresh must not toast')}
''' + function + '''
await loadAdblock(true);console.log(JSON.stringify(elements));
''')
        self.assertEqual(result['#adblock-state']['textContent'], '读取失败')
        self.assertEqual(result['#adblock-state']['className'], 'pill error')
        self.assertIn('storage offline', result['#adblock-detail']['textContent'])
        self.assertNotIn('正在读取', result['#adblock-sources']['innerHTML'])
