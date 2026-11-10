"""Execution gates must require complete, identical real-source inputs.

All sources here are synthetic in-memory fixtures; no Wazuh connection.
"""
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import m1_h03_live_manager_indexer_audit as audit

EXPECTED = {'audit_after_utc': '2026-11-10T21:08:00Z', 'sha256_v1': 'a'*64, 'sha256_v2': 'b'*64}


def event(kind='added'):
    return {'id': 'synthetic-unique', 'timestamp': '2026-11-10T21:10:00.001+0000',
            'agent': {'id': '004'}, 'rule': {'id': '554' if kind == 'added' else '550'},
            'syscheck': {'path': r'C:\SecurityLab\H03\H03-BenignProbe.exe',
                         'event': kind, 'sha256_after': EXPECTED['sha256_v1'] if kind == 'added' else EXPECTED['sha256_v2'],
                         'sha256_before': EXPECTED['sha256_v1'] if kind == 'modified' else '',
                         'uname_after': 'synthetic-operator'}}


class AuditGates(unittest.TestCase):
    def run_audit(self, manager, indexer, failed=0, timeout=False, total=None):
        result = {'hits': {'hits': [{'_source': item} for item in indexer],
                           'total': {'relation': 'eq', 'value': len(indexer) if total is None else total}},
                  '_shards': {'failed': failed}, 'timed_out': timeout}
        content = ''.join(json.dumps(item)+'\n' for item in manager)
        environment = {'INDEXER_URL': 'https://synthetic.invalid:9200', 'INDEXER_USERNAME': 'fixture',
                       'INDEXER_PASSWORD': 'fixture', 'SSL_CERTIFICATE_AUTHORITIES': 'fixture.pem'}
        with patch('builtins.open', return_value=io.StringIO(content)), \
             patch.dict(audit.os.environ, environment), \
             patch.object(audit.ssl, 'create_default_context'), \
             patch.object(audit.urllib.request, 'urlopen', return_value=io.StringIO(json.dumps(result))):
            return audit.run(EXPECTED)

    def test_empty_equal_sources_do_not_release_any_execution_gate(self):
        result = self.run_audit([], [])
        self.assertFalse(result['baseline_ok'])
        self.assertFalse(result['modified_ok'])

    def test_exact_baseline_releases_only_baseline_gate(self):
        item = event()
        result = self.run_audit([item], [item])
        self.assertTrue(result['baseline_ok'])
        self.assertFalse(result['modified_ok'])

    def test_exact_modified_hash_chain_releases_modify_gate(self):
        item = event('modified')
        self.assertTrue(self.run_audit([item], [item])['modified_ok'])

    def test_wrong_before_hash_never_releases_modify_gate(self):
        item = event('modified')
        item['syscheck']['sha256_before'] = 'c'*64
        self.assertFalse(self.run_audit([item], [item])['modified_ok'])

    def test_duplicate_manager_record_is_not_silently_collapsed(self):
        item = event()
        result = self.run_audit([item, item], [item])
        self.assertFalse(result['manager_indexer_exact'])
        self.assertFalse(result['baseline_ok'])

    def test_changed_source_identity_does_not_release_gate(self):
        item = event()
        changed = copy.deepcopy(item)
        changed['id'] = 'different-source-event'
        self.assertFalse(self.run_audit([item], [changed])['baseline_ok'])

    def test_incomplete_queries_never_release_gate(self):
        item = event()
        for options in ({'failed': 1}, {'timeout': True}, {'total': 1001}):
            with self.subTest(options=options):
                self.assertFalse(self.run_audit([item], [item], **options)['baseline_ok'])

    def test_missing_actor_on_modified_event_is_rejected(self):
        item = event('modified')
        del item['syscheck']['uname_after']
        with self.assertRaises(ValueError):
            self.run_audit([item], [item])
