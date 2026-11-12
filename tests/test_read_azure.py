import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile
import json
import io

spec = importlib.util.spec_from_file_location('collector', Path(__file__).resolve().parents[1] / 'scripts/read_azure.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SUB = '11111111-1111-1111-1111-111111111111'


def row(identity='a', cves=None):
    return {'id': identity, 'subscriptionId': SUB, 'properties': {'additionalData': {'CvesDetails': cves}}}


class CollectorTests(unittest.TestCase):
    def test_offline_main_never_calls_azure(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'output'
            source = Path(__file__).parent / 'fixtures/defender-sample.json'
            with patch('sys.argv', ['read_azure', '--input', str(source), '--out', str(output)]), patch.object(c, 'collect', side_effect=AssertionError('Azure called')), patch.object(c.subprocess, 'run', side_effect=AssertionError('CLI called')), patch.dict(c.os.environ, {}, clear=True):
                self.assertEqual(c.main(), 0)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['mode'], 'DEBUG_OFFLINE')
            self.assertEqual(summary['observation_count'], 1)
            self.assertEqual(summary['unresolved_count'], 1)
            self.assertEqual(summary['policy_evaluation'], 'NOT_EVALUATED')

    def test_offline_stdin_forms(self):
        item = row(cves=[{'CveId': 'CVE-2021-44228'}])
        for payload in (item, [item], {'data': [item]}, []):
            with patch('sys.stdin', io.StringIO(json.dumps(payload))):
                self.assertEqual(c.load_input(Path('-')), [] if payload == [] else [item])

    def test_offline_rejects_bad_or_partial_input(self):
        for payload in ({'data': [], '$skipToken': 'next'}, {'data': [], 'resultTruncated': True}, [row(), row()], [None], {'arbitrary': 1}):
            with patch('sys.stdin', io.StringIO(json.dumps(payload))), self.assertRaises(ValueError):
                c.load_input(Path('-'))

    def test_invalid_json_fails_with_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'output'
            with patch('sys.argv', ['read_azure', '--input', '-', '--out', str(output)]), patch('sys.stdin', io.StringIO('{bad')), patch('sys.stderr', io.StringIO()):
                self.assertEqual(c.main(), 1)
            self.assertEqual(json.loads((output / 'summary.json').read_text())['collection_status'], 'INCOMPLETE')

    def test_pagination(self):
        requests = []
        def send(body):
            requests.append(body)
            if len(requests) == 1:
                return {'data': [row()], 'count': 1, '$skipToken': 'next', 'resultTruncated': 'true'}
            return {'data': [row('b')], 'count': 1}
        self.assertEqual(len(c.collect(SUB, 'query', send)), 2)
        self.assertEqual(requests[1]['options']['$skipToken'], 'next')

    def test_truncated_without_token_fails(self):
        with self.assertRaises(ValueError):
            c.collect(SUB, 'q', lambda _: {'data': [], 'count': 0, 'resultTruncated': True})

    def test_duplicate_pages_fail(self):
        with self.assertRaises(ValueError):
            c.collect(SUB, 'q', lambda _: {'data': [row()], 'count': 1, '$skipToken': 'again'})

    def test_other_subscription_fails(self):
        item = row()
        item['subscriptionId'] = 'other'
        with self.assertRaises(ValueError):
            c.collect(SUB, 'q', lambda _: {'data': [item], 'count': 1})

    def test_empty_response_is_only_empty_collection(self):
        self.assertEqual(c.collect(SUB, 'q', lambda _: {'data': [], 'count': 0}), [])

    def test_unrecognized_cves_retained(self):
        observations, unresolved = c.normalize([row(cves='{bad')])
        self.assertEqual(observations, [])
        self.assertEqual(len(unresolved), 1)

    def test_string_cves_preserve_unknown_identity(self):
        observations, unresolved = c.normalize([row(cves='[{"CveId":"CVE-2025-1234"}]')])
        self.assertEqual(unresolved, [])
        self.assertEqual(observations[0]['decision'], 'INCOMPLETE')
        self.assertIsNone(observations[0]['runtime_confirmed'])
        self.assertIsNone(observations[0]['image_digest'])

    def test_subscription_validation(self):
        for value in ['[]', '{}', '["not-a-uuid"]']:
            with self.assertRaises((ValueError, TypeError)):
                c.subscriptions(value)


if __name__ == '__main__':
    unittest.main()

