import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('collector', Path(__file__).parents[1] / 'scripts/collect_inspector.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def finding():
    return {'findingArn': 'arn:test:1', 'awsAccountId': '123456789012',
            'type': 'PACKAGE_VULNERABILITY', 'status': 'ACTIVE',
            'packageVulnerabilityDetails': {'vulnerabilityId': 'CVE-2025-0001',
                'vulnerablePackages': [{'name': 'pkg', 'version': '1', 'filePath': '/a'}]},
            'resources': [{'type': 'AWS_ECR_CONTAINER_IMAGE', 'id': 'image1',
                'region': 'eu-north-1', 'details': {'awsEcrContainerImage': {
                    'imageHash': 'sha256:' + 'a' * 64, 'architecture': 'amd64'}}}]}


class CollectorTests(unittest.TestCase):
    def test_pagination(self):
        with patch.object(c, 'aws', side_effect=[{'findings': [1], 'nextToken': 'next'}, {'findings': [2]}]) as api:
            self.assertEqual(c.pages('eu-north-1', 'list-findings', 'findings'), [1, 2])
            self.assertEqual(api.call_args.args[-2:], ('--next-token', 'next'))

    def test_repeated_token_rejected(self):
        with patch.object(c, 'aws', return_value={'findings': [], 'nextToken': 'same'}):
            with self.assertRaises(ValueError):
                c.pages('eu-north-1', 'list-findings', 'findings')

    def test_missing_array_rejected(self):
        with patch.object(c, 'aws', return_value={}):
            with self.assertRaises(ValueError):
                c.pages('eu-north-1', 'list-findings', 'findings')

    def test_runtime_unknown_zero_and_positive_distinct(self):
        f = finding()
        for count, state in [(None, 'UNKNOWN'), (0, 'NOT_REPORTED_IN_USE'), (2, 'REPORTED_IN_USE')]:
            f['resources'][0]['details']['awsEcrContainerImage']['inUseCount'] = count
            row = c.normalize([f])[0]
            self.assertEqual(row['runtime']['state'], state)
            self.assertIsNone(row['prod_critical'])

    def test_suppression_not_vex_and_exploit_not_kev(self):
        f = finding()
        f.update(status='SUPPRESSED', exploitAvailable='YES', epss={'score': 0.9})
        row = c.normalize([f])[0]
        self.assertEqual(row['provider_status'], 'SUPPRESSED')
        self.assertEqual(row['vex_status'], 'NOT_EVALUATED')
        self.assertIsNone(row['kev'])
        self.assertIsNone(row['epss_percentile'])

    def test_package_paths_and_architecture_preserved(self):
        f = finding()
        other = copy.deepcopy(f)
        other['resources'][0]['details']['awsEcrContainerImage']['architecture'] = 'arm64'
        f['packageVulnerabilityDetails']['vulnerablePackages'].append({'name': 'pkg', 'version': '1', 'filePath': '/b'})
        rows = c.normalize([f, other])
        self.assertEqual(len({r['observation_id'] for r in rows}), 3)

    def test_host_is_separate_asset(self):
        f = finding()
        f['resources'] = [{'type': 'AWS_EC2_INSTANCE', 'id': 'i-123', 'region': 'eu-north-1'}]
        row = c.normalize([f])[0]
        self.assertEqual(row['runtime']['state'], 'HOST_REQUIRES_INVENTORY')
        self.assertIsNone(row['asset']['image_digest'])

    def test_failure_manifest_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'report'
            with patch.object(c, 'aws', return_value={'Account': '123456789012'}), patch.object(c, 'pages', side_effect=RuntimeError('denied')):
                with self.assertRaises(RuntimeError):
                    c.collect('eu-north-1', out)
            self.assertFalse(json.loads((out / 'manifest.json').read_text())['collection_complete'])

    def test_success_is_collection_not_policy_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'report'
            with patch.object(c, 'aws', return_value={'Account': '123456789012'}), patch.object(c, 'pages', side_effect=[[finding()], []]):
                c.collect('eu-north-1', out)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertTrue(manifest['collection_complete'])
            self.assertFalse(manifest['policy_evaluated'])


if __name__ == '__main__':
    unittest.main()
