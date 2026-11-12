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
    def test_offline_never_calls_aws_and_matches_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'findings.json'
            source.write_text(json.dumps({'findings': [finding()]}))
            out = Path(tmp) / 'report'
            with patch.object(c, 'aws', side_effect=AssertionError('AWS must not run')), patch.object(c, 'pages', side_effect=AssertionError('API must not run')):
                c.collect(None, out, source)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertTrue(manifest['collection_complete'])
            self.assertFalse(manifest['live_aws_data'])
            self.assertFalse(manifest['coverage_supplied'])
            rows = json.loads((out / 'normalized-findings.json').read_text())['findings']
            self.assertEqual(rows[0].pop('input_mode'), 'offline')
            self.assertEqual(rows, c.normalize([finding()]))

    def test_offline_empty_findings_with_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, coverage, out = (Path(tmp) / name for name in ['input.json', 'coverage.json', 'out'])
            source.write_text('{"findings": []}')
            coverage.write_text('{"coveredResources": [{"resourceId": "debug"}]}')
            with patch.object(c, 'aws', side_effect=AssertionError('AWS must not run')):
                c.collect(None, out, source, coverage)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(manifest['normalized_count'], 0)
            self.assertEqual(manifest['coverage_count'], 0)  # no ECR resourceType in this fixture
            self.assertTrue(manifest['coverage_supplied'])

    def test_invalid_offline_input_fails_without_fallback(self):
        for payload in ['broken json', '[]', '{}', '{"findings": [null]}', '{"findings": [], "nextToken": "more"}']:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                source, out = Path(tmp) / 'input.json', Path(tmp) / 'out'
                source.write_text(payload)
                with patch.object(c, 'aws', side_effect=AssertionError('AWS must not run')):
                    with self.assertRaises(ValueError):
                        c.collect(None, out, source)
                self.assertFalse(json.loads((out / 'manifest.json').read_text())['collection_complete'])

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

    def test_host_is_out_of_scope(self):
        f = finding()
        f['resources'] = [{'type': 'AWS_EC2_INSTANCE', 'id': 'i-123', 'region': 'eu-north-1'}]
        self.assertEqual(c.normalize([f]), [])

    def test_cloud_collector_discards_host_and_other_finding_types(self):
        ec2 = finding()
        ec2['resources'] = [{'type': 'AWS_EC2_INSTANCE', 'id': 'i-123', 'region': 'eu-north-1'}]
        other = finding()
        other['type'] = 'NETWORK_REACHABILITY'
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'in.json'
            out = Path(tmp) / 'out'
            source.write_text(json.dumps({'findings': [finding(), ec2, other]}))
            c.collect(None, out, source)
            retained = json.loads((out / 'raw-findings.json').read_text())['findings']
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]['type'], 'PACKAGE_VULNERABILITY')
            self.assertEqual(retained[0]['resources'][0]['type'], c.ECR_TYPE)

    def test_online_uses_ecr_only_filter(self):
        with patch.object(c, 'aws', return_value={'findings': []}) as api:
            c.pages('eu-north-1', 'list-findings', 'findings')
            args = api.call_args.args[3:]
            self.assertIn('--filter-criteria', args)
            filter_value = json.loads(args[args.index('--filter-criteria') + 1])
            self.assertEqual(filter_value, c.ECR_FINDING_FILTER)

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
