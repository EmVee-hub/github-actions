import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cloud_showcase import run, ROOT


class CloudShowcaseTests(unittest.TestCase):
    def test_connected_all_and_single_provider_scenarios(self):
        for scenario, expected in [('all', {'AWS_INSPECTOR', 'AZURE_DEFENDER'}),
                                   ('inspector', {'AWS_INSPECTOR'}), ('defender', {'AZURE_DEFENDER'})]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'result'
                result = run(out, scenario)
                active = [r for r in result['observations'] if r['decision_status'] == 'EVALUATED']
                self.assertEqual({r['source'] for r in active}, expected)
                by_workload = {r['workload']: r for r in result['observations']}
                if 'AWS_INSPECTOR' in expected:
                    self.assertEqual(by_workload['payments-abc']['final_outcome'], '3D')
                    self.assertEqual(result['excluded_by_reason']['NO_EXACT_RUNTIME_MATCH'], 1)
                    raw = json.loads((out / 'inspector/normalized-findings.json').read_text())
                    self.assertNotIn('purl', raw['findings'][0]['package'])
                if 'AZURE_DEFENDER' in expected:
                    self.assertEqual(by_workload['customer-api-abc']['final_outcome'], '3DF')
                    self.assertEqual(by_workload['internal-tools-abc']['decision_status'], 'SUPPRESSED_BY_VEX')
                    self.assertEqual(result['excluded_by_reason']['IMAGE_IDENTITY_INCOMPLETE'], 1)
                    self.assertEqual(len(json.loads((out / 'defender/unresolved.json').read_text())), 1)
                    self.assertIsNone(json.loads((out / 'defender/observations.json').read_text())[0]['image_digest'])
                self.assertIn('synthetic identity map', (out / 'report.md').read_text())

    def test_without_identity_map_no_fabricated_policy_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'empty.json').write_text('{}')
            result = run(path / 'out', identity_map=path / 'empty.json')
            self.assertEqual(result['counts'], {'REVIEW_REQUIRED': 2})
            self.assertEqual(result['excluded_by_reason']['IMAGE_IDENTITY_INCOMPLETE'], 3)

    def test_raw_provider_status_change_reaches_evaluator(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            fixtures = ROOT / 'tests/fixtures/cloud-showcase'
            raw = json.loads((fixtures / 'inspector-raw.json').read_text())
            raw['findings'][0]['status'] = 'CLOSED'
            (path / 'inspector-raw.json').write_text(json.dumps(raw))
            (path / 'synthetic-identity-map.json').write_text((fixtures / 'synthetic-identity-map.json').read_text())
            result = run(path / 'out', 'inspector', fixture=path)
            row = next(r for r in result['observations'] if r['workload'] == 'payments-abc')
            self.assertEqual(row['decision_status'], 'REVIEW_REQUIRED')
            self.assertIn('PROVIDER_STATUS_NOT_ACTIVE', row['reasons'])


if __name__ == '__main__':
    unittest.main()
