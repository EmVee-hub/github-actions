import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from provider_summary import render
from collect_inspector import normalize
from read_azure import normalize as normalize_azure

FIX = Path(__file__).parent / 'fixtures'


class ProviderSummaryTests(unittest.TestCase):
    def test_inspector_shows_normalized_findings(self):
        rows = normalize(json.loads((FIX / 'inspector-debug.json').read_text())['findings'])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'normalized-findings.json').write_text(json.dumps({'findings': rows}))
            result = render('inspector', path)
        self.assertIn('Normalized package findings: **4**', result)
        for row in rows:
            self.assertIn(row['vulnerability_id'], result)
        self.assertIn('not real CVEs', result)

    def test_defender_keeps_unresolved_and_missing_identity_visible(self):
        rows, unresolved = normalize_azure(json.loads((FIX / 'defender-sample.json').read_text()))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            for name, value in [('observations.json', rows), ('unresolved.json', unresolved), ('summary.json', {})]:
                (path / name).write_text(json.dumps(value))
            result = render('defender', path)
        self.assertIn('CVE-2021-44228', result)
        self.assertIn('Unresolved assessments: **1**', result)
        self.assertIn('Unknown | Unknown | INCOMPLETE', result)

    def test_empty_is_not_clean_and_provider_text_cannot_break_table(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'normalized-findings.json'
            path.write_text('{"findings": []}')
            self.assertIn('not a clean security verdict', render('inspector', path.parent))
            path.write_text(json.dumps({'findings': [{'vulnerability_id': '<b>x</b>|y\nz'}]}))
            self.assertIn('&lt;b&gt;x&lt;/b&gt;&#124;y z', render('inspector', path.parent))


if __name__ == '__main__':
    unittest.main()
