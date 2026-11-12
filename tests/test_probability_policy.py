import copy
import json
import tempfile
import unittest
from pathlib import Path
from test_evaluate import ev, BASE, AMP, ROOT


class ProbabilityPolicyTests(unittest.TestCase):
    def test_config_changes_behavior(self):
        policy = copy.deepcopy(AMP)
        policy["probability_policy"]["non_kev"]["thresholds"][0]["minimum_probability"] = .20
        self.assertEqual(ev.poc_priority("3D", "N", .15, policy)[0], "60D")
        self.assertEqual(ev.poc_priority("3D", "N", .15, AMP)[0], "30D")

    def test_boundaries_and_kev(self):
        for score, target in [(None, "FSU"), (.04999, "FSU"), (.05, "60D"),
                              (.09999, "60D"), (.10, "30D"), (1, "30D")]:
            self.assertEqual(ev.poc_priority("3D", "N", score, AMP)[0], target)
        self.assertEqual(ev.poc_priority("14D", "Y", None, AMP)[0], "3D")
        self.assertEqual(ev.poc_priority("3DF", "Y", 0, AMP)[0], "3DF")

    def test_invalid_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bod-26-04.json").write_text(json.dumps(BASE))
            policy = copy.deepcopy(AMP)
            policy["probability_policy"]["non_kev"]["thresholds"].reverse()
            (root / "epss-amplifier.json").write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                ev.load_policy(root)
