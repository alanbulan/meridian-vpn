import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('loopback_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class EvidenceTests(unittest.TestCase):
    def check_events(self, events):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            path.write_text(''.join(json.dumps(e) + '\n' for e in events))
            return runner.verify_auth_results(path)

    def good(self):
        return ([{'Action': 'pass', 'Package': package, 'Test': test}
                 for package, test in sorted(runner.AUTH_REQUIRED)]
                + [{'Action': 'pass', 'Package': package}
                   for package in sorted(runner.AUTH_PACKAGES)])

    def test_all_required_fixtures_pass(self):
        self.assertEqual(self.check_events(self.good()), 21)

    def test_empty_or_partial_or_missing_package_fails(self):
        for events in ([], self.good()[1:], self.good()[:-1]):
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                self.check_events(events)

    def test_skipped_or_failed_subtest_is_not_pass(self):
        for action in ('skip', 'fail'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.check_events(self.good() + [{'Action': action, 'Test': 'TestRealMFAClientCertificate/PEM'}])

    def test_wrong_package_is_not_completion(self):
        with self.assertRaises(ValueError):
            self.check_events(self.good()[:-1] + [{'Action': 'pass', 'Package': 'another/package'}])

    def test_test_pass_from_wrong_package_is_not_evidence(self):
        events = self.good()
        events[0] = dict(events[0], Package='another/package')
        with self.assertRaises(ValueError):
            self.check_events(events)

    def test_missing_cli_fixture_is_not_success(self):
        events = [e for e in self.good() if e.get('Test') != 'TestRealCLIMFAChallengeRetry']
        with self.assertRaises(ValueError):
            self.check_events(events)

    def test_malformed_json_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.jsonl'
            path.write_text('{truncated')
            with self.assertRaises(ValueError):
                runner.verify_auth_results(path)


if __name__ == '__main__':
    unittest.main()
