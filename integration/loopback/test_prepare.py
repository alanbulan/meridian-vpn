"""Regression: patches must apply inside a destination nested under a Git repo."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PreparationTests(unittest.TestCase):
    def test_nested_checkout_applies_every_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            destination = root / 'build' / 'native'
            # Deliberately hostile inherited Git routing must not redirect patches.
            env = dict(os.environ, GIT_DIR=str(root / '.git'), GIT_WORK_TREE=str(root))
            subprocess.run([sys.executable,
                            str(ROOT / 'integration/univpn-native/scripts/prepare_native.py'),
                            '--archive', str(ROOT / 'integration/univpn-native/source/openconnect-upstream.tar.gz'),
                            '--destination', str(destination)], env=env, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertIn('lib_srcs_univpn', (destination / 'Makefile.am').read_text())
            self.assertTrue((destination / 'tests/univpn-packet-integration.py').is_file())
            self.assertTrue((destination / 'tests/univpn-fd-cleanup.c').is_file())
            self.assertIn('publication notices added', (destination / 'univpn.c').read_text())
            self.assertFalse((root / 'univpn.c').exists())


if __name__ == '__main__':
    unittest.main()
