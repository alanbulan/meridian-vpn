import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('deb', Path(__file__).with_name('package-linux-deb.py'))
deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deb)

class DebianPackageTests(unittest.TestCase):
    def test_bad_archive_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'bad'; p.write_bytes(b'not a release')
            with self.assertRaises(ValueError): deb.read_archive(p)

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'existing'; p.write_bytes(b'keep')
            with self.assertRaises(ValueError): deb.package(Path('/missing'), p, 'a' * 40)
            self.assertEqual(p.read_bytes(), b'keep')

    def test_invalid_provenance_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError): deb.package(Path('/missing'), Path(tmp) / 'out', 'unknown')

if __name__ == '__main__': unittest.main()
