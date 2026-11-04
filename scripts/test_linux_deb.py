import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io

spec = importlib.util.spec_from_file_location('deb', Path(__file__).with_name('package-linux-deb.py'))
deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deb)

font_spec = importlib.util.spec_from_file_location('fonts', Path(__file__).with_name('check-linux-fonts.py'))
fonts = importlib.util.module_from_spec(font_spec)
font_spec.loader.exec_module(fonts)

class DebianPackageTests(unittest.TestCase):
    def test_required_chinese_fallback_without_recommends(self):
        fields = dict(line.split(': ', 1) for line in deb.control_metadata(123).splitlines() if ': ' in line)
        self.assertIn('fonts-noto-cjk', [x.strip() for x in fields['Depends'].split(',')])
        self.assertEqual(fields['Version'], '0.1.0~alpha.1-2')
        self.assertEqual(fields['Installed-Size'], '123')
        self.assertNotIn('network-manager', fields['Depends'])

    def test_font_probe_requires_real_coverage(self):
        for result in (1, 16, -1):
            with self.subTest(result=result), patch.object(fonts, 'unknown_glyphs', return_value=result), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fonts.main(), 1)
        with patch.object(fonts, 'unknown_glyphs', side_effect=OSError('missing Pango')), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fonts.main(), 1)
        with patch.object(fonts, 'unknown_glyphs', return_value=0) as probe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fonts.main(), 0)
            self.assertEqual(probe.call_count, 2)
            for call, font in zip(probe.call_args_list, fonts.FONTS):
                self.assertEqual(call.args, (fonts.LABELS, font))
                self.assertIn('连接', call.args[0])

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
