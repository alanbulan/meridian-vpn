import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("linux_package", Path(__file__).with_name("package-linux.py"))
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


class LinuxPackageTests(unittest.TestCase):
    def test_external_workspace_and_goenv_are_disabled(self):
        with mock.patch.dict(pkg.os.environ, {"GOWORK": "/external/go.work", "GOENV": "/external/goenv", "GOFLAGS": "", "GOEXPERIMENT": "", "OPENCONNECT_STAGE": ""}):
            env = pkg.build_environment(123)
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOAMD64"], "v1")
        self.assertEqual(env["SOURCE_DATE_EPOCH"], "123")

    def test_archive_determinism_and_modes(self):
        files = {"b": (b"binary", 0o755), "a": (b"notice", 0o644)}
        a = pkg.archive_bytes(files, 123)
        self.assertEqual(a, pkg.archive_bytes(dict(reversed(list(files.items()))), 123))
        with tarfile.open(fileobj=io.BytesIO(a), mode="r:gz") as tar:
            self.assertEqual(tar.getnames(), ["a", "b"])
            for member in tar:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 123))
                self.assertEqual(member.mode, files[member.name][1])
                self.assertEqual(tar.extractfile(member).read(), files[member.name][0])

    def test_unsafe_members_rejected(self):
        for path in ["/absolute", "../escape", "a/../b", "a//b", "./x"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                pkg.archive_bytes({path: (b"x", 0o644)}, 0)

    def test_input_files_reject_symlinks_empty_and_directories(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "empty").touch()
            (root / "link").symlink_to(root / "empty")
            for p in [root, root / "empty", root / "link"]:
                with self.subTest(path=p), self.assertRaises(ValueError):
                    pkg.checked_file(p)

    def test_versions_reject_shell_and_path_payloads(self):
        for value in ["v1.0.0", "1.0", "1.0.0;id", "../1.0.0", "1.0.0\n", "01.0.0", ""]:
            self.assertIsNone(pkg.VERSION.fullmatch(value))
        for value in ["0.1.0-alpha.1", "1.2.3", "1.2.3-rc.2"]:
            self.assertIsNotNone(pkg.VERSION.fullmatch(value))

    def test_invalid_version_and_existing_output_fail_before_build(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "existing"
            out.write_text("unchanged")
            for version in ["1.2.3", "bad"]:
                with self.assertRaises(ValueError):
                    pkg.package(version, out, go="must-not-execute")
            self.assertEqual(out.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
