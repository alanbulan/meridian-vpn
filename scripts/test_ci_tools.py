import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


summary = module("ci-summary")
manifest = module("build-manifest")


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "tests.jsonl"

    def events(self, events):
        self.path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        return summary.summarize(self.path)

    def test_missing_empty_and_malformed_are_unverified(self):
        self.assertFalse(summary.summarize(self.path)[1])
        self.assertFalse(self.events([])[1])
        self.path.write_text("not JSON\n[]\n", encoding="utf-8")
        self.assertFalse(summary.summarize(self.path)[1])

    def test_package_compile_failure_without_test_event(self):
        text, ok = self.events([{"Package": "example/core", "Action": "fail"}])
        self.assertFalse(ok)
        self.assertIn("Failed package: example/core", text)
        self.assertIn("0 passed, 1 failed, 0 skipped", text)

    def test_truncated_package_is_not_pass(self):
        text, ok = self.events([{"Package": "example/core", "Action": "start"}, {"Package": "example/core", "Test": "TestOne", "Action": "pass"}])
        self.assertFalse(ok)
        self.assertIn("Incomplete package", text)

    def test_skips_remain_visible(self):
        text, ok = self.events([{"Package": "core", "Test": "TestLive", "Action": "skip"}, {"Package": "core", "Action": "pass"}, {"Package": "cli", "Action": "skip"}])
        self.assertTrue(ok)
        self.assertIn("0 passed, 0 failed, 1 skipped", text)
        self.assertIn("core: TestLive", text)

    def test_individual_failure_is_not_pass(self):
        self.assertFalse(self.events([{"Package": "core", "Test": "TestOne", "Action": "fail"}, {"Package": "core", "Action": "pass"}])[1])


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def binary(self, target):
        data = bytearray(128)
        if target == "linux-amd64":
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 62)
        elif target == "darwin-arm64":
            data[:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<I", data, 4, 0x0100000C)
        else:
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<H", data, 68, 0x8664)
        return bytes(data)

    def prepare(self, target):
        for base in ("meridian", "meridianctl"):
            (self.root / (base + manifest.TARGETS[target])).write_bytes(self.binary(target))

    def test_all_targets_and_deterministic_checksums(self):
        for target in manifest.TARGETS:
            with self.subTest(target=target):
                self.prepare(target)
                data = manifest.write_manifest(self.root, target, "a" * 40)
                before = (self.root / "build-manifest.json").read_bytes()
                manifest.write_manifest(self.root, target, "a" * 40)
                self.assertEqual(before, (self.root / "build-manifest.json").read_bytes())
                self.assertEqual(data["source_commit"], "a" * 40)
                for row in data["files"]:
                    self.assertIn(row["sha256"] + "  " + row["name"], (self.root / "SHA256SUMS").read_text())

    def test_wrong_target_does_not_produce_manifest(self):
        self.prepare("linux-amd64")
        with self.assertRaises(ValueError):
            manifest.write_manifest(self.root, "darwin-arm64", "a" * 40)
        self.assertFalse((self.root / "build-manifest.json").exists())

    def test_invalid_commit_and_target(self):
        for target, commit in [("linux-amd64", "main"), ("linux-arm64", "a" * 40), ("linux-amd64", "A" * 40)]:
            with self.assertRaises(ValueError):
                manifest.write_manifest(self.root, target, commit)

    def test_missing_binary_fails(self):
        with self.assertRaises(OSError):
            manifest.write_manifest(self.root, "linux-amd64", "a" * 40)

    def test_symlink_is_rejected(self):
        self.prepare("linux-amd64")
        target = self.root / "meridian"
        target.rename(self.root / "real")
        try:
            target.symlink_to(self.root / "real")
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            manifest.write_manifest(self.root, "linux-amd64", "a" * 40)

    def test_truncated_and_overflow_pe_headers(self):
        self.assertFalse(manifest.check_target(b"MZ", "windows-amd64"))
        data = bytearray(self.binary("windows-amd64"))
        struct.pack_into("<I", data, 60, 0xFFFFFFFF)
        self.assertFalse(manifest.check_target(data, "windows-amd64"))


if __name__ == "__main__":
    unittest.main()
