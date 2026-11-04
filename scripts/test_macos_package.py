import importlib.util
import json
import os
import hashlib
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest import mock
SPEC = importlib.util.spec_from_file_location("package_macos", Path(__file__).with_name("package-macos.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
class MacOSPackageTests(unittest.TestCase):
    def binary(self, cpu=0x0100000C, kind=2):
        return struct.pack("<IIIIIIII", 0xfeedfacf, cpu, 0, kind, 0, 0, 0, 0)
    def test_architecture_and_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"bin"
            for cpu,arch in [(0x0100000C,"arm64"),(0x01000007,"amd64")]:
                p.write_bytes(self.binary(cpu))
                self.assertEqual(m.executable_bytes(p,arch),p.read_bytes())
                with self.assertRaises(ValueError):m.executable_bytes(p,"invalid")
            p.write_bytes(self.binary(kind=6))
            with self.assertRaises(ValueError):m.executable_bytes(p,"arm64")
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/"bin";p.write_bytes(self.binary());link=root/"link";link.symlink_to(p)
            with self.assertRaises(ValueError):m.executable_bytes(link,"arm64")
    def test_bundle_only_expected_files_and_preview_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);bins=root/"bin";bins.mkdir();stage=root/"stage";stage.mkdir()
            for name in m.BINARIES:(bins/name).write_bytes(self.binary())
            with mock.patch.object(Path,"chmod",autospec=True,side_effect=Path.chmod) as chmod:
                app=m.stage_bundle(bins,stage,"arm64")
            chmod.assert_has_calls([mock.call(app/"Contents"/p,0o755) for p in m.BINARIES.values()],any_order=True)
            info=plistlib.loads((app/"Contents/Info.plist").read_bytes())
            self.assertEqual(info["CFBundleName"],"Meridian Preview")
            self.assertEqual(info["CFBundleExecutable"],"meridian")
            self.assertEqual(info["LSMinimumSystemVersion"],"15.0")
            self.assertTrue((app/"Contents/Resources/Notices/THIRD_PARTY.md").is_file())
            self.assertTrue((app/"Contents/Resources/Notices/MYGO-LICENSE.txt").is_file())
            self.assertTrue((app/"Contents/Resources/Notices/LUCIDE-LICENSE").is_file())
            self.assertEqual(len(list((app/"Contents/Resources/Notices/GoDependencies").rglob("*"))), len(list((m.ROOT/"docs/third-party").rglob("*"))))
            # Windows chmod cannot represent POSIX executable bits. Keep the
            # actual permission assertion on POSIX; all hosts verify chmod calls.
            if os.name != "nt":
                self.assertTrue(all((app/"Contents"/p).stat().st_mode & 0o111 for p in m.BINARIES.values()))
    def test_non_darwin_never_runs_tools(self):
        with mock.patch.object(m.platform,"system",return_value="Linux"),mock.patch.object(m,"invoke") as invoke:
            with self.assertRaises(ValueError):m.package(Path("x"),Path("y"),"arm64","a"*40,Path("z"))
            invoke.assert_not_called()
    def test_abi_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"evidence.json"
            for data in ['{}','[]','{"result":"passed"}']:
                p.write_text(data)
                with self.assertRaises(ValueError):m.validate_abi(p,"arm64")
    def test_abi_matches_exact_source_and_architecture(self):
        source_hash=hashlib.sha256()
        for source in sorted((m.ROOT/"internal/macosvpn").glob("*.go"))+sorted((m.ROOT/"internal/core").glob("*.go"))+[m.ROOT/"go.mod",m.ROOT/"go.sum"]:
            source_hash.update(source.relative_to(m.ROOT).as_posix().encode()+b"\x00"+source.read_bytes()+b"\x00")
        evidence={"schema":1,"mode":"abi","platform":"Darwin","result":"passed","stage":"complete","network_changes":False,"live_vpn_verified":False,"tests_passed":["TestMacOSReadOnlyABI"],"architecture":"arm64","source_sha256":source_hash.hexdigest(),"test_binary_sha256":"a"*64}
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"evidence.json";p.write_text(json.dumps(evidence))
            captured=m.validate_abi(p,"arm64")
            self.assertEqual(captured,p.read_bytes())
            with self.assertRaises(ValueError):m.validate_abi(p,"amd64")
            evidence["source_sha256"]="b"*64;p.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError):m.validate_abi(p,"arm64")
            self.assertNotEqual(captured,p.read_bytes())
    def test_nested_helpers_signed_before_main_and_bundle(self):
        with mock.patch.object(m,"invoke") as invoke:
            m.sign_bundle(Path("Preview.app"))
            calls=[c.args[0] for c in invoke.call_args_list]
            self.assertEqual(len(calls),6)
            self.assertEqual({Path(c[-1]) for c in calls[:3]}, {Path("Preview.app")/"Contents"/"Helpers"/name for name in ("meridianctl","meridian-macos-inspect","meridian-macos-service")})
            self.assertEqual(Path(calls[3][-1]),Path("Preview.app")/"Contents"/"MacOS"/"meridian")
            self.assertEqual(calls[4][-1],"Preview.app")
            self.assertEqual(calls[5][1:4],["--verify","--deep","--strict"])
    def test_missing_input_does_not_create_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaises(FileNotFoundError):m.stage_bundle(root,root,"arm64")
            self.assertFalse((root/m.APP).exists())
if __name__=="__main__":unittest.main()
