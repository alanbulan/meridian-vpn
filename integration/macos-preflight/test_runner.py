import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import signal
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("macos_preflight", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PreflightEvidenceTests(unittest.TestCase):
    def events(self, tests):
        rows = [{"Action": "pass", "Package": runner.PACKAGE, "Test": t} for t in tests]
        rows.append({"Action": "pass", "Package": runner.PACKAGE})
        return ("\n".join(json.dumps(r) for r in rows) + "\n").encode()

    def test_complete_evidence(self):
        self.assertEqual(runner.verify_events(self.events([runner.ABI_TEST]), [runner.ABI_TEST]), [runner.ABI_TEST])
        required = [runner.ABI_TEST, runner.SERVICE_TEST]
        self.assertEqual(runner.verify_events(self.events(required), required), sorted(required))

    def test_missing_skipped_failed_wrong_package_and_oversized_fail(self):
        good = self.events([runner.ABI_TEST])
        cases = [b"", b"{}", b"[]", b"null", good.splitlines()[0], b"{" + b" " * runner.MAX_LOG_BYTES,
                 self.events([]), good.replace(b'"pass"', b'"skip"', 1),
                 good.replace(b'"pass"', b'"fail"', 1),
                 good.replace(runner.PACKAGE.encode(), b"other/package", 1),
                 good.replace(runner.ABI_TEST.encode(), b"TestUnexpected", 1)]
        for bad in cases:
            with self.subTest(length=len(bad)):
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    runner.verify_events(bad, [runner.ABI_TEST])
        with self.assertRaises(ValueError):
            runner.verify_events(good, [runner.ABI_TEST, runner.SERVICE_TEST])

    def test_non_darwin_never_launches(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Linux"), mock.patch.object(runner, "run_bounded") as launch:
            with self.assertRaises(RuntimeError):
                runner.execute("go", "abi", None, Path(tmp) / "report")
            launch.assert_not_called()
            self.assertFalse((Path(tmp) / "report").exists())

    def test_invalid_modes_and_service_ids_never_launch(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"), mock.patch.object(runner, "run_bounded") as launch:
            for mode, service in [("other", None), ("service", None), ("service", "x/y"), ("service", "a" * 128), ("abi", "private-service")]:
                with self.assertRaises(ValueError):
                    runner.execute("go", mode, service, Path(tmp) / "report")
            launch.assert_not_called()

    def test_failed_launch_writes_no_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"), mock.patch.object(runner, "run_bounded", side_effect=RuntimeError("private diagnostic")):
            report = Path(tmp) / "report"
            with self.assertRaises(RuntimeError):
                runner.execute("go", "service", "private-service", report)
            text = (report / "evidence.json").read_text()
            result = json.loads(text)
            self.assertEqual(result["result"], "failed")
            self.assertNotIn("private", text)
            self.assertFalse(result["live_vpn_verified"])

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "仅在 POSIX 平台检查进程组超时处理")
    def test_timeout_kills_only_child_group_and_reaps(self):
        proc = mock.Mock(pid=12345, returncode=None)
        proc.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 15), 0]
        with mock.patch.object(runner.subprocess, "Popen", return_value=proc) as launch, mock.patch.object(runner.os, "killpg") as kill:
            with self.assertRaises(RuntimeError):
                runner.run_bounded(["synthetic"], {}, 15)
            kill.assert_called_once_with(12345, signal.SIGKILL)
            self.assertEqual(proc.wait.call_count, 2)
            self.assertTrue(launch.call_args.kwargs["start_new_session"])

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "仅在 POSIX 平台检查进程组超时处理")
    def test_unconfirmed_termination_is_not_success(self):
        proc = mock.Mock(pid=12345, returncode=None)
        proc.wait.side_effect = subprocess.TimeoutExpired("synthetic", 15)
        with mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg"):
            with self.assertRaisesRegex(RuntimeError, "终止状态尚未确认"):
                runner.run_bounded(["synthetic"], {}, 15)

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "仅在 POSIX 平台检查进程组取消处理")
    def test_keyboard_interrupt_kills_and_reaps(self):
        proc = mock.Mock(pid=12345, returncode=None)
        proc.wait.side_effect = [KeyboardInterrupt(), 0]
        with mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg") as kill:
            with self.assertRaises(KeyboardInterrupt):
                runner.run_bounded(["synthetic"], {}, 15)
            kill.assert_called_once_with(12345, signal.SIGKILL)
            self.assertEqual(proc.wait.call_count, 2)

    def test_already_reaped_child_is_never_signaled(self):
        proc = mock.Mock(pid=12345, returncode=0)
        proc.wait.side_effect = KeyboardInterrupt()
        with mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg", create=True) as kill:
            with self.assertRaises(KeyboardInterrupt):
                runner.run_bounded(["synthetic"], {}, 15)
            kill.assert_not_called()

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "仅在 POSIX 平台检查终止失败")
    def test_kill_failure_is_uncertain(self):
        proc = mock.Mock(pid=12345, returncode=None)
        proc.wait.side_effect = subprocess.TimeoutExpired("synthetic", 15)
        with mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg", side_effect=PermissionError()):
            with self.assertRaisesRegex(RuntimeError, "退出状态尚未确认"):
                runner.run_bounded(["synthetic"], {}, 15)

    def test_existing_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"), mock.patch.object(runner, "run_bounded") as launch:
            report = Path(tmp) / "report"
            report.mkdir()
            marker = report / "evidence.json"
            marker.write_text("keep")
            with self.assertRaises(FileExistsError):
                runner.execute("go", "abi", None, report)
            self.assertEqual(marker.read_text(), "keep")
            launch.assert_not_called()

    def test_abi_clears_inherited_service_selection(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"), mock.patch.dict(runner.os.environ, {"MERIDIAN_MACOS_SERVICE_ID": "private-inherited-service"}):
            def launch(command, env, timeout):
                self.assertNotIn("MERIDIAN_MACOS_SERVICE_ID", env)
                if command[1] == "version":
                    return b"go version go1.27.3 darwin/arm64\n"
                if command[1] == "-C":
                    Path(command[command.index("-o") + 1]).write_bytes(b"synthetic")
                    return b""
                return self.events([runner.ABI_TEST])
            with mock.patch.object(runner, "run_bounded", side_effect=launch):
                self.assertEqual(runner.execute("go", "abi", None, Path(tmp) / "report")["result"], "passed")

    def test_build_uses_captured_source_not_changed_checkout(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"):
            root = Path(tmp) / "repo"
            source = root / "internal/macosvpn/example.go"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"package macosvpn\n")
            dependency = root / "internal/windowsvpn/example.go"
            dependency.parent.mkdir(parents=True)
            dependency.write_bytes(b"package windowsvpn\n")
            (root / "go.mod").write_bytes(b"module mygo-vpn\n")
            (root / "go.sum").write_bytes(b"")
            def launch(command, env, timeout):
                if command[1] == "version":
                    return b"go version go1.27.3 darwin/arm64\n"
                if command[1] == "-C":
                    source.write_bytes(b"changed checkout, not the build input")
                    dependency.write_bytes(b"changed dependency, not the build input")
                    self.assertEqual((Path(command[2]) / "internal/windowsvpn/example.go").read_bytes(), b"package windowsvpn\n")
                    self.assertEqual((Path(command[2]) / "internal/macosvpn/example.go").read_bytes(), b"package macosvpn\n")
                    Path(command[command.index("-o") + 1]).write_bytes(b"synthetic")
                    return b""
                return self.events([runner.ABI_TEST])
            with mock.patch.object(runner, "ROOT", root), mock.patch.object(runner, "run_bounded", side_effect=launch):
                result = runner.execute("go", "abi", None, Path(tmp) / "report")
            expected = runner.hashlib.sha256()
            for name, data in [("internal/macosvpn/example.go", b"package macosvpn\n"), ("internal/windowsvpn/example.go", b"package windowsvpn\n"), ("go.mod", b"module mygo-vpn\n"), ("go.sum", b"")]:
                expected.update(name.encode() + b"\x00" + data + b"\x00")
            self.assertEqual(result["source_sha256"], expected.hexdigest())

    def test_success_is_bound_to_binary_and_required_test(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.platform, "system", return_value="Darwin"):
            calls = []
            def launch(command, env, timeout):
                calls.append((command, env.copy(), timeout))
                if command[1] == "version":
                    return b"go version go1.27.3 darwin/arm64\n"
                if command[1] == "-C":
                    self.assertTrue((Path(command[2]) / "internal/macosvpn/native_smoke_darwin_test.go").is_file())
                    self.assertTrue((Path(command[2]) / "internal/windowsvpn/borrowed_session_other.go").is_file())
                    Path(command[command.index("-o") + 1]).write_bytes(b"synthetic test binary, never executed")
                    return b""
                self.assertEqual(env["MERIDIAN_MACOS_SERVICE_ID"], "private-service")
                return self.events([runner.ABI_TEST, runner.SERVICE_TEST])
            with mock.patch.object(runner, "run_bounded", side_effect=launch):
                result = runner.execute("go", "service", "private-service", Path(tmp) / "report")
            self.assertEqual(result["result"], "passed")
            self.assertEqual(len(result["test_binary_sha256"]), 64)
            self.assertEqual(len(result["source_sha256"]), 64)
            self.assertNotIn("MERIDIAN_MACOS_SERVICE_ID", calls[1][1])
            self.assertNotIn("private-service", json.dumps(result))
            self.assertEqual(calls[-1][2], 15)


if __name__ == "__main__":
    unittest.main()
