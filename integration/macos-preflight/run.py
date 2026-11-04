#!/usr/bin/env python3
"""macOS 原生只读预检：独立进程、固定测试、失败关闭，不操作 VPN。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ABI_TEST = "TestMacOSReadOnlyABI"
SERVICE_TEST = "TestMacOSExistingServicePreflight"
PACKAGE = "mygo-vpn/internal/macosvpn"
MAX_LOG_BYTES = 1024 * 1024


def verify_events(data, required):
    if len(data) > MAX_LOG_BYTES:
        raise ValueError("预检记录超过大小限制")
    passed = set()
    package_passed = False
    for line in data.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("预检记录不是 JSON 对象")
        if event.get("Package") != PACKAGE:
            raise ValueError("预检记录的包标识不匹配")
        action = event.get("Action")
        test = event.get("Test")
        if test is not None and (not isinstance(test, str) or not any(test == name or test.startswith(name + "/") for name in required)):
            raise ValueError("预检记录包含未请求的测试")
        if action in ("fail", "skip"):
            raise ValueError("预检失败或被跳过，不能记为通过")
        if action == "pass":
            test = event.get("Test")
            if test:
                passed.add(test)
            else:
                package_passed = True
    if not package_passed or not set(required).issubset(passed):
        raise ValueError("缺少完整的必需预检结果")
    return sorted(required)


def run_bounded(command, env, timeout):
    # Temporary output is not persisted or printed. The fixed test suite never
    # logs IDs/gateways/credentials. A timeout kills only this child process group.
    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except BaseException as failure:
            # While wait has not reaped the child, its PID/group identity cannot
            # be reused. Never signal a numeric group after a known completed wait.
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    raise RuntimeError("预检进程终止请求失败，退出状态尚未确认") from None
                try:
                    proc.wait(timeout=5)
                except BaseException:
                    raise RuntimeError("预检进程终止状态尚未确认") from None
            if isinstance(failure, subprocess.TimeoutExpired):
                raise RuntimeError("预检进程超时并已终止；未得到原生验证结果") from None
            raise
        if code != 0:
            raise RuntimeError("预检子进程失败；未得到原生验证结果")
        log.seek(0)
        data = log.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise RuntimeError("预检子进程输出超限")
        return data


def execute(go, mode, service_id, reports):
    if mode not in ("abi", "service"):
        raise ValueError("未知预检模式")
    if platform.system() != "Darwin":
        raise RuntimeError("原生只读预检必须在 macOS 上运行；交叉编译不算运行通过")
    if mode == "service" and not re.fullmatch(r"[A-Za-z0-9-]{1,127}", service_id or ""):
        raise ValueError("服务预检必须明确提供有效的系统服务标识")
    if mode == "abi" and service_id:
        raise ValueError("ABI 预检不接受系统服务标识")
    reports.mkdir(mode=0o700, parents=False, exist_ok=False)
    evidence = {"schema": 1, "mode": mode, "platform": "Darwin",
                "architecture": platform.machine(), "result": "failed",
                "network_changes": False, "live_vpn_verified": False, "stage": "toolchain"}
    try:
        env = dict(os.environ)
        env.update(GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", CGO_ENABLED="0")
        env.pop("MERIDIAN_MACOS_ABI_TEST", None)
        env.pop("MERIDIAN_MACOS_SERVICE_ID", None)
        version = run_bounded([go, "version"], env, 10).decode().strip()
        if not version.startswith("go version go") or "darwin/" not in version:
            raise RuntimeError("未检测到可用的 macOS Go 工具链")
        evidence["go_version"] = version
        # Builds use their own deadline; they are not mistaken for ABI execution.
        with tempfile.TemporaryDirectory(prefix="meridian-macos-preflight-") as tmp:
            binary = Path(tmp) / "macosvpn.test"
            snapshot = Path(tmp) / "source"
            snapshot.mkdir(mode=0o700)
            source_hash = hashlib.sha256()
            for source in sorted((ROOT / "internal/macosvpn").glob("*.go")) + sorted((ROOT / "internal/core").glob("*.go")) + sorted((ROOT / "internal/windowsvpn").glob("*.go")) + [ROOT / "go.mod", ROOT / "go.sum"]:
                relative = source.relative_to(ROOT)
                data = source.read_bytes()
                target = snapshot / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                source_hash.update(relative.as_posix().encode() + b"\x00" + data + b"\x00")
            evidence["source_sha256"] = source_hash.hexdigest()
            evidence["stage"] = "build"
            run_bounded([go, "-C", str(snapshot), "test", "-c", "-o", str(binary), "./internal/macosvpn"], env, 180)
            evidence["test_binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            required = [ABI_TEST]
            if mode == "service":
                required.append(SERVICE_TEST)
                env["MERIDIAN_MACOS_SERVICE_ID"] = service_id
            env["MERIDIAN_MACOS_ABI_TEST"] = "1"
            pattern = "^(" + "|".join(required) + ")$"
            evidence["stage"] = "native_checks"
            output = run_bounded([go, "tool", "test2json", "-p", "mygo-vpn/internal/macosvpn",
                                  str(binary), "-test.v=test2json", "-test.count=1",
                                  "-test.timeout=10s", "-test.run=" + pattern], env, 15)
            evidence["tests_passed"] = verify_events(output, required)
        evidence["stage"] = "complete"
        evidence["result"] = "passed"
        return evidence
    finally:
        # No service IDs, gateways, credentials, raw dictionaries or subprocess
        # transcripts are stored, even on failure.
        (reports / "evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description="执行隔离进程内的 macOS 只读 ABI/服务预检，不启动或断开 VPN")
    parser.add_argument("mode", choices=("abi", "service"), help="abi：系统框架验证；service：另含明确所选服务的只读检查")
    parser.add_argument("--go", default="go", help="Go 编译器路径")
    parser.add_argument("--service-id", help="明确选择的现有系统服务标识；不会写入报告")
    parser.add_argument("--reports", required=True, type=Path, help="新建的报告目录，不覆盖已有目录")
    args = parser.parse_args()
    try:
        execute(args.go, args.mode, args.service_id, args.reports)
    except KeyboardInterrupt:
        print("只读预检已取消；不记录为通过。", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        print("macOS 只读预检未通过；不代表 VPN 已可用。请检查平台、工具链和所选服务。", file=sys.stderr)
        return 1
    print("macOS 只读预检通过；未启动或断开 VPN，未验收路由、DNS、签名或真实网关。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
