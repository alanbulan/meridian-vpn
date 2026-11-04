"""构建诚实标注的 macOS 开发预览 .app/.dmg/.pkg，不执行网络配置。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import struct
import sys
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = "Meridian Preview.app"
BINARIES = {"meridian": "MacOS/meridian", "meridianctl": "Helpers/meridianctl", "meridian-macos-inspect": "Helpers/meridian-macos-inspect", "meridian-macos-service": "Helpers/meridian-macos-service"}


def invoke(args):
    try:
        return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, timeout=180).stdout
    except subprocess.CalledProcessError as error:
        # These fixed packaging/version tools never receive credentials. Retain
        # bounded diagnostic stderr; do not hide a failed signing operation.
        print("打包命令失败：" + Path(args[0]).name, file=sys.stderr)
        print((error.stderr or b"")[:8192].decode("utf-8", errors="replace"), file=sys.stderr)
        raise


def executable_bytes(path, arch):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 32 <= info.st_size <= 256 * 1024 * 1024:
        raise ValueError("输入不是大小受限的常规可执行文件")
    data = path.read_bytes()
    cpu = {"arm64": 0x0100000C, "amd64": 0x01000007}.get(arch)
    if cpu is None or data[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack_from("<I", data, 4)[0] != cpu or struct.unpack_from("<I", data, 12)[0] != 2:
        raise ValueError("Mach-O 格式、架构或可执行类型不匹配")
    return data


def stage_bundle(binaries, root, arch):
    app = root / APP
    contents = app / "Contents"
    # Validate every input before writing the bundle; do not preserve symlinks.
    captured = {name: executable_bytes(binaries / name, arch) for name in BINARIES}
    contents.mkdir(parents=True, exist_ok=False)
    for name, relative in BINARIES.items():
        target = contents / relative
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(captured[name])
        target.chmod(0o755)
    resources = contents / "Resources"
    resources.mkdir()
    shutil.copyfile(ROOT / "packaging/macos/安装说明.md", resources / "安装说明.md")
    notices = resources / "Notices"
    notices.mkdir()
    for source, name in [(ROOT / "THIRD_PARTY.md", "THIRD_PARTY.md"), (ROOT / "docs/MYGO-LICENSE.txt", "MYGO-LICENSE.txt"), (ROOT / "internal/desktop/assets/lucide/LICENSE", "LUCIDE-LICENSE")]:
        shutil.copyfile(source, notices / name)
    shutil.copytree(ROOT / "docs/third-party", notices / "GoDependencies")
    info = {"CFBundleIdentifier": "site.meridian-vpn.preview", "CFBundleName": "Meridian Preview",
            "CFBundleDisplayName": "Meridian Preview", "CFBundleExecutable": "meridian", "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "1", "LSMinimumSystemVersion": "15.0",
            "NSHighResolutionCapable": True, "NSHumanReadableCopyright": "开发预览：macOS VPN 连接未完成，未作正式签名或公证"}
    (contents / "Info.plist").write_bytes(plistlib.dumps(info, sort_keys=True))
    return app


def sign_bundle(app):
    # Signing the main executable can seal its enclosing bundle. Nested helpers
    # must already be signed, especially on Intel where Go does not pre-sign.
    for relative in sorted(BINARIES.values(), key=lambda p: p.startswith("MacOS/")):
        invoke(["/usr/bin/codesign", "--force", "--sign", "-", str(app / "Contents" / relative)])
    invoke(["/usr/bin/codesign", "--force", "--sign", "-", str(app)])
    invoke(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])


def validate_abi(path, arch):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 65536:
        raise ValueError("只读 ABI 证据格式不正确")
    data = path.read_bytes()
    evidence = json.loads(data)
    if not isinstance(evidence, dict) or any(evidence.get(k) != v for k, v in {
        "schema": 1, "mode": "abi", "platform": "Darwin", "result": "passed", "stage": "complete",
        "network_changes": False, "live_vpn_verified": False, "tests_passed": ["TestMacOSReadOnlyABI"],
        "architecture": "arm64" if arch == "arm64" else "x86_64"}.items()):
        raise ValueError("缺少完整且匹配架构的原生只读验证")
    source_hash = hashlib.sha256()
    for source in sorted((ROOT / "internal/macosvpn").glob("*.go")) + sorted((ROOT / "internal/core").glob("*.go")) + [ROOT / "go.mod", ROOT / "go.sum"]:
        source_hash.update(source.relative_to(ROOT).as_posix().encode() + b"\x00" + source.read_bytes() + b"\x00")
    if evidence.get("source_sha256") != source_hash.hexdigest() or not re.fullmatch(r"[0-9a-f]{64}", evidence.get("test_binary_sha256", "")):
        raise ValueError("原生证据与当前源码不匹配")
    return data


def package(binaries, output, arch, commit, abi_evidence):
    if platform.system() != "Darwin":
        raise ValueError("安装包必须在 macOS CI 上构建和验证")
    if arch not in ("arm64", "amd64") or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("需要明确架构与完整源码提交")
    if invoke(["git", "rev-parse", "HEAD"]).decode().strip() != commit or invoke(["git", "status", "--porcelain"]):
        raise ValueError("源码提交不匹配或工作区有未提交变更")
    abi_bytes = validate_abi(abi_evidence, arch)
    abi_sha = hashlib.sha256(abi_bytes).hexdigest()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="meridian-package-") as tmp:
        root = Path(tmp)
        stage = root / "image"
        stage.mkdir()
        app = stage_bundle(binaries, stage, arch)
        sign_bundle(app)
        invoke(["/usr/bin/plutil", "-lint", str(app / "Contents/Info.plist")])
        for relative in ("MacOS/meridian", "Helpers/meridian-macos-inspect", "Helpers/meridian-macos-service", "Helpers/meridianctl"):
            args = [str(app / "Contents" / relative)]
            args.append("--help" if relative.endswith(("inspect", "service")) else "--version" if relative == "MacOS/meridian" else "version")
            result = invoke(args)  # Safe entry points only: never selects or starts a service.
            if relative == "MacOS/meridian" and commit.encode() not in result:
                raise ValueError("命令行工具未绑定对应源码提交")
        shutil.copyfile(ROOT / "packaging/macos/安装说明.md", stage / "安装说明.md")
        stem = "meridian-macos-" + arch + "-development-preview"
        dmg, pkg = output / (stem + ".dmg"), output / (stem + ".pkg")
        invoke(["/usr/bin/hdiutil", "create", "-volname", "Meridian Preview", "-srcfolder", str(stage), "-format", "UDZO", str(dmg)])
        invoke(["/usr/bin/hdiutil", "verify", str(dmg)])
        # Never relocate an upgrade to a mounted/temporary copy discovered by
        # Installer. Only this app belongs in the /Applications payload.
        pkgroot = root / "pkgroot"
        pkgroot.mkdir()
        shutil.copytree(app, pkgroot / APP)
        components = root / "components.plist"
        components.write_bytes(plistlib.dumps([{"RootRelativeBundlePath": APP,
            "BundleIsRelocatable": False, "BundleHasStrictIdentifier": True,
            "BundleIsVersionChecked": True, "BundleOverwriteAction": "upgrade"}]))
        invoke(["/usr/bin/pkgbuild", "--root", str(pkgroot), "--component-plist", str(components), "--install-location", "/Applications", "--identifier", "site.meridian-vpn.preview", "--version", "0.1.0", str(pkg)])
        expanded = root / "expanded"
        invoke(["/usr/sbin/pkgutil", "--expand-full", str(pkg), str(expanded)])
        copies = list(expanded.rglob("Info.plist"))
        if len(copies) != 1 or copies[0].read_bytes() != (app / "Contents/Info.plist").read_bytes():
            raise ValueError("安装包内容与预期应用不匹配")
        if any(p.name == "Scripts" for p in expanded.rglob("*")):
            raise ValueError("预览安装包不允许安装脚本")
        payload_app = copies[0].parent.parent
        for relative in BINARIES.values():
            if (payload_app / "Contents" / relative).read_bytes() != (app / "Contents" / relative).read_bytes():
                raise ValueError("安装包内二进制不匹配")
        invoke(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(payload_app)])
    files = [{"name": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in (dmg, pkg)]
    manifest = {"schema": 1, "source_commit": commit, "architecture": arch, "distribution": "development-preview",
                "developer_id_signed": False, "notarized": False, "live_vpn_verified": False, "clean_install_verified": False, "readonly_abi_evidence_sha256": abi_sha,
                "scope": "可安装开发预览：仅包结构及临时签名完整性验证；原生 ABI 见独立 CI 证据；不代表 VPN 已完成", "files": files}
    (output / "readonly-abi-evidence.json").write_bytes(abi_bytes)
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").write_text("".join(f"{r['sha256']}  {r['name']}\n" for r in files))
    shutil.copyfile(ROOT / "packaging/macos/安装说明.md", output / "安装说明.md")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="创建未公证、非 VPN 成品的 macOS 开发预览安装包")
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=("arm64", "amd64"))
    parser.add_argument("--commit", required=True)
    parser.add_argument("--abi-evidence", required=True, type=Path)
    args = parser.parse_args()
    package(args.binaries.resolve(), args.output.resolve(), args.arch, args.commit, args.abi_evidence.resolve())
