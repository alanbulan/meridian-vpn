#!/usr/bin/env python3
"""只编译/封装：不执行 Meridian、helper、安装器、测试或运行验收。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NOTICE = ROOT / "packaging/build-only/安装说明.md"
TARGETS = {"linux-amd64": ("Linux", "amd64"), "windows-amd64": ("Windows", "amd64"),
           "darwin-arm64": ("Darwin", "arm64"), "darwin-amd64": ("Darwin", "amd64")}
# Pinned official-runner Inno compiler; do not download or accept unknown bytes.
ISCC_SHA = "eb6f4410c8db367a5f74127e8025ad2ccacc0afabbe783959d237df3050f97fb"


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], cwd=ROOT, check=True,
                          stdout=subprocess.PIPE, timeout=900, **kwargs).stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(source, version, target):
    return {"schema_version": 1, "source_commit": source, "version": version, "target": target,
            "distribution": "untested-development-prerelease", "tests_run": False,
            "runtime_validation_run": False, "installation_validation_run": False,
            "live_vpn_verified": False, "publisher_signed": False, "notarized": False,
            "signing": "ad-hoc-only" if target.startswith("darwin") else "unsigned",
            "limits": "本轮仅编译与封装；未运行测试、软件、安装器或真实VPN验收；未实现能力仍未实现。Linux UniVPN生产路径未实现；Windows/macOS保持开发预览限制。"}


def notices(destination, source):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(NOTICE, destination / "安装说明.md")
    shutil.copyfile(ROOT / "THIRD_PARTY.md", destination / "THIRD_PARTY.md")
    shutil.copyfile(ROOT / "docs/MYGO-LICENSE.txt", destination / "MYGO-LICENSE.txt")
    shutil.copyfile(ROOT / "internal/desktop/assets/lucide/LICENSE", destination / "LUCIDE-LICENSE.txt")
    shutil.copytree(ROOT / "docs/third-party", destination / "third-party")
    run(["git", "archive", "--format=tar", "-o", destination / "source.tar", source])


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    path.chmod(mode)


def linux_package(binaries, stage, output, version, source, meta, env):
    root = stage / "deb"
    for binary in ("meridian", "meridianctl", "meridian-auth-helper"):
        write(root / "usr/lib/meridian" / binary, (binaries / binary).read_bytes(), 0o755)
    (root / "usr/bin").mkdir(parents=True)
    for binary in ("meridian", "meridianctl"):
        (root / "usr/bin" / binary).symlink_to("../lib/meridian/" + binary)
    docs = root / "usr/share/doc/meridian"
    notices(docs, source)
    write(docs / "build-manifest.json", json.dumps(meta, ensure_ascii=False, indent=2))
    write(root / "usr/share/applications/meridian.desktop",
          "[Desktop Entry]\nType=Application\nName=Meridian VPN\nName[zh_CN]=Meridian VPN 客户端\n"
          "Comment=未验证开发预览版\nExec=/usr/bin/meridian\nTryExec=/usr/bin/meridian\nIcon=meridian\n"
          "Terminal=false\nCategories=Network;\nStartupNotify=true\n")
    write(root / "usr/share/icons/hicolor/scalable/apps/meridian.svg",
          (ROOT / "internal/desktop/assets/lucide/shield-check.svg").read_bytes())
    debversion = version.replace("-", "~", 1) + "-1"
    write(root / "DEBIAN/control", f"""Package: meridian
Version: {debversion}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Meridian maintainers <alanbulan@users.noreply.github.com>
Homepage: https://github.com/alanbulan/meridian-vpn
Depends: libc6 (>= 2.34), libgtk-3-0t64 | libgtk-3-0, libpango-1.0-0, libpangocairo-1.0-0, libfontconfig1, libgl1, libepoxy0, libopenconnect5 (>= 9.12), libsecret-1-0, fonts-dejavu-core, fonts-noto-cjk
Recommends: libayatana-appindicator3-1
Suggests: network-manager, network-manager-openconnect, network-manager-l2tp, policykit-1
Description: Meridian 原生桌面 VPN 客户端（未验证开发预览）
 本轮仅编译封装，无测试、安装或实际VPN验收。
 不自动启用连接、开机自启或特权服务。
""")
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    root.chmod(0o755)
    # The filename intentionally avoids '~', which GitHub normalizes on upload.
    package = output / f"meridian_{version}_amd64.deb"
    run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", root, package], env=env)
    return [package]


def windows_package(binaries, stage, output, version, source, numeric, meta):
    payload = stage / "windows"
    notices(payload, source)
    for binary in ("meridian.exe", "meridianctl.exe"):
        shutil.copyfile(binaries / binary, payload / binary)
    png = (ROOT / "internal/desktop/assets/lucide/tray-network.png").read_bytes()
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("仓库图标不是PNG")
    width, height = struct.unpack_from(">II", png, 16)
    if not 1 <= width <= 256 or not 1 <= height <= 256:
        raise ValueError("图标大小不支持")
    icon = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", width % 256, height % 256, 0, 0, 1, 32, len(png), 22) + png
    write(payload / "meridian.ico", icon)
    write(payload / "build-manifest.json", json.dumps(meta, ensure_ascii=False, indent=2))
    # Inno InfoBeforeFile expects BOM for reliable Unicode rendering.
    (payload / "安装说明.md").write_text(NOTICE.read_text(encoding="utf-8"), encoding="utf-8-sig")
    compiler = Path(os.environ["ProgramFiles(x86)"]) / "Inno Setup 6/ISCC.exe"
    if not compiler.is_file() or digest(compiler) != ISCC_SHA:
        raise ValueError("官方运行器编译器缺失或哈希变更；不自动下载/绕过")
    run([compiler, f"/DStageDir={payload}", f"/DOutputDir={output}",
         f"/DReleaseVersion={version}", f"/DNumericVersion={numeric}",
         ROOT / "packaging/build-only/windows.iss"])
    return [output / f"Meridian-{version}-Windows-x64-Setup.exe"]


def macos_package(binaries, stage, output, version, source, numeric, arch, meta):
    image = stage / "image"
    app = image / "Meridian Preview.app"
    mapping = {"meridian": "MacOS/meridian", "meridianctl": "Helpers/meridianctl",
               "meridian-macos-inspect": "Helpers/meridian-macos-inspect",
               "meridian-macos-service": "Helpers/meridian-macos-service"}
    for binary, relative in mapping.items():
        write(app / "Contents" / relative, (binaries / binary).read_bytes(), 0o755)
    resources = app / "Contents/Resources"
    notices(resources, source)
    write(resources / "build-manifest.json", json.dumps(meta, ensure_ascii=False, indent=2))
    info = {"CFBundleIdentifier": "site.meridian-vpn.preview", "CFBundleName": "Meridian Preview",
            "CFBundleDisplayName": "Meridian Preview", "CFBundleExecutable": "meridian",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": ".".join(numeric.split(".")[:3]),
            # This preview uses its alpha sequence as the monotonic bundle build.
            # Windows' four-part version is not a valid CFBundleVersion.
            "CFBundleVersion": str(int(numeric.split(".")[3])), "LSMinimumSystemVersion": "15.0",
            "NSHighResolutionCapable": True, "NSHumanReadableCopyright": "未验证开发预览；未作Developer ID签名或公证"}
    write(app / "Contents/Info.plist", plistlib.dumps(info))
    # Ad-hoc sealing needs no certificate/key and is not publisher authentication.
    # Do not request entitlements, disable Gatekeeper, notarize, or run binaries.
    for relative in sorted(mapping.values(), key=lambda x: x.startswith("MacOS/")):
        run(["/usr/bin/codesign", "--force", "--sign", "-", app / "Contents" / relative])
    run(["/usr/bin/codesign", "--force", "--sign", "-", app])
    shutil.copyfile(NOTICE, image / "安装说明.md")
    stem = f"meridian-{version}-macos-{arch}"
    dmg, pkg = output / (stem + ".dmg"), output / (stem + ".pkg")
    run(["/usr/bin/hdiutil", "create", "-volname", "Meridian Preview", "-srcfolder", image, "-format", "UDZO", dmg])
    pkgroot = stage / "pkgroot"
    pkgroot.mkdir()
    shutil.copytree(app, pkgroot / app.name)
    components = stage / "components.plist"
    write(components, plistlib.dumps([{"RootRelativeBundlePath": app.name, "BundleIsRelocatable": False,
         "BundleHasStrictIdentifier": True, "BundleIsVersionChecked": True, "BundleOverwriteAction": "upgrade"}]))
    run(["/usr/bin/pkgbuild", "--root", pkgroot, "--component-plist", components,
         "--install-location", "/Applications", "--identifier", "site.meridian-vpn.preview",
         "--version", ".".join(numeric.split(".")[:3]), pkg])
    return [dmg, pkg]


def package(target, version, source, output):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)-alpha\.(\d+)", version)
    if not match or any(int(x) > 65535 for x in match.groups()) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("需要完整源码SHA与MAJOR.MINOR.PATCH-alpha.N版本")
    system, arch = TARGETS[target]
    actual = platform.machine().lower()
    if platform.system() != system or actual not in (("aarch64", "arm64") if arch == "arm64" else ("amd64", "x86_64")):
        raise ValueError("必须使用对应平台/架构的原生构建运行器")
    if run(["git", "rev-parse", "HEAD"]).decode().strip() != source or run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("源码提交不匹配或工作区不干净")
    if os.environ.get("GOFLAGS") or os.environ.get("GOEXPERIMENT"):
        raise ValueError("拒绝未声明的编译器开关")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOWORK="off", GOENV="off",
               GOOS=target.split("-")[0], GOARCH=arch, GOAMD64="v1")
    flags = f"-s -w -X mygo-vpn/internal/buildinfo.Version={version} -X mygo-vpn/internal/buildinfo.Commit={source}"
    meta = metadata(source, version, target)
    with tempfile.TemporaryDirectory(prefix="meridian-build-only-") as tmp:
        stage = Path(tmp)
        binaries = stage / "binaries"
        binaries.mkdir()
        commands = ["meridian", "meridianctl"]
        if system == "Darwin":
            commands += ["meridian-macos-inspect", "meridian-macos-service"]
        for command in commands:
            destination = binaries / (command + (".exe" if system == "Windows" else ""))
            commandflags = flags
            args = ["go", "build", "-buildvcs=false", "-trimpath", "-mod=readonly"]
            if command == "meridian":
                args += ["-tags", "mygo_noinspector"]
                commandflags += " -X github.com/egoist/mygo.production=1"
                if system == "Windows":
                    commandflags += " -H=windowsgui"
            run(args + ["-ldflags", commandflags, "-o", destination, "./cmd/" + command], env=env)
        if system == "Linux":
            run(["sh", "integration/mfa-helper/build.sh", binaries / "meridian-auth-helper"], env=env)
            files = linux_package(binaries, stage, output, version, source, meta, env)
        elif system == "Windows":
            files = windows_package(binaries, stage, output, version, source, ".".join(match.groups()), meta)
        else:
            files = macos_package(binaries, stage, output, version, source, ".".join(match.groups()), arch, meta)
    # Reading build outputs to record size/hash is not running application code.
    meta["files"] = [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)} for p in files]
    write(output / f"manifest-{target}.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
    write(output / f"SHA256SUMS-{target}", "".join(f"{digest(p)}  {p.name}\n" for p in files))
    shutil.copyfile(NOTICE, output / f"安装说明-{target}.md")
    if run(["git", "rev-parse", "HEAD"]).decode().strip() != source or run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("构建期间源码变化；不发布")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package(args.target, args.version, args.source, args.output)
