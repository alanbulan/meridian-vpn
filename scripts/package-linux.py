"""Build an unsigned, versioned Linux amd64 candidate; never install or publish.

The archive is deterministic for identical input bytes and SOURCE_DATE_EPOCH.
Compiler/runtime versions are recorded; cross-machine bit reproducibility is not claimed.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_manifest", ROOT / "scripts/build-manifest.py")
targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(targets)
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")


def checked_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > 256 << 20:
        raise ValueError(f"not a bounded regular file: {path.name}")
    return path.read_bytes()


def archive_bytes(files, epoch):
    """No host ownership, paths, wall clock or gzip filename in release metadata."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=epoch) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, (data, mode) in sorted(files.items()):
                if name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/")):
                    raise ValueError("unsafe archive member")
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, epoch
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=kwargs.pop("timeout", 30), **kwargs).stdout


def build_environment(epoch):
    if any(os.environ.get(key) for key in ("GOFLAGS", "GOEXPERIMENT", "OPENCONNECT_STAGE")):
        raise ValueError("custom build flags or staged runtime are unsupported for a release candidate")
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOENV="off", GOWORK="off",
               GOAMD64="v1", SOURCE_DATE_EPOCH=str(epoch))
    return env


def package(version, output, go="go", helper=False):
    if not VERSION.fullmatch(version):
        raise ValueError("version must be a bounded release version without v prefix")
    if len(version) > 64:
        raise ValueError("version too long")
    if output.exists():
        raise ValueError("output already exists; refusing overwrite")
    if run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("build requires a clean source checkout")
    commit = run(["git", "rev-parse", "HEAD"]).decode().strip()
    epoch = int(run(["git", "show", "-s", "--format=%ct", "HEAD"]))
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("invalid source identity")
    env = build_environment(epoch)
    toolchain = run([go, "version"], env=env).decode().strip()
    host = run([go, "env", "GOHOSTOS", "GOHOSTARCH"], env=env).decode().splitlines()
    if host != ["linux", "amd64"]:
        raise ValueError("only native Linux amd64 packaging is supported")
    if env.get("GOOS", "linux") != "linux" or env.get("GOARCH", "amd64") != "amd64":
        raise ValueError("cross-target environment is unsupported")
    run([go, "mod", "verify"], env=env, timeout=120)
    # Local build scratch is ignored by git; never installs anything.
    build = ROOT / "build/linux-candidate"
    build.mkdir(parents=True, exist_ok=True)
    flags = f"-s -w -X mygo-vpn/internal/buildinfo.Version={version} -X mygo-vpn/internal/buildinfo.Commit={commit}"
    for name in ("meridian", "meridianctl"):
        command = [go, "build", "-buildvcs=false", "-trimpath", "-mod=readonly"]
        if name == "meridian":
            command += ["-tags", "mygo_noinspector"]
        command += ["-ldflags", flags + " -X github.com/egoist/mygo.production=1", "-o", str(build / name), "./cmd/" + name]
        run(command, env=env, timeout=600)
    if run([str(build / "meridianctl"), "version"]).decode().strip() != f"Meridian CLI {version}":
        raise ValueError("CLI version mismatch")
    if run([str(build / "meridian"), "--version"]).decode().strip() != f"Meridian {version} ({commit})":
        raise ValueError("GUI version/source mismatch")
    files, binaries = {}, ["meridian", "meridianctl"]
    helper_runtime, helper_compiler = None, None
    if helper:
        run(["sh", "integration/mfa-helper/build.sh", str(build / "meridian-auth-helper")], env=env, timeout=120)
        if run([str(build / "meridian-auth-helper"), "--protocol-version"], env=env, timeout=3) != b"meridian-auth-helper/1\n":
            raise ValueError("MFA helper runtime handshake failed")
        helper_runtime = run(["pkg-config", "--modversion", "openconnect"]).decode().strip()
        helper_compiler = run([os.environ.get("CC", "cc"), "--version"]).decode().splitlines()[0]
        binaries.append("meridian-auth-helper")
    for name in binaries:
        data = checked_file(build / name)
        if not targets.check_target(data, "linux-amd64"):
            raise ValueError(f"wrong executable architecture: {name}")
        files[name] = (data, 0o755)
    # Exact source snapshot supplies own/helper source and third-party notices.
    # It does not imply a new license grant or bundle system libraries.
    files["source.tar"] = (run(["git", "archive", "--format=tar", commit], timeout=120), 0o644)
    for src, dest in [("docs/LINUX-RELEASE.md", "README.md"), ("THIRD_PARTY.md", "THIRD_PARTY.md"),
                      ("internal/desktop/assets/lucide/LICENSE", "licenses/Lucide.txt"),
                      ("docs/MYGO-LICENSE.txt", "licenses/MyGo.txt")]:
        files[dest] = (checked_file(ROOT / src), 0o644)
    for path in sorted((ROOT / "docs/third-party").rglob("*")):
        if path.is_file():
            files["licenses/go/" + path.relative_to(ROOT / "docs/third-party").as_posix()] = (checked_file(path), 0o644)
    manifest = {"schema_version": 1, "version": version, "source_commit": commit,
                "source_date_epoch": epoch, "target": "linux-amd64", "go": toolchain,
                "distribution": "unsigned-candidate", "mfa_helper": helper,
                "libopenconnect_build_version": helper_runtime, "helper_compiler": helper_compiler,
                "goamd64": "v1",
                "verification_scope": "Build, version and optional helper handshake only; not real VPN or route/DNS acceptance.",
                "license_status": "Maintainer distribution approval and project license decision required; no license is selected by this package.",
                "files": [{"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, (data, _) in sorted(files.items())]}
    files["build-manifest.json"] = ((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o644)
    files["SHA256SUMS"] = ("".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, (data, _) in sorted(files.items())).encode(), 0o644)
    data = archive_bytes(files, epoch)
    if run(["git", "rev-parse", "HEAD"]).decode().strip() != commit or run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("source changed during candidate build")
    # Exclusive final creation; no overwritten previous candidate on failure.
    with output.open("xb") as f:
        f.write(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {output.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--with-helper", action="store_true")
    args = parser.parse_args()
    try:
        package(args.version, args.output, args.go, args.with_helper)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Never echo environment or command subprocess output into reports.
        raise SystemExit(f"Candidate packaging failed: {type(error).__name__}: {error}") from None
