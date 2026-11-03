"""Validate native executable targets and record unsigned development artifacts."""
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import sys

TARGETS = {"linux-amd64": "", "windows-amd64": ".exe", "darwin-arm64": ""}


def check_target(data, target):
    if target == "linux-amd64":
        return len(data) >= 20 and data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 62
    if target == "darwin-arm64":
        return len(data) >= 8 and data[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", data, 4)[0] == 0x0100000C
    if target == "windows-amd64":
        if len(data) < 64 or data[:2] != b"MZ":
            return False
        offset = struct.unpack_from("<I", data, 60)[0]
        return offset + 6 <= len(data) and data[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", data, offset + 4)[0] == 0x8664
    return False


def write_manifest(directory, target, commit):
    if target not in TARGETS:
        raise ValueError("unsupported build target")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("a full verified source commit SHA is required")
    rows = []
    for base in ("meridian", "meridianctl"):
        name = base + TARGETS[target]
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > 256 << 20:
            raise ValueError(f"not a bounded regular executable: {name}")
        data = path.read_bytes()
        if not check_target(data, target):
            raise ValueError(f"executable target does not match {target}: {name}")
        rows.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "schema_version": 1,
        "source_commit": commit,
        "target": target,
        "distribution": "unsigned-development",
        "files": rows,
        "scope": "Build and offline tests only. Not an installer, code-signing attestation, GUI acceptance, or live VPN validation.",
    }
    # Write metadata only after both executable formats have been verified.
    (directory / "build-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (directory / "SHA256SUMS").write_text("".join(f"{row['sha256']}  {row['name']}\n" for row in rows), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    try:
        write_manifest(pathlib.Path(sys.argv[1]), sys.argv[2], os.environ.get("GITHUB_SHA", ""))
    except (ValueError, OSError, IndexError) as error:
        print(f"Build manifest failed: {error}", file=sys.stderr)
        sys.exit(1)
