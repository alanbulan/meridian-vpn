"""Compile ABI assertions with the runner's installed official Microsoft SDK.

No native VPN function is linked or executed. All artifacts are object files.
The Go fake-API tests independently check the matching Go layout.
"""
import os
from pathlib import Path
import subprocess
import sys


def main():
    if sys.platform != "win32":
        raise SystemExit("Windows SDK ABI verification requires Windows")
    root = Path(__file__).resolve().parents[2]
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installation = subprocess.check_output([
        str(vswhere), "-latest", "-products", "*", "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath",
    ], text=True).strip()
    vcvars = Path(installation) / "VC/Auxiliary/Build/vcvarsall.bat"
    if not vcvars.is_file():
        raise SystemExit("Installed Microsoft C compiler was not found")
    output = root / "build/windows-ras-abi"
    output.mkdir(parents=True, exist_ok=True)
    for architecture in ("x64", "x86"):
        obj = output / f"ras-layout-{architecture}.obj"
        source = root / "integration/windows-ras-abi/verify.c"
        command = f'""{vcvars}" {architecture} && cl /nologo /W4 /WX /TC /c "{source}" /Fo"{obj}""'
        subprocess.run("cmd.exe /d /s /c " + command, check=True, cwd=root)
        if not obj.is_file():
            raise SystemExit(f"SDK assertion object missing: {architecture}")
        print(f"Windows SDK ABI assertions passed: {architecture}", flush=True)


if __name__ == "__main__":
    main()
