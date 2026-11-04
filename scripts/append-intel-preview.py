#!/usr/bin/env python3
"""Append same-source Intel installers only; never replace or delete existing assets."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_helpers", ROOT / "scripts/publish-build-only.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.TARGETS = ("darwin-amd64",)
SOURCE = "c867b7a2200bc02eccf39a66bd73216a8e6f15bc"
TAG = "v0.1.0-alpha.2"
RELEASE = 434115778
SNAPSHOT = json.loads((ROOT / "packaging/build-only/release-before-intel.json").read_text())


def inventory(assets):
    return {a["id"]: (a["name"], a["size"], a.get("digest"), a["state"]) for a in assets}


def check_release(release, expected_assets):
    if (release["id"] != RELEASE or release["draft"] or not release["prerelease"]
            or release["tag_name"] != TAG or release["target_commitish"] != SOURCE
            or release["name"] != SNAPSHOT["name"] or release["body"] != SNAPSHOT["body"]
            or inventory(release["assets"]) != expected_assets):
        raise ValueError("发布内容或现有资产变化；停止，不覆盖")
    ref = helper.request("/git/ref/tags/" + TAG)
    if ref["object"]["type"] != "commit" or ref["object"]["sha"] != SOURCE:
        raise ValueError("标签变化；停止")


def main():
    if os.environ.get("GITHUB_REPOSITORY") != helper.REPO or os.environ.get("GITHUB_REF") != helper.BRANCH:
        raise ValueError("错误仓库或分支")
    files = helper.collect(ROOT / "build/intel-artifact", "0.1.0-alpha.2", SOURCE)
    files["INSTALL-MACOS-INTEL.zh-CN.md"] = files.pop("安装说明-darwin-amd64.md")
    expected = inventory(SNAPSHOT["assets"])
    current = helper.request(f"/releases/{RELEASE}")
    check_release(current, expected)
    if {a["name"] for a in current["assets"]} & set(files):
        raise ValueError("新资产名称已存在；停止")
    for name, data in sorted(files.items()):
        url = f"https://uploads.github.com/repos/{helper.REPO}/releases/{RELEASE}/assets?name=" + urllib.parse.quote(name, safe="")
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"], "Content-Type": "application/octet-stream",
            "Accept": "application/vnd.github+json"})
        with urllib.request.build_opener(helper.NoRedirect).open(req, timeout=180) as response:
            asset = json.load(response)
        fingerprint = "sha256:" + hashlib.sha256(data).hexdigest()
        if (asset["name"] != name or asset["size"] != len(data) or asset.get("digest") != fingerprint
                or asset["state"] != "uploaded" or asset["id"] in expected):
            raise ValueError("上传回执不符；停止，不自动重试")
        expected[asset["id"]] = (name, len(data), fingerprint, "uploaded")
    current = helper.request(f"/releases/{RELEASE}")
    check_release(current, expected)
    body = SNAPSHOT["body"].replace(
        "本次仅发布 Linux amd64 和 Windows x64 安装包。macOS 两种运行器在执行任何构建步骤之前被取消，本次不包含 macOS DMG/PKG；全部平台完成的目标尚未达到。",
        "本次已发布 Linux amd64、Windows x64 和 macOS Intel（x86_64）安装包。macOS Intel DMG/PKG 来自同一源码的首次成功构建；Apple Silicon（ARM64）运行器未执行任何构建步骤即取消，ARM64 安装包仍缺失，全部平台完成的目标尚未达到。")
    body = body.replace(
        "macOS 原计划提供 ARM64 和 Intel 开发预览 DMG/PKG，但本次未能完成全套构建，未发布 macOS 安装包；",
        "macOS 本次提供 Intel 开发预览 DMG/PKG，ARM64 尚未提供；")
    if body == SNAPSHOT["body"] or "未发布 macOS 安装包" in body:
        raise ValueError("发布说明替换失败")
    title = "Meridian 0.1.0-alpha.2：Linux / Windows / macOS Intel 未验证开发预览版"
    helper.request(f"/releases/{RELEASE}", "PATCH", {"name": title, "body": body, "make_latest": "false"})
    final = helper.request(f"/releases/{RELEASE}")
    SNAPSHOT["name"], SNAPSHOT["body"] = title, body
    check_release(final, expected)
    print("Intel 安装包已补齐；原资产未改变，ARM64仍缺失：" + final["html_url"])


if __name__ == "__main__":
    main()
