#!/usr/bin/env python3
"""发布新预发布版；只读取产物/来源/哈希，不执行测试或任何软件产物。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

REPO = "alanbulan/meridian-vpn"
API = "https://api.github.com/repos/" + REPO
BRANCH = "refs/heads/release/build-only-20261104"
TARGETS = ("linux-amd64", "windows-amd64")
ROOT = Path(__file__).resolve().parents[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(path, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
        "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=120) as response:
        return json.load(response)


def absent(path):
    try:
        request(path)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
        raise
    raise ValueError("目标标签或版本已存在；停止，不覆盖，也不自动重试")


def expected_names(version, target):
    if target == "linux-amd64":
        return {f"meridian_{version}_amd64.deb"}
    if target == "windows-amd64":
        return {f"Meridian-{version}-Windows-x64-Setup.exe"}
    arch = target.split("-")[1]
    return {f"meridian-{version}-macos-{arch}.dmg", f"meridian-{version}-macos-{arch}.pkg"}


def collect(directory, version, source):
    if {p.name for p in directory.iterdir()} != {"build-only-" + target for target in TARGETS}:
        raise ValueError("构建产物平台不完整或存在额外目录")
    files = {}
    for target in TARGETS:
        folder = directory / ("build-only-" + target)
        manifest_name = f"manifest-{target}.json"
        sums_name = f"SHA256SUMS-{target}"
        guide_name = f"安装说明-{target}.md"
        packages = expected_names(version, target)
        if {p.name for p in folder.iterdir()} != packages | {manifest_name, sums_name, guide_name}:
            raise ValueError("产物清单与预期不符")
        manifest = json.loads((folder / manifest_name).read_text(encoding="utf-8"))
        values = {"source_commit": source, "version": version, "target": target,
                  "tests_run": False, "runtime_validation_run": False, "installation_validation_run": False,
                  "live_vpn_verified": False, "publisher_signed": False, "notarized": False,
                  "distribution": "untested-development-prerelease"}
        if any(manifest.get(k) != v for k, v in values.items()):
            raise ValueError("来源或未验证声明不匹配")
        entries = manifest.get("files", [])
        if len(entries) != len(packages) or {x["name"] for x in entries} != packages:
            raise ValueError("安装包元数据不匹配")
        for entry in entries:
            path = folder / entry["name"]
            if path.is_symlink() or not path.is_file():
                raise ValueError("拒绝链接或异常文件")
            data = path.read_bytes()
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("安装包字节与构建清单不符")
        for path in folder.iterdir():
            if path.is_symlink() or not path.is_file() or path.name in files:
                raise ValueError("资产名称冲突或文件异常")
            files[path.name] = path.read_bytes()
        expected_sums = "".join(f"{x['sha256']}  {x['name']}\n" for x in entries)
        if files[sums_name] != expected_sums.encode():
            raise ValueError("校验清单不符")
    return files


def main(directory, version, source):
    if os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("GITHUB_REF") != BRANCH:
        raise ValueError("错误仓库/触发分支")
    if not re.fullmatch(r"\d+\.\d+\.\d+-alpha\.\d+", version) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("版本或完整源码SHA不合法")
    files = collect(directory, version, source)
    tag = "v" + version
    # Existing releases/tags are never reused, edited, deleted or force-moved.
    absent("/releases/tags/" + tag)
    absent("/git/ref/tags/" + tag)
    # This atomic ref create rejects a concurrently created tag.
    request("/git/refs", "POST", {"ref": "refs/tags/" + tag, "sha": source})
    body = (ROOT / "docs/releases/build-only.zh-CN.md").read_text(encoding="utf-8")
    body = body.replace("macOS 提供 ARM64 和 Intel 开发预览 DMG/PKG；", "macOS 原计划提供 ARM64 和 Intel 开发预览 DMG/PKG，但本次未能完成全套构建，未发布 macOS 安装包；")
    body = "本次仅发布 Linux amd64 和 Windows x64 安装包。macOS 两种运行器在执行任何构建步骤之前被取消，本次不包含 macOS DMG/PKG；全部平台完成的目标尚未达到。\n\n" + body
    body = f"# Meridian {version}：未验证开发预览版\n\n源码提交：{source}\n\n" + body
    title = f"Meridian {version}：Linux / Windows 未验证开发预览版"
    release = request("/releases", "POST", {"tag_name": tag, "target_commitish": source,
                      "name": title, "body": body, "draft": True, "prerelease": True,
                      "generate_release_notes": False, "make_latest": "false"})
    release_id = release["id"]
    if not release["draft"] or release["tag_name"] != tag or release["target_commitish"] != source:
        raise ValueError("草稿状态异常；停止并保留现场")
    uploaded = {}
    for name, data in sorted(files.items()):
        url = f"https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name=" + urllib.parse.quote(name, safe="")
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Content-Type": "application/octet-stream", "Accept": "application/vnd.github+json"})
        with urllib.request.build_opener(NoRedirect).open(req, timeout=180) as response:
            asset = json.load(response)
        fingerprint = "sha256:" + hashlib.sha256(data).hexdigest()
        if asset["name"] != name or asset["size"] != len(data) or asset.get("digest") != fingerprint or asset["state"] != "uploaded":
            raise ValueError("上传回执不匹配；保留草稿，不覆盖/重试资产")
        uploaded[asset["id"]] = (name, len(data), fingerprint)
    current = request(f"/releases/{release_id}")
    if (not current["draft"] or not current["prerelease"] or current["body"] != body
            or current["name"] != title or current["tag_name"] != tag
            or current["target_commitish"] != source):
        raise ValueError("草稿被并发修改；停止")
    actual = {a["id"]: (a["name"], a["size"], a.get("digest")) for a in current["assets"]}
    if actual != uploaded:
        raise ValueError("草稿资产被并发修改；停止")
    ref = request("/git/ref/tags/" + tag)
    if ref["object"]["type"] != "commit" or ref["object"]["sha"] != source:
        raise ValueError("标签变更；停止")
    request(f"/releases/{release_id}", "PATCH", {"draft": False, "prerelease": True, "make_latest": "false"})
    final = request(f"/releases/{release_id}")
    ref = request("/git/ref/tags/" + tag)
    if final["draft"] or not final["prerelease"] or final["tag_name"] != tag or final["body"] != body or ref["object"]["sha"] != source:
        raise ValueError("最终状态不确定；人工检查，不自动重试发布")
    if {a["id"]: (a["name"], a["size"], a.get("digest")) for a in final["assets"]} != uploaded:
        raise ValueError("最终资产发生变化；人工检查")
    print("预发布完成，仅构建/封装，未运行测试：" + final["html_url"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    main(args.artifacts, args.version, args.source)
