#!/usr/bin/env python3
"""Append verified installer assets to one existing alpha release, no replacements."""
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import urllib.error
import urllib.request
import zipfile

api = runpy.run_path(str(Path(__file__).with_name('publish-linux-alpha.py')))
request, require = api['request'], api['require']
RELEASE = 433608769
BUILD_SHA = '66b101554073c52fb81881778b5da824781904b4'
RUN = 41793223022
ARTIFACT = 13304193108
ZIP_SHA = '1a62e088e038f1b405d4846568e8e11aeac05c05b2a5fb2f878730bbb46cff53'
DEB_SHA = 'b14115079aafd3a74ceb33896713509726d2f140b7708e34e5b5618846872b8a'
DEB = 'meridian_0.1.0~alpha.1-1_amd64.deb'


def tag_is_original():
    tag = request('/git/ref/tags/' + api['TAG'])
    require(tag['object']['type'] == 'commit' and tag['object']['sha'] == api['SOURCE'], 'Tag changed')


def main():
    require(os.environ.get('GITHUB_REPOSITORY') == api['REPO'] and os.environ.get('GITHUB_REF') == 'refs/heads/candidate/linux-minimal-20261104', 'Wrong repository/ref')
    require(ARTIFACT > 0 and len(ZIP_SHA) == 64 and len(DEB_SHA) == 64, 'Publication inputs not approved')
    run = request(f'/actions/runs/{RUN}')
    require(run['head_sha'] == BUILD_SHA and run['status'] == 'completed' and run['conclusion'] == 'success' and run['event'] == 'push' and run['path'] == '.github/workflows/linux-deb.yml' and run['head_branch'] == 'candidate/linux-minimal-20261104', 'Installer acceptance not successful at exact source')
    jobs = request(f'/actions/runs/{RUN}/jobs')['jobs']
    required = {'build', 'install (debian:trixie-slim)', 'install (ubuntu:24.04)'}
    require({j['name'] for j in jobs} == required and all(j['conclusion'] == 'success' for j in jobs), 'Missing or failed installer acceptance jobs')
    artifact = request(f'/actions/artifacts/{ARTIFACT}')
    require(not artifact['expired'] and artifact['workflow_run']['id'] == RUN and artifact['digest'] == 'sha256:' + ZIP_SHA, 'Artifact identity changed')
    req = urllib.request.Request(api['API'] + f'/actions/artifacts/{ARTIFACT}/zip', headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'})
    try:
        urllib.request.build_opener(api['NoRedirect']).open(req, timeout=60)
        raise RuntimeError('Expected artifact redirect')
    except urllib.error.HTTPError as error:
        require(error.code == 302, 'Artifact redirect unavailable')
        location = error.headers['Location']
    require(location.startswith('https://'), 'Insecure download redirect')
    with urllib.request.urlopen(location, timeout=120) as response:
        archive = response.read()
    require(hashlib.sha256(archive).hexdigest() == ZIP_SHA, 'Artifact checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        require(sorted(z.namelist()) == sorted([DEB, 'SHA256SUMS-deb', '安装说明.md']), 'Unexpected artifact files')
        files = {DEB: z.read(DEB), 'SHA256SUMS-deb': z.read('SHA256SUMS-deb'), 'INSTALL-LINUX.zh-CN.md': z.read('安装说明.md')}
    require(hashlib.sha256(files[DEB]).hexdigest() == DEB_SHA, 'Installer checksum mismatch')
    require(files['SHA256SUMS-deb'].decode() == DEB_SHA + '  ' + DEB + '\n', 'Installer checksum file mismatch')
    before = request(f'/releases/{RELEASE}')
    require(before['tag_name'] == api['TAG'] and before['target_commitish'] == api['SOURCE'] and before['prerelease'] and not before['draft'], 'Unexpected release identity')
    originals = {a['id']: (a['name'], a['digest'], a['size']) for a in before['assets']}
    require(any(a['name'] == api['PACKAGE'] and a['digest'] == 'sha256:' + api['PACKAGE_SHA'] for a in before['assets']), 'Original archive changed')
    require(not set(files).intersection(a['name'] for a in before['assets']), 'Installer assets already exist; inspect partial state, never replace')
    old_sentence = '它不是安装器，也尚未完成生产环境验收。'
    require(old_sentence in before['body'], 'Release wording changed; review before editing')
    tag_is_original()
    additions = {}
    for name, data in files.items():
        req = urllib.request.Request(f'https://uploads.github.com/repos/{api["REPO"]}/releases/{RELEASE}/assets?name={name}', data=data, method='POST', headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Content-Type': 'application/vnd.debian.binary-package' if name == DEB else 'text/plain', 'Accept': 'application/vnd.github+json'})
        with urllib.request.build_opener(api['NoRedirect']).open(req, timeout=120) as response:
            uploaded = json.load(response)
        require(uploaded['name'] == name and uploaded['state'] == 'uploaded' and uploaded['size'] == len(data) and uploaded['digest'] == 'sha256:' + hashlib.sha256(data).hexdigest(), 'Upload verification failed; inspect partial state')
        additions[uploaded['id']] = (uploaded['name'], uploaded['digest'], uploaded['size'])
    current = request(f'/releases/{RELEASE}')
    require(current['tag_name'] == api['TAG'] and current['target_commitish'] == api['SOURCE'] and current['prerelease'] and not current['draft'], 'Release identity changed during upload')
    require(current['body'] == before['body'], 'Concurrent release text edit; assets uploaded, stop without overwriting')
    require(all(any(a['id'] == key and (a['name'], a['digest'], a['size']) == value for a in current['assets']) for key, value in (originals | additions).items()), 'Original or added assets changed')
    tag_is_original()
    body = before['body'].replace(old_sentence, '原始 tar.gz 是便携压缩包；现已新增可通过系统软件安装器安装的 .deb 包，仍未完成生产环境验收。', 1)
    body += f'''\n## 新增 Linux 安装包\n\n下载 `{DEB}`，适用于已通过隔离安装验收的 Debian 13 / Ubuntu 24.04 amd64。双击后使用系统软件安装器安装；若桌面没有本地包安装器，可运行 `sudo apt install ./{DEB}`。详细步骤见下载文件 `INSTALL-LINUX.zh-CN.md`。\n\nSHA-256：`{DEB_SHA}`，另附 `SHA256SUMS-deb`。\n\n安装后可从应用菜单打开 Meridian。包含启动器、图标、GUI、CLI 和认证辅助程序。没有安装脚本、开机自启或网络配置操作；包管理器安装声明的运行库，VPN 插件仍需管理员确认安装。卸载保留个人配置。\n\n[安装验收记录](https://github.com/alanbulan/meridian-vpn/actions/runs/{RUN})：两个全新发行版容器中均通过依赖安装、完整文件校验、非 root 版本/辅助程序检查、Xvfb 可见窗口启动、卸载和个人文件保留检查。这是隔离的 X11 启动测试，不代表真实桌面完整交互、Wayland 或真实 VPN 网关验收。\n\n安装封装源码：`{BUILD_SHA}`；二进制仍为原标签源码 `{api['SOURCE']}`，已有下载文件和版本标签保持不变。\n'''
    after = request(f'/releases/{RELEASE}', 'PATCH', {'body': body})
    after = request(f'/releases/{RELEASE}')
    require(after['body'] == body and after['prerelease'] and not after['draft'] and after['tag_name'] == api['TAG'] and after['target_commitish'] == api['SOURCE'], 'Release description/identity verification failed')
    require(all(any(a['id'] == key and (a['name'], a['digest'], a['size']) == value for a in after['assets']) for key, value in (originals | additions).items()), 'Final asset readback mismatch')
    tag_is_original()
    print('Verified installer assets appended:', after['html_url'])


if __name__ == '__main__':
    main()
