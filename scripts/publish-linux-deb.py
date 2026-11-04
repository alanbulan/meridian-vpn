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
BUILD_SHA = '5337e308b8cf9df55f661498d473fb174242dde2'
RUN = 41817674611
ARTIFACT = 13314962785
ZIP_SHA = 'e67a34b968413285773d12bea7931ddfbbc575b19ba2a795c7449065d37d3050'
DEB_SHA = 'f28152161f746d0ae76b5fa7f5bc7876f47c1c9ad232838ef76119f80c4cce60'
DEB = 'meridian_0.1.0~alpha.1-2_amd64.deb'
DOWNLOAD = 'meridian_0.1.0.alpha.1-2_amd64.deb'
CHECKSUM = 'SHA256SUMS-deb-r2'
GUIDE = 'INSTALL-LINUX-r2.zh-CN.md'
NOTE_HEADING = '## Linux 安装包修订版 -2：修复中文字体依赖'
ORIGINAL_INSTALLER = 'meridian_0.1.0.alpha.1-1_amd64.deb'
ORIGINAL_INSTALLER_SHA = 'b14115079aafd3a74ceb33896713509726d2f140b7708e34e5b5618846872b8a'


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
    # Upload the GitHub-normalized filename deliberately; retain package bytes.
    guide = files['INSTALL-LINUX.zh-CN.md'].replace(DEB.encode(), DOWNLOAD.encode())
    guide = guide.replace(b'SHA256SUMS-deb', CHECKSUM.encode())
    guide = guide.replace('此候选安装包为修订版'.encode(), '此安装包为修订版'.encode())
    files = {DOWNLOAD: files[DEB], CHECKSUM: (DEB_SHA + '  ' + DOWNLOAD + '\n').encode(), GUIDE: guide}
    before = request(f'/releases/{RELEASE}')
    require(before['tag_name'] == api['TAG'] and before['target_commitish'] == api['SOURCE'] and before['prerelease'] and not before['draft'], 'Unexpected release identity')
    require(any(a['name'] == ORIGINAL_INSTALLER and a['digest'] == 'sha256:' + ORIGINAL_INSTALLER_SHA for a in before['assets']), 'Original installer changed; stop')
    originals = {a['id']: (a['name'], a['digest'], a['size']) for a in before['assets']}
    require(any(a['name'] == api['PACKAGE'] and a['digest'] == 'sha256:' + api['PACKAGE_SHA'] for a in before['assets']), 'Original archive changed')
    require(not set(files).intersection(a['name'] for a in before['assets']), 'Installer assets already exist; inspect partial state, never replace')
    require(NOTE_HEADING not in before['body'], 'Revision notes already exist; inspect state')
    tag_is_original()
    additions = {}
    for name, data in files.items():
        req = urllib.request.Request(f'https://uploads.github.com/repos/{api["REPO"]}/releases/{RELEASE}/assets?name={name}', data=data, method='POST', headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Content-Type': 'application/vnd.debian.binary-package' if name == DOWNLOAD else 'text/plain', 'Accept': 'application/vnd.github+json'})
        with urllib.request.build_opener(api['NoRedirect']).open(req, timeout=120) as response:
            uploaded = json.load(response)
        require(uploaded['name'] == name and uploaded['state'] == 'uploaded' and uploaded['size'] == len(data) and uploaded['digest'] == 'sha256:' + hashlib.sha256(data).hexdigest(), 'Upload verification failed; inspect partial state')
        additions[uploaded['id']] = (uploaded['name'], uploaded['digest'], uploaded['size'])
    current = request(f'/releases/{RELEASE}')
    require(current['tag_name'] == api['TAG'] and current['target_commitish'] == api['SOURCE'] and current['prerelease'] and not current['draft'], 'Release identity changed during upload')
    require(current['body'] == before['body'], 'Concurrent release text edit; assets uploaded, stop without overwriting')
    require(all(any(a['id'] == key and (a['name'], a['digest'], a['size']) == value for a in current['assets']) for key, value in (originals | additions).items()), 'Original or added assets changed')
    tag_is_original()
    notes = f'''{NOTE_HEADING}

建议新安装或升级使用 `{DOWNLOAD}`，并用独立的 `{CHECKSUM}` 校验；步骤见 `{GUIDE}`。已有 `-1` 安装包和说明保留供追溯。`-1` 只声明了 DejaVu 字体，精简系统可能缺少中文字符；`-2` 将 Noto CJK 列为必需依赖。三个可执行文件与原发布压缩包完全相同，没有新增 VPN 功能或改动版本标签。

SHA-256：`{DEB_SHA}`。Debian 包内版本为 `0.1.0~alpha.1-2`，下载文件名使用 GitHub 的规范化形式。安装或升级命令：`sudo apt install ./{DOWNLOAD}`。程序仍应以普通用户运行。

[修订版安装验收记录](https://github.com/alanbulan/meridian-vpn/actions/runs/{RUN})：Debian 13 与 Ubuntu 24.04 的全新隔离容器中，实际安装后以非 root 用户检查代表性中文标签的常规/粗体 Pango 字形，均无缺字；窗口启动、辅助程序、文件完整性、卸载及个人配置保留检查均通过。这不等于全部界面排版、真实桌面交互、Wayland 或真实 VPN 网关已通过验收。

安装封装源码：`{BUILD_SHA}`；二进制仍为 `{api['SOURCE']}`。未经代码签名，真实 VPN、路由/DNS 恢复及其他生产验收限制保持不变。旧资产均不替换。

'''
    body = notes + before['body']
    after = request(f'/releases/{RELEASE}', 'PATCH', {'body': body})
    after = request(f'/releases/{RELEASE}')
    require(after['body'] == body and after['prerelease'] and not after['draft'] and after['tag_name'] == api['TAG'] and after['target_commitish'] == api['SOURCE'], 'Release description/identity verification failed')
    require(all(any(a['id'] == key and (a['name'], a['digest'], a['size']) == value for a in after['assets']) for key, value in (originals | additions).items()), 'Final asset readback mismatch')
    tag_is_original()
    for name, data in files.items():
        asset = next(a for a in after['assets'] if a['name'] == name)
        public_url = f'https://github.com/{api["REPO"]}/releases/download/{api["TAG"]}/{name}'
        require(asset['browser_download_url'] == public_url, 'Unexpected public download URL')
        with urllib.request.urlopen(public_url, timeout=120) as response:
            downloaded = response.read()
        require(len(downloaded) == len(data) and hashlib.sha256(downloaded).digest() == hashlib.sha256(data).digest(), 'Public download mismatch; inspect state without retrying upload')
        print('Verified public download:', name, hashlib.sha256(downloaded).hexdigest())
    print('Verified installer assets appended:', after['html_url'])


if __name__ == '__main__':
    main()
