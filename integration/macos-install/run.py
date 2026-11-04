"""仅在一次性 GitHub macOS runner 验收当前构建的安装包；不连接 VPN。"""
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
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

APP = Path('/Applications/Meridian Preview.app')
IDENTIFIER = 'site.meridian-vpn.preview'
ROOT = Path(__file__).resolve().parents[2]


def run(args, *, allowed=(0,), timeout=120):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, check=False)
    if result.returncode not in allowed:
        # Commands may show runner/user details. Publish only fixed operation and status.
        raise RuntimeError(f'操作失败：{Path(str(args[0])).name}，状态 {result.returncode}')
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 256 * 1024:
        raise RuntimeError('命令输出超限')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard(arch, commit):
    if platform.system() != 'Darwin' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('RUNNER_OS') != 'macOS':
        raise ValueError('只允许一次性 GitHub 托管 macOS runner')
    if platform.mac_ver()[0].split('.')[0] != '15':
        raise ValueError('仅支持获准的 macOS 15 runner')
    if platform.machine() != {'arm64': 'arm64', 'amd64': 'x86_64'}.get(arch) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('架构或提交无效')
    if os.environ.get('GITHUB_SHA') != commit or run(['git', '-C', ROOT, 'rev-parse', 'HEAD']).stdout.decode().strip() != commit:
        raise ValueError('验收必须绑定当前精确提交')
    if run(['git', '-C', ROOT, 'status', '--porcelain']).stdout:
        raise ValueError('验收源码工作区有未提交修改')
    if os.path.lexists(APP):
        raise ValueError('目标应用已存在，拒绝覆盖')
    receipts = run(['/usr/sbin/pkgutil', '--pkgs']).stdout.decode().splitlines()
    if IDENTIFIER in receipts:
        raise ValueError('安装收据已存在，拒绝接管')


def validate_manifest(directory, arch, commit):
    path = directory / 'manifest.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('清单无效')
    manifest = json.loads(path.read_text())
    if any(manifest.get(k) != v for k, v in {'schema': 1, 'source_commit': commit, 'architecture': arch, 'distribution': 'development-preview', 'developer_id_signed': False, 'notarized': False, 'live_vpn_verified': False}.items()):
        raise ValueError('清单范围或提交不匹配')
    expected = {f'meridian-macos-{arch}-development-preview.{ext}' for ext in ('dmg', 'pkg')}
    records = manifest.get('files', [])
    if len(records) != 2 or {r.get('name') for r in records} != expected:
        raise ValueError('安装包集合不匹配')
    result = {}
    for record in records:
        p = directory / record['name']
        if p.is_symlink() or not p.is_file() or p.stat().st_size != record.get('bytes') or not 0 < p.stat().st_size <= 512 * 1024 * 1024 or digest(p) != record.get('sha256'):
            raise ValueError('安装包摘要、大小或类型不匹配')
        result[p.suffix] = p
    return result


def inventory(app):
    if app.is_symlink() or not app.is_dir():
        raise ValueError('应用目录无效')
    result = {}
    for path in [app] + sorted(app.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('应用包含链接或特殊文件')
        if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH):
            raise ValueError('应用含不安全权限')
        relative = path.relative_to(app).as_posix()
        result[relative] = {'mode': stat.S_IMODE(mode), 'type': 'directory'}
        if path.is_file():
            if path.stat().st_size > 256 * 1024 * 1024:
                raise ValueError('应用文件过大')
            result[relative] = {'mode': stat.S_IMODE(mode), 'type': 'file', 'sha256': digest(path)}
    executable = app / 'Contents/MacOS/meridian'
    if not executable.is_file() or not executable.stat().st_mode & 0o111:
        raise ValueError('主程序不可执行')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != IDENTIFIER or info.get('CFBundleExecutable') != 'meridian':
        raise ValueError('应用身份不匹配')
    return result


def validate_payload(expanded):
    infos = list(expanded.rglob('PackageInfo'))
    if len(infos) != 1 or any(p.name == 'Scripts' for p in expanded.rglob('*')):
        raise ValueError('安装包组件或脚本不符合预期')
    info = ET.fromstring(infos[0].read_bytes())
    if info.get('identifier') != IDENTIFIER or info.get('install-location') != '/Applications' or info.find('scripts') is not None or info.get('postinstall-action', 'none') != 'none' or info.get('relocatable', 'false') != 'false':
        raise ValueError('安装位置或标识不匹配')
    relocate = info.find('relocate')
    if relocate is not None and (len(relocate) or relocate.attrib or (relocate.text or '').strip()):
        raise ValueError('安装包允许重定位')
    payload = infos[0].parent / 'Payload'
    if sorted(p.name for p in payload.iterdir()) != [APP.name]:
        raise ValueError('安装包包含额外目标')
    return payload / APP.name


def network_observation():
    # A bounded observation, not packet capture or proof of whole-device equality.
    data = run(['/usr/sbin/scutil', '--nc', 'list'], timeout=20).stdout
    if b'(Connected)' in data or b'(Connecting)' in data or b'(Disconnecting)' in data:
        raise ValueError('runner 存在活动系统 VPN，拒绝测试')
    return hashlib.sha256(data).hexdigest()


def verify_signature(app):
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    details = run(['/usr/bin/codesign', '-d', '--verbose=4', app]).stderr
    if b'Signature=adhoc' not in details or b'Authority=Developer ID' in details:
        raise ValueError('临时签名状态与声明不匹配')


def launch_observed(helper, config, baseline, root, report):
    # The helper uses LaunchServices and requests normal quit. No forced quit or
    # deadline is ever interpreted as successful cleanup.
    with (root / 'launch.stdout').open('wb') as out, (root / 'launch.stderr').open('wb') as err:
        process = subprocess.Popen([str(helper), str(APP), str(config)], stdout=out, stderr=err)
        deadline = time.monotonic() + 75
        samples = 0
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise RuntimeError('GUI 验收超时，进程结果不确定；未强制终止')
            if network_observation() != baseline:
                raise ValueError('运行期间系统服务观察发生变化；保留现场')
            samples += 1
            time.sleep(1)
        report['helper_exit_code'] = process.returncode
        report['sample_count'] = samples
        if process.returncode != 0 or samples < 3:
            raise RuntimeError('GUI 窗口、身份或正常退出验收失败')
        return samples


def remove_owned_app(expected):
    if inventory(APP) != expected:
        raise ValueError('应用内容变化，拒绝递归删除')
    run(['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', APP])
    if os.path.lexists(APP):
        raise ValueError('应用卸载未完成')


def acceptance(directory, reports, arch, commit):
    guard(arch, commit)
    packages = validate_manifest(directory, arch, commit)
    reports.mkdir(parents=True, exist_ok=False)
    evidence = {'schema': 1, 'source_commit': commit, 'architecture': arch, 'runner': 'github-hosted-disposable', 'result': 'failed', 'developer_id_signed': False, 'notarized': False, 'live_vpn_verified': False, 'network_changes_requested': False, 'scope': '本地构建安装包的复制/安装、窗口出现、正常退出请求与进程终止观察及应用/收据移除；不是下载隔离、真实网关、整机恢复或完整视觉验收', 'stages': [], 'manifest_sha256': digest(directory / 'manifest.json'), 'package_sha256': {ext: digest(path) for ext, path in packages.items()}, 'run_url': 'https://github.com/' + os.environ.get('GITHUB_REPOSITORY', '') + '/actions/runs/' + os.environ.get('GITHUB_RUN_ID', ''), 'macos_version': platform.mac_ver()[0]}
    # Do not remove a changed app, live GUI or unknown receipt in a failure path.
    # The disposable VM is discarded by GitHub; failure remains visible.
    try:
        baseline = network_observation()
        evidence['system_service_state_sha256'] = baseline
        with tempfile.TemporaryDirectory(prefix='meridian-install-', dir=os.environ['RUNNER_TEMP']) as temp:
            root = Path(temp)
            expanded = root / 'expanded'
            run(['/usr/sbin/pkgutil', '--expand-full', packages['.pkg'], expanded])
            payload = validate_payload(expanded)
            expected = inventory(payload)
            verify_signature(payload)
            helper = root / 'launch-check'
            run(['/usr/bin/xcrun', 'swiftc', ROOT / 'integration/macos-install/launch.swift', '-o', helper], timeout=180)
            mount = root / 'mount'
            mount.mkdir()
            mounted = False
            try:
                run(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, packages['.dmg']])
                mounted = True
                source = mount / APP.name
                if inventory(source) != expected:
                    raise ValueError('DMG 与 PKG 应用不一致')
                if os.path.lexists(APP):
                    raise ValueError('目标位置在检查后出现')
                run(['/usr/bin/sudo', '-n', '/usr/bin/ditto', source, APP])
            finally:
                if mounted:
                    run(['/usr/bin/hdiutil', 'detach', mount])
            for mode in ('dmg', 'pkg'):
                if mode == 'pkg':
                    if os.path.lexists(APP):
                        raise ValueError('PKG 安装前目标存在')
                    evidence['pkg_install_outcome'] = 'attempted; outcome uncertain until verified'
                    run(['/usr/bin/sudo', '-n', '/usr/sbin/installer', '-pkg', packages['.pkg'], '-target', '/'])
                    receipt = plistlib.loads(run(['/usr/sbin/pkgutil', '--pkg-info-plist', IDENTIFIER]).stdout)
                    if receipt.get('pkgid') != IDENTIFIER or receipt.get('install-location') not in ('Applications', '/Applications') or receipt.get('volume') != '/':
                        raise ValueError('安装收据位置或身份不符')
                if inventory(APP) != expected:
                    raise ValueError('安装结果与包内容不一致')
                if mode == 'pkg':
                    evidence['pkg_install_outcome'] = 'verified at /Applications/Meridian Preview.app'
                verify_signature(APP)
                config = root / f'{mode}-profiles.json'
                evidence[mode + '_launch'] = {}
                samples = launch_observed(helper, config, baseline, root, evidence[mode + '_launch'])
                evidence[mode + '_system_service_samples'] = samples
                if config.exists() or network_observation() != baseline:
                    raise ValueError('新启动写入配置或系统服务观察发生变化')
                evidence['stages'].append(mode + ': installed, visible window, normal quit requested and termination observed, unchanged sampled system-service state')
                remove_owned_app(expected)
                if mode == 'pkg':
                    run(['/usr/bin/sudo', '-n', '/usr/sbin/pkgutil', '--forget', IDENTIFIER])
                    if IDENTIFIER in run(['/usr/sbin/pkgutil', '--pkgs']).stdout.decode().splitlines():
                        raise ValueError('收据未移除')
                evidence['stages'].append(mode + ': owned app removed' + (' and receipt forgotten' if mode == 'pkg' else ''))
        evidence['result'] = 'passed'
        evidence['clean_runner_install_verified'] = True
    finally:
        (reports / 'evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--reports', required=True, type=Path)
    parser.add_argument('--arch', required=True, choices=('arm64', 'amd64'))
    parser.add_argument('--commit', required=True)
    a = parser.parse_args()
    acceptance(a.packages.resolve(), a.reports.resolve(), a.arch, a.commit)
