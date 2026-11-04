#!/usr/bin/env python3
"""Repackage exact released bytes into a no-scripts Debian installer."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '8e0aaa94034e44150345733dc482126a03469d9a'
SHA = '9247a8c826b7f8683ac4758e52fddb5df0e66e8eba3d115bdbe5501073c99d36'
VERSION = '0.1.0~alpha.1-1'
NAME = 'meridian_' + VERSION + '_amd64.deb'
BINS = {'meridian', 'meridianctl', 'meridian-auth-helper'}


def read_archive(path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Original release archive SHA-256 mismatch')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            name = member.name
            if not member.isfile() or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')) or name in files:
                raise ValueError('Unsafe or duplicate archive member')
            files[name] = archive.extractfile(member).read()
    manifest = json.loads(files['build-manifest.json'])
    if manifest['source_commit'] != SOURCE or manifest['version'] != '0.1.0-alpha.1' or manifest['target'] != 'linux-amd64' or manifest['mfa_helper'] is not True:
        raise ValueError('Wrong source/version/target/helper')
    expected = {'build-manifest.json', 'SHA256SUMS'}
    for item in manifest['files']:
        content = files[item['name']]
        if len(content) != item['bytes'] or hashlib.sha256(content).hexdigest() != item['sha256']:
            raise ValueError('Manifest integrity mismatch')
        expected.add(item['name'])
    if set(files) != expected or not BINS.issubset(files):
        raise ValueError('Unexpected archive inventory')
    return files, manifest


def package(archive, output, packaging_commit):
    if output.exists():
        raise ValueError('Refusing to replace existing output')
    if len(packaging_commit) != 40 or any(c not in '0123456789abcdef' for c in packaging_commit):
        raise ValueError('Invalid packaging commit')
    files, manifest = read_archive(archive)
    epoch = manifest['source_date_epoch']
    with tempfile.TemporaryDirectory(prefix='meridian-deb-') as temporary:
        root = Path(temporary) / 'root'
        root.mkdir(mode=0o755)
        def write(name, data, mode=0o644):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        for name, data in files.items():
            target = 'usr/lib/meridian/' + name if name in BINS else 'usr/share/doc/meridian/source-package/' + name
            write(target, data, 0o755 if name in BINS else 0o644)
        (root / 'usr/bin').mkdir(parents=True)
        for binary in ('meridian', 'meridianctl'):
            (root / 'usr/bin' / binary).symlink_to('../lib/meridian/' + binary)
        write('usr/share/applications/meridian.desktop', (ROOT / 'packaging/linux/meridian.desktop').read_bytes())
        write('usr/share/icons/hicolor/scalable/apps/meridian.svg', (ROOT / 'internal/desktop/assets/lucide/shield-check.svg').read_bytes())
        write('usr/share/doc/meridian/README.md', (ROOT / 'packaging/linux/安装说明.md').read_bytes())
        metadata = {'package_version': VERSION, 'binary_source_commit': SOURCE, 'packaging_source_commit': packaging_commit,
                    'original_archive_sha256': SHA, 'supported_test_targets': ['Debian 13 amd64', 'Ubuntu 24.04 amd64'],
                    'network_changes_on_install': False, 'autostart': False, 'maintainer_scripts': False,
                    'scope': 'Unsigned alpha installer; installation tests do not validate live VPN behavior.'}
        write('usr/share/doc/meridian/installer-manifest.json', (json.dumps(metadata, indent=2) + '\n').encode())
        installed_sums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  /' + path.relative_to(root).as_posix() + '\n' for path in sorted(root.rglob('*')) if path.is_file() and not path.is_symlink())
        write('usr/share/doc/meridian/SHA256SUMS-installed', installed_sums.encode())
        control = f'''Package: meridian
Version: {VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Meridian maintainers <alanbulan@users.noreply.github.com>
Homepage: https://github.com/alanbulan/meridian-vpn
Depends: libc6 (>= 2.34), libgtk-3-0t64 | libgtk-3-0, libpango-1.0-0, libpangocairo-1.0-0, libfontconfig1, libgl1, libepoxy0, libopenconnect5 (>= 9.12), libsecret-1-0, fonts-dejavu-core
Recommends: libayatana-appindicator3-1
Suggests: network-manager, network-manager-openconnect, network-manager-l2tp, policykit-1
Installed-Size: {(sum(len(x) for x in files.values()) + 1023) // 1024}
Description: Meridian 原生桌面 VPN 客户端（测试版）
 图形界面、前台命令行及多因素认证辅助程序。
 不自动配置网络或开机启动；真实 VPN 网关尚未验收。
'''
        write('DEBIAN/control', control.encode())
        # Root ownership without fakeroot or installation; fixed times/order.
        for path in root.rglob('*'):
            if path.is_dir(): path.chmod(0o755)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        os.utime(root, (epoch, epoch))
        built = Path(temporary) / NAME
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z9', '--build', str(root), str(built)], check=True,
                       env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)), timeout=120)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('xb') as stream:
            stream.write(built.read_bytes())
    print(hashlib.sha256(output.read_bytes()).hexdigest(), output.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--packaging-commit', required=True)
    args = parser.parse_args()
    package(args.archive, args.output, args.packaging_commit)
