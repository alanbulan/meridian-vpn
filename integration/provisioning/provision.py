#!/usr/bin/env python3
"""Offline-only UniVPN rootfs preparation. Never install, launch, or modify a host."""
import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import tempfile

MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_ENTRIES = 4096
UID = 65532
NAME = 'meridian-worker'
REQUIRED_NOTICES = {'licenses/OPENCONNECT-LGPL-2.1.txt',
                    'licenses/UNIVPN-CONNECT-MIT.txt', 'licenses/THIRD_PARTY_NOTICES.md'}
GATES = [
    'Review manifest authenticity, every library/provider dependency and license source offer.',
    'Reserve UID/GID 65532 exclusively using current NSS and process identity evidence.',
    'Install immutable root-owned rootfs and static bootstrap under trusted ancestry.',
    'Provision protected dedicated cgroup v2 domain and read back resource limits.',
    'Validate bootstrap and atomic cgroup launch in an authorized disposable VM.',
    'Resolve host network/resolver ownership; this plan supplies no exclusive lease.',
    'Implement and review service entry point, admission, recovery and explicit activation.',
]


class Invalid(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid('duplicate JSON field')
        result[key] = value
    return result


def parse_manifest(raw):
    if len(raw) > 2 * 1024 * 1024:
        raise Invalid('manifest too large')
    obj = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(obj, dict) or set(obj) != {'version', 'files'} or type(obj['version']) is not int or obj['version'] != 1:
        raise Invalid('unknown manifest schema')
    if not isinstance(obj['files'], list) or not 1 <= len(obj['files']) <= MAX_ENTRIES:
        raise Invalid('invalid inventory size')
    entries = {}
    for item in obj['files']:
        if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'mode', 'size'}:
            raise Invalid('invalid entry fields')
        path = item['path']
        if not isinstance(path, str) or not re.fullmatch(r'[A-Za-z0-9_./+\-]+', path) or len(path) > 512:
            raise Invalid('invalid path')
        p = PurePosixPath(path)
        if p.is_absolute() or str(p) != path or any(c in ('', '.', '..') for c in path.split('/')):
            raise Invalid('noncanonical path')
        # Rootfs cannot contain host views, secrets, shells or extra executables.
        if path.startswith('rootfs/'):
            rel = path[len('rootfs/'):]
            if rel != 'bin/meridian-univpn' and not rel.startswith(('lib/', 'lib64/', 'usr/lib/', 'etc/ssl/')):
                raise Invalid('rootfs path outside minimal inventory')
        elif path != 'bootstrap/meridian-worker-bootstrap' and path not in REQUIRED_NOTICES:
            raise Invalid('unexpected bundle path')
        if path in entries or not isinstance(item['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise Invalid('duplicate path or invalid digest')
        if type(item['mode']) is not int or item['mode'] not in (0o444, 0o555):
            raise Invalid('mode must be read-only 0444 or 0555')
        if type(item['size']) is not int or not 0 < item['size'] <= MAX_FILE:
            raise Invalid('invalid size')
        entries[path] = item
    if sum(x['size'] for x in entries.values()) > MAX_TOTAL:
        raise Invalid('bundle too large')
    if not ({'rootfs/bin/meridian-univpn', 'bootstrap/meridian-worker-bootstrap'} | REQUIRED_NOTICES) <= entries.keys():
        raise Invalid('missing executables or notices')
    for path in ('rootfs/bin/meridian-univpn', 'bootstrap/meridian-worker-bootstrap'):
        if entries[path]['mode'] != 0o555:
            raise Invalid('executable mode required')
    for path in entries:
        if any(str(parent) in entries for parent in PurePosixPath(path).parents):
            raise Invalid('file and directory collision')
    return entries


def read_bundle(directory, entries):
    """Read only listed regular, single-link files using fd-relative NOFOLLOW traversal.

    Offline artifact consistency, not deployed ownership/mount-topology proof.
    Bytes copied later are the exact bytes hashed here, not reopened source paths.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(directory, flags | os.O_DIRECTORY)
    found = {}
    total_seen = 0
    def visit(parent, prefix):
        nonlocal total_seen
        directory_before = os.fstat(parent)
        for name in sorted(os.listdir(parent)):
            total_seen += 1
            if total_seen > MAX_ENTRIES * 2:
                raise Invalid('too many filesystem entries')
            path = prefix + name
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                if not any(x.startswith(path + '/') for x in entries):
                    raise Invalid('unexpected directory')
                child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
                try:
                    now = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (now.st_dev, now.st_ino) or now.st_mode & 0o7022:
                        raise Invalid('changed or writable directory')
                    visit(child, path + '/')
                finally:
                    os.close(child)
            else:
                if path not in entries or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise Invalid('unexpected, linked or special file')
                child = os.open(name, flags | os.O_NONBLOCK, dir_fd=parent)
                try:
                    now = os.fstat(child)
                    item = entries[path]
                    if os.listxattr(child):
                        raise Invalid('extended attributes are not supported')
                    if (before.st_dev, before.st_ino) != (now.st_dev, now.st_ino) or not stat.S_ISREG(now.st_mode) or now.st_nlink != 1:
                        raise Invalid('file changed during open')
                    if stat.S_IMODE(now.st_mode) != item['mode'] or now.st_size != item['size']:
                        raise Invalid('file metadata differs from inventory')
                    data = bytearray()
                    while len(data) <= item['size']:
                        part = os.read(child, min(65536, item['size'] + 1 - len(data)))
                        if not part:
                            break
                        data.extend(part)
                    after = os.fstat(child)
                    if (now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise Invalid('file changed during read')
                    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                        raise Invalid('artifact hash mismatch')
                    found[path] = bytes(data)
                finally:
                    os.close(child)
        directory_after = os.fstat(parent)
        if (directory_before.st_dev, directory_before.st_ino, directory_before.st_mtime_ns, directory_before.st_ctime_ns) != (directory_after.st_dev, directory_after.st_ino, directory_after.st_mtime_ns, directory_after.st_ctime_ns):
            raise Invalid('directory changed during read')
    try:
        if os.fstat(fd).st_mode & 0o7022:
            raise Invalid('writable source root')
        visit(fd, '')
    finally:
        os.close(fd)
    if set(found) != set(entries):
        raise Invalid('inventory incomplete')
    return found


def identity_conflicts(passwd_text, group_text):
    """Offline NSS-export check. Never a live reservation or uniqueness proof."""
    conflicts = []
    for label, raw, count in [('passwd', passwd_text, 7), ('group', group_text, 4)]:
        for line in raw.splitlines():
            if not line:
                continue
            fields = line.split(':')
            if len(fields) != count or not fields[2].isascii() or not fields[2].isdigit():
                raise Invalid('malformed identity export')
            if label == 'passwd' and (not fields[3].isascii() or not fields[3].isdigit()):
                raise Invalid('malformed primary group')
            if fields[0] == NAME or int(fields[2]) == UID or (label == 'passwd' and int(fields[3]) == UID):
                conflicts.append(label + ': reserved identity conflict')
    return conflicts


def plan(entries):
    return {'schema': 1, 'kind': 'offline-installation-plan', 'activation_allowed': False,
            'service_enabled': False, 'service_start': False, 'worker_uid': UID, 'worker_gid': UID,
            'worker_root': '/var/lib/meridian/worker-root',
            'rootfs_inventory': [entries[k] for k in sorted(entries) if k.startswith('rootfs/')],
            'cgroup_requirements': {'type': 'domain', 'controllers': ['cpu', 'memory', 'pids'],
                                    'proposed_limits': {'memory.max': 268435456, 'pids.max': 16, 'cpu.max': '100000 100000'},
                                    'fresh_empty': True, 'atomic_launch': 'CLONE_INTO_CGROUP',
                                    'cleanup': 'cgroup.kill then hierarchical populated 0 before removal'},
            'release_gates': GATES}


def stage(parent, entries, contents):
    """Create only a new private workspace child. Never overwrite existing paths.

    Caller must provide a trusted, nonconcurrently-mutated workspace parent.
    Rollback uses a journal of this transaction's paths, never recursive deletion.
    """
    validated = parse_manifest(json.dumps({'version': 1, 'files': list(entries.values())}))
    if entries != validated:
        raise Invalid('noncanonical staging inventory')
    entries = validated
    if set(contents) != set(entries):
        raise Invalid('incomplete stage input')
    for name, data in contents.items():
        if len(data) != entries[name]['size'] or hashlib.sha256(data).hexdigest() != entries[name]['sha256']:
            raise Invalid('stage data mismatch')
    output = tempfile.mkdtemp(prefix='meridian-offline-', dir=parent)
    journal = [('dir', output, os.lstat(output))]
    try:
        files = dict(contents)
        files['installation-plan.json'] = (json.dumps(plan(entries), indent=2) + '\n').encode()
        files['manifest.json'] = (json.dumps({'version': 1, 'files': [entries[k] for k in sorted(entries)]}, indent=2) + '\n').encode()
        for name, data in sorted(files.items()):
            current = output
            for part in PurePosixPath(name).parts[:-1]:
                current = os.path.join(current, part)
                if not os.path.exists(current):
                    os.mkdir(current, 0o700)
                    journal.append(('dir', current, os.lstat(current)))
            target = os.path.join(output, name)
            with open(target, 'xb') as stream:
                journal.append(('file', target, os.fstat(stream.fileno())))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(target, entries[name]['mode'] if name in entries else 0o444)
        return output
    except BaseException as cause:
        failures = []
        for kind, path, original in reversed(journal):
            try:
                actual = os.lstat(path)
                if (actual.st_dev, actual.st_ino) != (original.st_dev, original.st_ino):
                    failures.append(path)
                    continue
                (os.unlink if kind == 'file' else os.rmdir)(path)
            except OSError:
                failures.append(path)
        if failures:
            raise Invalid('rollback uncertain; retain and inspect staging directory: ' + output) from cause
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--passwd-export', help='optional administrator-supplied NSS passwd export, never collected automatically')
    parser.add_argument('--group-export', help='matching NSS group export; both required together')
    parser.add_argument('--stage-parent', help='optional trusted workspace directory; creates new private child only')
    args = parser.parse_args()
    try:
        with open(args.manifest, 'rb') as stream:
            entries = parse_manifest(stream.read(2 * 1024 * 1024 + 1))
        contents = read_bundle(args.bundle, entries)
        report = plan(entries)
        if bool(args.passwd_export) != bool(args.group_export):
            raise Invalid('both identity exports required')
        if args.passwd_export:
            snapshots = []
            for source in (args.passwd_export, args.group_export):
                with open(source, 'r', encoding='utf-8') as stream:
                    snapshot = stream.read(2 * 1024 * 1024 + 1)
                if len(snapshot) > 2 * 1024 * 1024:
                    raise Invalid('identity export too large')
                snapshots.append(snapshot)
            if identity_conflicts(*snapshots):
                raise Invalid('reserved identity conflict')
            report['identity_snapshot'] = 'No conflict in supplied exports; live NSS reservation remains required.'
        if args.stage_parent:
            source = os.path.realpath(args.bundle)
            parent = os.path.realpath(args.stage_parent)
            if os.path.commonpath([source, parent]) == source:
                raise Invalid('staging output cannot be nested inside source')
            report['staging_directory'] = stage(args.stage_parent, entries, contents)
        print(json.dumps(report, indent=2))
    except (Invalid, ValueError, OSError) as exc:
        # No raw JSON, artifact contents, account exports or credentials in diagnostics.
        detail = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        parser.exit(1, 'Offline provisioning refused: ' + detail + '\n')


if __name__ == '__main__':
    main()
