import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import provision as p


class OfflineProvisioning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'bundle'
        self.root.mkdir()
        self.content = {name: b'reviewed-fixture-not-real-ELF' for name in
                        p.REQUIRED_NOTICES | {'rootfs/bin/meridian-univpn', 'bootstrap/meridian-worker-bootstrap', 'rootfs/lib/libssl.so'}}
        self.rows = []
        for name, data in sorted(self.content.items()):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            mode = 0o555 if 'bin/' in name or name.startswith('bootstrap/') else 0o444
            path.chmod(mode)
            self.rows.append(dict(path=name, size=len(data), mode=mode, sha256=hashlib.sha256(data).hexdigest()))
        self.entries = self.parse(self.rows)

    def parse(self, rows):
        return p.parse_manifest(json.dumps(dict(version=1, files=rows)))

    def test_valid_bundle_and_disabled_stage(self):
        contents = p.read_bundle(self.root, self.entries)
        out = Path(p.stage(self.tmp.name, self.entries, contents))
        plan = json.loads((out / 'installation-plan.json').read_text())
        self.assertFalse(plan['activation_allowed'])
        self.assertFalse(plan['service_enabled'])
        self.assertFalse(plan['service_start'])
        for name, data in contents.items():
            self.assertEqual((out / name).read_bytes(), data)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)

    def test_unknown_duplicate_and_bad_types(self):
        for raw in ['{"version":1,"version":1,"files":[]}', '{"version":true,"files":[]}']:
            with self.assertRaises(p.Invalid): p.parse_manifest(raw)
        for key, value in [('size', True), ('mode', 0o4755), ('sha256', '0'*63), ('path', '../escape')]:
            rows = [dict(x) for x in self.rows]
            rows[0][key] = value
            with self.assertRaises(p.Invalid): self.parse(rows)
        with self.assertRaises(p.Invalid): self.parse(self.rows + [self.rows[0]])

    def test_forbidden_paths(self):
        for name in ['rootfs/proc/self', 'rootfs/sys/x', 'rootfs/dev/null', 'rootfs/bin/sh', 'rootfs/etc/shadow', '/rootfs/lib/x', 'rootfs/lib/../x', 'rootfs/lib//x']:
            row = dict(self.rows[0], path=name)
            with self.assertRaises(p.Invalid): self.parse(self.rows + [row])

    def test_missing_extra_hash_mode_hardlink_symlink(self):
        native = self.root / 'rootfs/bin/meridian-univpn'
        for mutation in ['hash', 'mode', 'hardlink', 'symlink', 'extra', 'directory']:
            with self.subTest(mutation=mutation):
                if mutation == 'hash':
                    native.chmod(0o755); native.write_bytes(b'x' * native.stat().st_size); native.chmod(0o555)
                if mutation == 'mode': native.chmod(0o755)
                if mutation == 'hardlink': os.link(native, self.root / 'link')
                if mutation == 'symlink':
                    native.unlink(); native.symlink_to('/etc/passwd')
                if mutation == 'extra': (self.root / 'extra').write_text('unexpected')
                if mutation == 'directory': (self.root / 'rootfs/lib').chmod(0o777)
                with self.assertRaises(p.Invalid): p.read_bundle(self.root, self.entries)
                if mutation == 'hardlink': (self.root / 'link').unlink()
                if mutation == 'extra': (self.root / 'extra').unlink()
                if mutation == 'directory': (self.root / 'rootfs/lib').chmod(0o755)
                native.unlink(missing_ok=True)
                native.write_bytes(self.content['rootfs/bin/meridian-univpn']); native.chmod(0o555)
        native.unlink()
        with self.assertRaises(p.Invalid): p.read_bundle(self.root, self.entries)

    def test_special_file(self):
        native = self.root / 'rootfs/bin/meridian-univpn'
        native.unlink(); os.mkfifo(native)
        with self.assertRaises(p.Invalid): p.read_bundle(self.root, self.entries)

    def test_stage_rollback_only_new_output(self):
        sentinel = Path(self.tmp.name) / 'keep'
        sentinel.write_text('retain')
        with patch.object(p.os, 'fsync', side_effect=OSError('injected')):
            with self.assertRaises(OSError): p.stage(self.tmp.name, self.entries, self.content)
        self.assertEqual(sentinel.read_text(), 'retain')
        self.assertEqual(list(Path(self.tmp.name).glob('meridian-offline-*')), [])

    def test_uncertain_rollback_retains(self):
        with patch.object(p.os, 'fsync', side_effect=OSError('injected')), patch.object(p.os, 'unlink', side_effect=OSError('injected')):
            with self.assertRaisesRegex(p.Invalid, 'rollback uncertain'):
                p.stage(self.tmp.name, self.entries, self.content)
        self.assertEqual(len(list(Path(self.tmp.name).glob('meridian-offline-*'))), 1)

    def test_no_stage_on_changed_data(self):
        contents = dict(self.content)
        contents['rootfs/bin/meridian-univpn'] = b'changed'
        with self.assertRaises(p.Invalid): p.stage(self.tmp.name, self.entries, contents)
        self.assertEqual(list(Path(self.tmp.name).glob('meridian-offline-*')), [])

    def test_staging_revalidates_paths(self):
        for name in ('../escaped', '/tmp/escaped'):
            entries = dict(self.entries)
            item = dict(self.rows[0], path=name)
            entries[name] = item
            contents = dict(self.content)
            contents[name] = self.content[self.rows[0]['path']]
            with self.assertRaises(p.Invalid): p.stage(self.tmp.name, entries, contents)
        entries = dict(self.entries)
        entries['../escaped'] = entries.pop(self.rows[0]['path'])
        with self.assertRaises(p.Invalid): p.stage(self.tmp.name, entries, self.content)
        self.assertEqual(list(Path(self.tmp.name).glob('meridian-offline-*')), [])

    def test_directory_change_rejected(self):
        real_listdir = os.listdir
        first = True
        def mutate(fd):
            nonlocal first
            result = real_listdir(fd)
            if first:
                first = False
                added = os.open('late', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                os.close(added)
            return result
        with patch.object(p.os, 'listdir', side_effect=mutate):
            with self.assertRaisesRegex(p.Invalid, 'directory changed during read'):
                p.read_bundle(self.root, self.entries)

    def test_xattrs_rejected(self):
        with patch.object(p.os, 'listxattr', return_value=['security.capability']):
            with self.assertRaises(p.Invalid): p.read_bundle(self.root, self.entries)

    def test_symlink_directory_rejected(self):
        lib = self.root / 'rootfs/lib'
        (lib / 'libssl.so').unlink(); lib.rmdir(); lib.symlink_to('/tmp')
        with self.assertRaises(p.Invalid): p.read_bundle(self.root, self.entries)

    def test_changed_source_rejected(self):
        real_read = os.read
        changed = False
        def change(fd, size):
            nonlocal changed
            data = real_read(fd, size)
            if not changed:
                changed = True
                info = os.fstat(fd)
                os.utime(fd, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
            return data
        with patch.object(p.os, 'read', side_effect=change):
            with self.assertRaisesRegex(p.Invalid, 'changed during read'):
                p.read_bundle(self.root, self.entries)

    def test_nss_conflicts_are_not_reuse_permission(self):
        self.assertEqual(p.identity_conflicts('root:x:0:0:root:/root:/bin/sh', 'root:x:0:'), [])
        for passwd, group in [('other:x:65532:1::/:/sbin/nologin', ''), ('other:x:1:65532::/:/sbin/nologin', ''), ('', 'other:x:65532:'), ('meridian-worker:x:123:123::/:/sbin/nologin', '')]:
            self.assertTrue(p.identity_conflicts(passwd, group))
        with self.assertRaises(p.Invalid): p.identity_conflicts('bad record', '')


if __name__ == '__main__': unittest.main()
