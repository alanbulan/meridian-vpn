import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('run.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class AcceptanceTests(unittest.TestCase):
    def manifest(self, root):
        data = {'schema': 1, 'source_commit': 'a' * 40, 'architecture': 'arm64', 'distribution': 'development-preview', 'developer_id_signed': False, 'notarized': False, 'live_vpn_verified': False, 'files': []}
        for ext in ('dmg', 'pkg'):
            p = root / f'meridian-macos-arm64-development-preview.{ext}'
            p.write_bytes(ext.encode())
            data['files'].append({'name': p.name, 'bytes': p.stat().st_size, 'sha256': m.digest(p)})
        (root / 'manifest.json').write_text(json.dumps(data))
        return data

    def bundle(self, root):
        app = root / m.APP.name
        contents = app / 'Contents'
        contents.mkdir(parents=True)
        (contents / 'MacOS').mkdir()
        executable = contents / 'MacOS/meridian'
        executable.write_bytes(b'fixture')
        executable.chmod(0o755)
        (contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': m.IDENTIFIER, 'CFBundleExecutable': 'meridian'}))
        return app

    def test_guard_non_hosted_never_invokes_command(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted', 'RUNNER_OS': 'macOS'}):
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(m.platform, 'system', return_value='Darwin'), mock.patch.object(m, 'run') as run:
                with self.assertRaises(ValueError): m.guard('arm64', 'a' * 40)
                run.assert_not_called()

    def test_manifest_pins_commit_artifacts_and_no_production_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = self.manifest(root)
            self.assertEqual(set(m.validate_manifest(root, 'arm64', 'a' * 40)), {'.dmg', '.pkg'})
            with self.assertRaises(ValueError): m.validate_manifest(root, 'amd64', 'a' * 40)
            with self.assertRaises(ValueError): m.validate_manifest(root, 'arm64', 'b' * 40)
            for key in ('developer_id_signed', 'notarized', 'live_vpn_verified'):
                data[key] = True
                (root / 'manifest.json').write_text(json.dumps(data))
                with self.assertRaises(ValueError): m.validate_manifest(root, 'arm64', 'a' * 40)
                data[key] = False

    def test_manifest_rejects_modified_duplicate_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = self.manifest(root)
            (root / data['files'][0]['name']).write_bytes(b'bad')
            with self.assertRaises(ValueError): m.validate_manifest(root, 'arm64', 'a' * 40)
            data = self.manifest(root)
            data['files'][0]['name'] = '../escape.dmg'
            (root / 'manifest.json').write_text(json.dumps(data))
            with self.assertRaises(ValueError): m.validate_manifest(root, 'arm64', 'a' * 40)
            data = self.manifest(root)
            data['files'][1] = data['files'][0]
            (root / 'manifest.json').write_text(json.dumps(data))
            with self.assertRaises(ValueError): m.validate_manifest(root, 'arm64', 'a' * 40)

    def test_bundle_rejects_symlink_or_changed_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self.bundle(root)
            self.assertTrue(m.inventory(app))
            link = app / 'alias'
            link.symlink_to(root / 'missing')
            with self.assertRaises(ValueError): m.inventory(app)
            link.unlink()
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'other'}))
            with self.assertRaises(ValueError): m.inventory(app)

    def test_inventory_tracks_empty_directories_and_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self.bundle(Path(temp))
            before = m.inventory(app)
            (app / 'extra').mkdir()
            self.assertNotEqual(before, m.inventory(app))
            (app / 'extra').rmdir()
            (app / 'Contents/MacOS/meridian').chmod(0o644)
            with self.assertRaises(ValueError): m.inventory(app)

    def test_changed_application_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self.bundle(Path(temp))
            expected = m.inventory(app)
            (app / 'changed').write_text('changed')
            with mock.patch.object(m, 'APP', app), mock.patch.object(m, 'run') as run:
                with self.assertRaises(ValueError): m.remove_owned_app(expected)
                run.assert_not_called()

    def test_payload_rejects_extra_targets_scripts_and_relocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / 'Payload'
            payload.mkdir()
            self.bundle(payload)
            info = root / 'PackageInfo'
            base = f'<pkg-info identifier="{m.IDENTIFIER}" install-location="/Applications">{{}}</pkg-info>'
            info.write_text(base.format(''))
            self.assertEqual(m.validate_payload(root), payload / m.APP.name)
            info.write_text(base.format('<relocate/>'))
            self.assertEqual(m.validate_payload(root), payload / m.APP.name)
            for extra in ('<scripts/>', '<relocate><bundle id="other"/></relocate>'):
                info.write_text(base.format(extra))
                with self.assertRaises(ValueError): m.validate_payload(root)
            info.write_text(base.format(''))
            (payload / 'unowned').write_text('x')
            with self.assertRaises(ValueError): m.validate_payload(root)

    def test_network_snapshot_rejects_active_service(self):
        for state in ('Connected', 'Connecting', 'Disconnecting'):
            with mock.patch.object(m, 'run', return_value=mock.Mock(stdout=f'* ({state}) VPN'.encode())):
                with self.assertRaises(ValueError): m.network_observation()
        with mock.patch.object(m, 'run', return_value=mock.Mock(stdout=b'Available network connection services:')):
            self.assertEqual(len(m.network_observation()), 64)

    def test_signature_does_not_promote_adhoc_to_developer_id(self):
        for details, passes in [(b'Signature=adhoc\nTeamIdentifier=not set', True), (b'Authority=Developer ID Application', False), (b'Signature=adhoc\nAuthority=Developer ID', False)]:
            with mock.patch.object(m, 'run', return_value=mock.Mock(stderr=details)):
                if passes: m.verify_signature(Path('test.app'))
                else:
                    with self.assertRaises(ValueError): m.verify_signature(Path('test.app'))


if __name__ == '__main__': unittest.main()
