"""Offline release append tests: all HTTP and credentials are fixtures."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-linux-deb.py'))
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


class PublicationTests(unittest.TestCase):
    def exercise(self, collision=False, wrong_digest=False, concurrent=False):
        deb = b'fixture Debian bytes'
        digest = hashlib.sha256(deb).hexdigest()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr(pub.DEB, deb)
            z.writestr('SHA256SUMS-deb', digest + '  ' + pub.DEB + '\n')
            z.writestr('安装说明.md', '此候选安装包为修订版 SHA256SUMS-deb ' + pub.DEB)
        archive = archive.getvalue()
        old_assets = [dict(id=1, name=pub.ORIGINAL_INSTALLER, digest='sha256:' + pub.ORIGINAL_INSTALLER_SHA, size=5),
                      dict(id=2, name=pub.api['PACKAGE'], digest='sha256:' + pub.api['PACKAGE_SHA'], size=7)]
        if collision:
            old_assets.append(dict(id=3, name=pub.CHECKSUM, digest='sha256:existing', size=9))
        release = dict(tag_name=pub.api['TAG'], target_commitish=pub.api['SOURCE'], prerelease=True, draft=False,
                       body='Original Chinese safety notes 保留所有限制', assets=copy.deepcopy(old_assets), html_url='https://github.com/alanbulan/meridian-vpn/releases/tag/v0.1.0-alpha.1')
        uploaded, patched, downloads = {}, [], []
        def request(path, method='GET', payload=None):
            if path.endswith('/jobs'):
                return {'jobs': [dict(name=n, conclusion='success') for n in ('build', 'install (debian:trixie-slim)', 'install (ubuntu:24.04)')]}
            if path.startswith('/actions/runs/'):
                return dict(head_sha=pub.BUILD_SHA, status='completed', conclusion='success', event='push', path='.github/workflows/linux-deb.yml', head_branch='candidate/linux-minimal-20261104')
            if path.startswith('/actions/artifacts/'):
                return dict(expired=False, workflow_run={'id':pub.RUN}, digest='sha256:' + hashlib.sha256(archive).hexdigest())
            if path.startswith('/git/ref/tags/'):
                return {'object': {'type':'commit', 'sha':pub.api['SOURCE']}}
            self.assertEqual(path, '/releases/' + str(pub.RELEASE))
            if method == 'PATCH':
                patched.append(payload)
                release['body'] = payload['body']
            if concurrent and uploaded:
                release['body'] = 'Concurrent edit'
            return copy.deepcopy(release)
        def open_request(req, timeout):
            if req.full_url.endswith('/zip'):
                raise urllib.error.HTTPError(req.full_url, 302, 'redirect', {'Location':'https://fixture.invalid/artifact'}, None)
            self.assertEqual(req.method, 'POST')
            name = req.full_url.split('?name=')[1]
            self.assertNotIn(name, uploaded)
            self.assertNotIn(name, [a['name'] for a in old_assets])
            uploaded[name] = req.data
            entry = dict(id=100+len(uploaded), name=name, state='uploaded', size=len(req.data), digest='sha256:'+hashlib.sha256(req.data).hexdigest(), browser_download_url=f'https://github.com/{pub.api["REPO"]}/releases/download/{pub.api["TAG"]}/{name}')
            release['assets'].append(entry)
            return io.BytesIO(json.dumps(entry).encode())
        def urlopen(url, timeout):
            if url == 'https://fixture.invalid/artifact':
                return io.BytesIO(archive)
            name = url.rsplit('/',1)[1]
            downloads.append(name)
            return io.BytesIO(uploaded[name])
        with patch.dict(os.environ, GITHUB_REPOSITORY=pub.api['REPO'], GITHUB_REF='refs/heads/candidate/linux-minimal-20261104', GH_TOKEN='fixture'), patch.object(pub, 'request', side_effect=request), patch.object(pub, 'ZIP_SHA', hashlib.sha256(archive).hexdigest()), patch.object(pub, 'DEB_SHA', '0'*64 if wrong_digest else digest), patch.object(pub.urllib.request, 'build_opener') as opener, patch.object(pub.urllib.request, 'urlopen', side_effect=urlopen):
            opener.return_value.open.side_effect = open_request
            if collision or wrong_digest or concurrent:
                with self.assertRaises(RuntimeError): pub.main()
                self.assertFalse(patched)
                if not concurrent: self.assertFalse(uploaded)
            else:
                pub.main()
                self.assertEqual(set(uploaded), {pub.DOWNLOAD,pub.CHECKSUM,pub.GUIDE})
                self.assertEqual(set(downloads), set(uploaded))
                self.assertEqual(uploaded[pub.DOWNLOAD], deb)
                self.assertEqual(uploaded[pub.CHECKSUM], (digest+'  '+pub.DOWNLOAD+'\n').encode())
                self.assertIn(pub.CHECKSUM.encode(), uploaded[pub.GUIDE])
                self.assertNotIn(pub.DEB.encode(), uploaded[pub.GUIDE])
                self.assertTrue(release['body'].endswith('Original Chinese safety notes 保留所有限制'))
                self.assertEqual(release['assets'][:2], old_assets)
    def test_append_and_public_readback(self): self.exercise()
    def test_partial_upload_stops_without_write(self): self.exercise(collision=True)
    def test_bad_deb_stops_without_write(self): self.exercise(wrong_digest=True)
    def test_concurrent_notes_never_overwritten(self): self.exercise(concurrent=True)

if __name__ == '__main__': unittest.main()
