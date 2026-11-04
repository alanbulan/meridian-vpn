#!/usr/bin/env python3
"""One bounded publication of an already verified artifact, never a rebuild."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import urllib.error
import urllib.request
import zipfile

REPO = 'alanbulan/meridian-vpn'
SOURCE = '8e0aaa94034e44150345733dc482126a03469d9a'
TAG = 'v0.1.0-alpha.1'
VERSION = '0.1.0-alpha.1'
RUN = 41788337017
CI = 41788337082
ARTIFACT = 13301874082
ZIP_SHA = 'c920607b3afb80c14cc2564c834971e0194f2415c331e493cf32912b35aac774'
PACKAGE_SHA = '9247a8c826b7f8683ac4758e52fddb5df0e66e8eba3d115bdbe5501073c99d36'
PACKAGE = 'meridian-linux-amd64.tar.gz'
API = 'https://api.github.com/repos/' + REPO


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(path, method='GET', payload=None, raw=False, missing=False):
    url = API + path
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
    })
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=60) as response:
            result = response.read()
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None
        raise RuntimeError(f'GitHub {method} {path} failed: HTTP {error.code}') from None
    return result if raw else json.loads(result)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Wrong repository')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/candidate/linux-minimal-20261104', 'Wrong ref')
    publication = os.environ['PUBLICATION_COMMIT']
    require(len(publication) == 40 and all(c in '0123456789abcdef' for c in publication), 'Invalid workflow SHA')
    for run_id in (RUN, CI):
        run = request(f'/actions/runs/{run_id}')
        require(run['head_sha'] == SOURCE and run['conclusion'] == 'success' and run['status'] == 'completed', 'Original build/CI not successful at exact source')
    artifact = request(f'/actions/artifacts/{ARTIFACT}')
    require(not artifact['expired'] and artifact['workflow_run']['id'] == RUN, 'Wrong or expired artifact')
    require(artifact['digest'] == 'sha256:' + ZIP_SHA, 'Artifact digest changed')
    # Obtain an unsigned redirect URL without forwarding the GitHub token off-host.
    req = urllib.request.Request(API + f'/actions/artifacts/{ARTIFACT}/zip', headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json'})
    try:
        urllib.request.build_opener(NoRedirect).open(req, timeout=60)
        raise RuntimeError('Expected artifact redirect')
    except urllib.error.HTTPError as error:
        require(error.code == 302, 'Artifact redirect unavailable')
        location = error.headers['Location']
    require(location.startswith('https://'), 'Insecure artifact redirect')
    with urllib.request.urlopen(location, timeout=60) as response:
        archive = response.read()
    require(hashlib.sha256(archive).hexdigest() == ZIP_SHA, 'ZIP checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        require(sorted(z.namelist()) == ['SHA256SUMS', PACKAGE], 'Unexpected artifact contents')
        package = z.read(PACKAGE)
    require(hashlib.sha256(package).hexdigest() == PACKAGE_SHA, 'Package checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as tar:
        manifests = [m for m in tar.getmembers() if m.name.endswith('/build-manifest.json') or m.name == 'build-manifest.json']
        require(len(manifests) == 1 and manifests[0].isfile(), 'Ambiguous manifest')
        manifest = json.load(tar.extractfile(manifests[0]))
        require(manifest['source_commit'] == SOURCE and manifest['version'] == VERSION and manifest['target'] == 'linux-amd64' and manifest['mfa_helper'] is True, 'Wrong package metadata')
    require(request('/git/ref/tags/' + TAG, missing=True) is None, 'Tag already exists; stop without replacement')
    require(request('/releases/tags/' + TAG, missing=True) is None, 'Release already exists; stop without replacement')
    notes = Path('docs/releases/' + TAG + '.md').read_text()
    notes += '\nPublication workflow commit: `' + publication + '`. The published artifact and tag retain the independently built source commit `' + SOURCE + '`; the workflow commit is not the binary source.\n'
    created_tag = request('/git/refs', 'POST', {'ref': 'refs/tags/' + TAG, 'sha': SOURCE})
    require(created_tag['object']['type'] == 'commit' and created_tag['object']['sha'] == SOURCE, 'Unexpected created tag')
    verified_tag = request('/git/ref/tags/' + TAG)
    require(verified_tag['object']['type'] == 'commit' and verified_tag['object']['sha'] == SOURCE, 'Created tag verification failed')
    release = request('/releases', 'POST', {
        'tag_name': TAG, 'target_commitish': SOURCE,
        'name': 'Meridian ' + VERSION + ' — Linux amd64 alpha',
        'body': notes, 'draft': True, 'prerelease': True, 'make_latest': 'false',
    })
    release_id = release['id']
    require(release['draft'] and release['tag_name'] == TAG, 'Unexpected draft response')
    for name, data, content_type in (
        (PACKAGE, package, 'application/gzip'),
        ('SHA256SUMS', (PACKAGE_SHA + '  ' + PACKAGE + '\n').encode(), 'text/plain'),
    ):
        url = f'https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name={name}'
        req = urllib.request.Request(url, data=data, method='POST', headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Content-Type': content_type,
            'Accept': 'application/vnd.github+json'})
        with urllib.request.build_opener(NoRedirect).open(req, timeout=120) as response:
            uploaded = json.load(response)
        require(uploaded['state'] == 'uploaded' and uploaded['size'] == len(data) and uploaded['digest'] == 'sha256:' + hashlib.sha256(data).hexdigest(), 'Uploaded asset verification failed; draft retained')
    before_publish_tag = request('/git/ref/tags/' + TAG, missing=True)
    require(before_publish_tag is not None and before_publish_tag['object']['type'] == 'commit' and before_publish_tag['object']['sha'] == SOURCE, 'Conflicting tag appeared; draft retained')
    published = request(f'/releases/{release_id}', 'PATCH', {'draft': False, 'prerelease': True, 'make_latest': 'false'})
    require(not published['draft'] and published['prerelease'], 'Release not public alpha')
    tag = request('/git/ref/tags/' + TAG)
    require(tag['object']['sha'] == SOURCE and tag['object']['type'] == 'commit', 'Unexpected release tag target')
    print('Published verified Linux alpha:', published['html_url'])


if __name__ == '__main__':
    main()
