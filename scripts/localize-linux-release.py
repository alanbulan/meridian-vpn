#!/usr/bin/env python3
"""Translate one existing release; never create tags or change download files."""
import hashlib
import os
from pathlib import Path
import runpy

api = runpy.run_path(str(Path(__file__).with_name('publish-linux-alpha.py')))
request, require = api['request'], api['require']
RELEASE_ID = 433608769
SOURCE = api['SOURCE']
EXPECTED_BODY_SHA = '53878bc326d8e0934dffca32283ad374b41fcbea80ca10ae02b14ab95538dc41'
TITLE = 'Meridian 0.1.0-alpha.1：Linux amd64 测试版'


def identity(release):
    return {key: release[key] for key in ('id', 'tag_name', 'target_commitish', 'draft', 'prerelease')} | {
        'assets': sorted((a['id'], a['name'], a['size'], a['digest'], a['browser_download_url']) for a in release['assets'])}


def main():
    require(os.environ.get('GITHUB_REPOSITORY') == api['REPO'], 'Wrong repository')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/candidate/linux-minimal-20261104', 'Wrong branch')
    before = request('/releases/' + str(RELEASE_ID))
    require(before['id'] == RELEASE_ID and before['tag_name'] == api['TAG'] and before['target_commitish'] == SOURCE and not before['draft'] and before['prerelease'], 'Unexpected release identity')
    require(hashlib.sha256(before['body'].encode()).hexdigest() == EXPECTED_BODY_SHA, 'Release text changed; stop without overwriting')
    require(sorted((a['name'], a['digest']) for a in before['assets']) == [('SHA256SUMS', 'sha256:cb284132a63b4be41adfd3786d28904139057a9bf954385b456ade40ebfa7903'), (api['PACKAGE'], 'sha256:' + api['PACKAGE_SHA'])], 'Unexpected release assets')
    tag = request('/git/ref/tags/' + api['TAG'])
    require(tag['object']['type'] == 'commit' and tag['object']['sha'] == SOURCE, 'Unexpected tag target')
    body = Path('docs/releases/v0.1.0-alpha.1.zh-CN.md').read_text()
    updated = request('/releases/' + str(RELEASE_ID), 'PATCH', {'name': TITLE, 'body': body})
    require(identity(updated) == identity(before), 'Release identity/assets unexpectedly changed')
    after = request('/releases/' + str(RELEASE_ID))
    require(after['name'] == TITLE and after['body'] == body and identity(after) == identity(before), 'Translation read-back mismatch')
    tag_after = request('/git/ref/tags/' + api['TAG'])
    require(tag_after['object'] == tag['object'], 'Tag changed')
    print('Verified Chinese release title and description:', after['html_url'])


if __name__ == '__main__':
    main()
