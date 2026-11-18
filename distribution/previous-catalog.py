#!/usr/bin/env python3
"""Require the source catalog to retain every published plugin payload."""
import argparse
import json
import http.client
import os
from pathlib import Path
import re
import urllib.parse

API = 'https://api.github.com/repos/enkv-sh/extensions'
DOWNLOADS = 'https://github.com/enkv-sh/extensions/releases/download/'


def read_json(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or not parsed.path.startswith('/repos/enkv-sh/extensions/') or parsed.fragment:
        raise ValueError('published release API location differs')
    headers = {'Accept': 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'enkv-release'}
    token = os.environ.get('GH_TOKEN', '')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    connection = http.client.HTTPSConnection('api.github.com', timeout=30)
    try:
        connection.request('GET', parsed.path + '?' + parsed.query, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('published release API returned status ' + str(response.status))
        body = response.read(2097153)
    finally:
        connection.close()
    if len(body) > 2097152:
        raise ValueError('published release response exceeds byte limit')
    return json.loads(body)


def pages(path, per_page=100):
    seen = set()
    page = 1
    while True:
        rows = read_json(API + path + '?per_page=' + str(per_page) + '&page=' + str(page))
        if not isinstance(rows, list) or len(rows) > per_page:
            raise ValueError('invalid published release list')
        for row in rows:
            if not isinstance(row, dict) or type(row.get('id')) is not int or row['id'] <= 0 or row['id'] in seen:
                raise ValueError('invalid or repeated published release identity')
            seen.add(row['id'])
            yield row
        if len(rows) < per_page:
            return
        page += 1


def check(source):
    releases = list(pages('/releases', per_page=5))
    if any(type(release.get('draft')) is not bool for release in releases):
        raise ValueError('invalid release publication state')
    releases = [release for release in releases if not release['draft']]
    catalog = source / 'distribution/catalog'
    if not releases:
        if catalog.exists() or catalog.is_symlink():
            raise ValueError('source catalog has no published predecessor')
        return False
    published = set()
    for release in releases:
        tag = release.get('tag_name')
        if release.get('draft') is not False or type(release.get('prerelease')) is not bool or not isinstance(tag, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', tag):
            raise ValueError('invalid published plugin release')
        payloads = set()
        for asset in pages('/releases/' + str(release['id']) + '/assets'):
            name = asset.get('name')
            if not isinstance(name, str) or asset.get('state') != 'uploaded':
                raise ValueError('invalid published plugin asset')
            if name.endswith('.tar.gz'):
                expected = DOWNLOADS + urllib.parse.quote(tag, safe='') + '/' + urllib.parse.quote(name, safe='')
                if asset.get('browser_download_url') != expected or expected in payloads:
                    raise ValueError('published payload location differs')
                payloads.add(expected)
        if not payloads or published & payloads:
            raise ValueError('published plugin release has missing or repeated payloads')
        published.update(payloads)
    if catalog.is_symlink() or not catalog.is_dir():
        raise ValueError('published plugins require distribution/catalog in the release source')
    redirects_file = catalog / 'redirects.json'
    if redirects_file.is_symlink() or not redirects_file.is_file():
        raise ValueError('previous catalog redirects are missing or nonregular')
    redirects = json.loads(redirects_file.read_text())
    if not isinstance(redirects, list):
        raise ValueError('invalid previous catalog redirects')
    retained, paths = set(), set()
    for row in redirects:
        if not isinstance(row, dict) or set(row) != {'path', 'url'} or not isinstance(row['path'], str) or not isinstance(row['url'], str) or row['path'] in paths:
            raise ValueError('invalid or duplicate previous catalog redirect')
        paths.add(row['path'])
        url = row['url']
        if url.startswith(DOWNLOADS):
            retained.add(url)
        elif not url.startswith('https://github.com/enkv-sh/core/releases/download/'):
            raise ValueError('previous catalog payload host differs')
    if retained != published:
        raise ValueError('previous catalog differs from published plugin payloads')
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    print('published predecessor retained' if check(args.source) else 'first plugin release')
