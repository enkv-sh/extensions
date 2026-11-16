#!/usr/bin/env python3
"""Stage checked files in one draft release without replacing existing assets."""
import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


class AssetRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        source, target = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(new_url)
        hosts = {'github.com', 'release-assets.githubusercontent.com'}
        asset_api = source.hostname == 'api.github.com' and '/releases/assets/' in source.path
        if not (asset_api or source.hostname in hosts) or target.scheme != 'https' or target.hostname not in hosts or target.username is not None or target.port not in [None, 443]:
            raise ValueError('unapproved release asset redirect')
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if redirected is None:
            raise ValueError('release asset redirect refused')
        redirected.remove_header('Authorization')
        return redirected


def api(method, url, token, data=None, content_type='application/json', limit=1048576):
    request = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': content_type})
    if method == 'GET' and content_type == 'application/octet-stream':
        request.add_header('Accept', 'application/octet-stream')
    with urllib.request.build_opener(AssetRedirects()).open(request, timeout=120) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('release response exceeds expected byte limit')
    return body if method == 'GET' and content_type == 'application/octet-stream' else json.loads(body)


def tag_commit(base, tag, source, token):
    try:
        reference = api('GET', base + '/git/ref/tags/' + urllib.parse.quote(tag, safe=''), token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            error.close()
            return None
        raise
    if reference['ref'] != 'refs/tags/' + tag:
        raise ValueError('tag reference differs')
    target = reference['object']
    seen = set()
    while target['type'] == 'tag':
        identity = target['sha']
        if identity in seen:
            raise ValueError('tag object cycle')
        seen.add(identity)
        annotated = api('GET', base + '/git/tags/' + identity, token)
        if annotated['sha'] != identity:
            raise ValueError('tag object identity differs')
        target = annotated['object']
    if target['type'] != 'commit' or target['sha'] != source:
        raise ValueError('release tag does not point to the exact source commit')
    return source


def find_draft(base, tag, token):
    matches = []
    page = 1
    while True:
        rows = api('GET', base + f'/releases?per_page=100&page={page}', token)
        matches.extend(row for row in rows if row['tag_name'] == tag)
        if len(rows) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise ValueError('multiple releases use the candidate tag')
    if matches and not matches[0]['draft']:
        raise ValueError('candidate tag already has a published release')
    return matches[0] if matches else None


def stage(repository, tag, source, directory, token):
    if repository not in ['enkv-sh/core', 'enkv-sh/extensions']:
        raise ValueError('unexpected release repository')
    if len(source) != 40 or any(c not in '0123456789abcdef' for c in source):
        raise ValueError('exact source commit required')
    local = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise ValueError('nonregular draft asset')
        local[path.name] = path.read_bytes()
    if not local:
        raise ValueError('empty draft candidate')
    base = 'https://api.github.com/repos/' + repository
    commit = api('GET', base + '/git/commits/' + source, token)
    if commit['sha'] != source:
        raise ValueError('source commit does not exist at the exact identity')
    initial_tag = tag_commit(base, tag, source, token)
    release = find_draft(base, tag, token)
    if release is None:
        if initial_tag is not None and tag_commit(base, tag, source, token) is None:
            raise ValueError('release tag disappeared')
        if initial_tag is None:
            tag_commit(base, tag, source, token)
        release = api('POST', base + '/releases', token, json.dumps({
            'tag_name': tag, 'target_commitish': source, 'name': 'ENKV beta candidate ' + tag,
            'draft': True, 'prerelease': True}).encode())
    release_id = release['id']
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise ValueError('draft has no numeric release identity')

    def check_release(fresh):
        if fresh['id'] != release_id or not fresh['draft'] or fresh['tag_name'] != tag:
            raise ValueError('release is not the exact draft')
        resolved = tag_commit(base, tag, source, token)
        if initial_tag is not None and resolved is None:
            raise ValueError('release tag disappeared')
        if resolved is None and fresh['target_commitish'] != source:
            raise ValueError('absent tag has a different pending source')
        return resolved

    check_release(release)
    existing = {}
    page = 1
    while True:
        rows = api('GET', base + f'/releases/{release_id}/assets?per_page=100&page={page}', token)
        for row in rows:
            if row['name'] in existing or row['name'] not in local or row['state'] != 'uploaded':
                raise ValueError('duplicate, unexpected or incomplete draft asset')
            existing[row['name']] = row
        if len(rows) < 100:
            break
        page += 1
    for name, row in existing.items():
        remote = api('GET', base + '/releases/assets/' + str(row['id']), token, content_type='application/octet-stream', limit=len(local[name]))
        if remote != local[name] or row['size'] != len(local[name]):
            raise ValueError('existing draft bytes differ')
    for name, body in local.items():
        if name in existing:
            continue
        fresh = api('GET', base + '/releases/' + str(release_id), token)
        check_release(fresh)
        url = f'https://uploads.github.com/repos/{repository}/releases/{release_id}/assets?name=' + urllib.parse.quote(name, safe='')
        row = api('POST', url, token, body, 'application/octet-stream')
        remote = api('GET', base + '/releases/assets/' + str(row['id']), token, content_type='application/octet-stream', limit=len(body))
        if row['name'] != name or row['state'] != 'uploaded' or row['size'] != len(body) or remote != body:
            raise ValueError('draft readback differs')
    final_tag = check_release(api('GET', base + '/releases/' + str(release_id), token))
    print(json.dumps({'draft_release_id': release_id, 'assets': len(local), 'tag_state': 'present' if final_tag is not None else 'absent'}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repository', required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--assets', type=Path, required=True)
    a = p.parse_args()
    try:
        stage(a.repository, a.tag, a.source, a.assets, os.environ['GH_TOKEN'])
    except urllib.error.HTTPError as error:
        error.close()
        raise SystemExit('draft HTTP operation failed') from None
    except urllib.error.URLError:
        raise SystemExit('draft HTTP operation failed') from None


if __name__ == '__main__':
    main()
