#!/usr/bin/env python3
"""Local release workflow and staging checks with mocked HTTP calls."""
import importlib.util
import json
import os
import base64
import hashlib
import subprocess
import textwrap
import shutil
import tarfile
from pathlib import Path
import tempfile
import unittest
import urllib.request
import urllib.error
import io
from contextlib import redirect_stdout
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location('stage_release', Path(__file__).with_name('stage-release.py'))
stage_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_release)


class CatalogPredecessorTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('previous_catalog', Path(__file__).with_name('previous-catalog.py'))
        self.previous = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.previous)

    def test_first_release_requires_positive_empty_history(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch)
            with patch.object(self.previous, 'read_json', return_value=[]):
                self.assertFalse(self.previous.check(source))
            for error in [OSError('unavailable'), ValueError('invalid JSON')]:
                with patch.object(self.previous, 'read_json', side_effect=error), self.assertRaises(type(error)):
                    self.previous.check(source)
            with patch.object(self.previous, 'read_json', return_value={}), self.assertRaises(ValueError):
                self.previous.check(source)
            catalog = source / 'distribution/catalog'
            catalog.mkdir(parents=True)
            (catalog / 'redirects.json').write_text('[]')
            with patch.object(self.previous, 'read_json', return_value=[]), self.assertRaises(ValueError):
                self.previous.check(source)

    def test_first_candidate_with_only_drafts_has_no_predecessor(self):
        draft = {'id': 1, 'tag_name': 'plugins-v0.1.0', 'draft': True, 'prerelease': True}
        with tempfile.TemporaryDirectory() as scratch, patch.object(self.previous, 'read_json', return_value=[draft]):
            self.assertFalse(self.previous.check(Path(scratch)))

    def test_api_token_stays_on_fixed_host_and_redirects_refuse(self):
        for token in ['', 'scoped-workflow-token']:
            connection = Mock()
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = b'[]'
            with patch.dict(os.environ, GH_TOKEN=token), patch.object(self.previous.http.client, 'HTTPSConnection', return_value=connection) as factory:
                self.assertEqual(self.previous.read_json(self.previous.API + '/releases?per_page=5&page=1'), [])
            factory.assert_called_once_with('api.github.com', timeout=30)
            headers = connection.request.call_args.kwargs['headers']
            self.assertEqual(headers.get('Authorization'), 'Bearer ' + token if token else None)
            self.assertEqual(connection.request.call_args.args[:2], ('GET', '/repos/enkv-sh/extensions/releases?per_page=5&page=1'))
            connection.close.assert_called_once()
        for status in [301, 302, 403, 404, 500]:
            connection = Mock()
            connection.getresponse.return_value.status = status
            with patch.object(self.previous.http.client, 'HTTPSConnection', return_value=connection), self.assertRaises(ValueError):
                self.previous.read_json(self.previous.API + '/releases?per_page=5&page=1')
            connection.getresponse.return_value.read.assert_not_called()
            connection.close.assert_called_once()
        for body in [b'{', b' ' * 2097153]:
            connection = Mock()
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = body
            with patch.object(self.previous.http.client, 'HTTPSConnection', return_value=connection), self.assertRaises(ValueError):
                self.previous.read_json(self.previous.API + '/releases?per_page=5&page=1')
            connection.close.assert_called_once()
        with patch.object(self.previous.http.client, 'HTTPSConnection') as connection, self.assertRaises(ValueError):
            self.previous.read_json('https://evil.test/releases')
        connection.assert_not_called()

    def test_catalog_must_cover_all_published_release_assets(self):
        base = 'https://api.github.com/repos/enkv-sh/extensions'
        urls = ['https://github.com/enkv-sh/extensions/releases/download/plugins-v0.' + str(i) + '/plugin-' + str(i) + '.tar.gz' for i in [1, 2]]
        releases = [{'id': i, 'tag_name': 'plugins-v0.' + str(i), 'draft': False, 'prerelease': i == 2} for i in [1, 2]]
        releases[0]['tag_name'] = 'beta.2026_1'
        urls[0] = 'https://github.com/enkv-sh/extensions/releases/download/beta.2026_1/plugin-1.tar.gz'
        calls = []
        def read(url):
            calls.append(url)
            if url == base + '/releases?per_page=5&page=1':
                return releases
            for i in [1, 2]:
                if url == base + '/releases/' + str(i) + '/assets?per_page=100&page=1':
                    return [{'id': 10 + i, 'name': 'plugin-' + str(i) + '.tar.gz', 'state': 'uploaded', 'browser_download_url': urls[i - 1]}]
            self.fail(url)
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch)
            catalog = source / 'distribution/catalog'
            with patch.object(self.previous, 'read_json', side_effect=read), self.assertRaises(ValueError):
                self.previous.check(source)
            catalog.mkdir(parents=True)
            for condition in ['complete', 'stale', 'unpublished', 'bad-host', 'duplicate']:
                selected = urls[:1] if condition == 'stale' else list(urls)
                if condition == 'unpublished':
                    selected.append('https://github.com/enkv-sh/extensions/releases/download/future/plugin.tar.gz')
                if condition == 'bad-host':
                    selected[0] = 'https://evil.test/' + selected[0].split('/')[-1]
                redirects = [{'path': '/releases/artifacts/' + str(i) + '/plugin.tar.gz', 'url': url} for i, url in enumerate(selected)]
                redirects += [{'path': '/releases/plugins/name/' + str(i) + '/plugin.tar.gz', 'url': url} for i, url in enumerate(selected)]
                if condition == 'duplicate':
                    redirects.append(redirects[0])
                (catalog / 'redirects.json').write_text(json.dumps(redirects))
                with self.subTest(condition=condition), patch.object(self.previous, 'read_json', side_effect=read):
                    if condition == 'complete':
                        self.assertTrue(self.previous.check(source))
                    else:
                        with self.assertRaises(ValueError):
                            self.previous.check(source)
            self.assertIn(base + '/releases/2/assets?per_page=100&page=1', calls)

    def test_pagination_and_failed_asset_reads_refuse(self):
        pages = [[{'id': i} for i in range(1, 101)], [{'id': 101}]]
        with patch.object(self.previous, 'read_json', side_effect=pages) as call:
            self.assertEqual(len(list(self.previous.pages('/releases'))), 101)
            self.assertTrue(call.call_args.args[0].endswith('page=2'))
        pages = [[{'id': i}] for i in range(1, 103)] + [[]]
        with patch.object(self.previous, 'read_json', side_effect=pages):
            self.assertEqual(len(list(self.previous.pages('/releases', per_page=1))), 102)
        with patch.object(self.previous, 'read_json', return_value=[{'id': 1}, {'id': 1}]), self.assertRaises(ValueError):
            list(self.previous.pages('/releases'))
        release = [{'id': 1, 'tag_name': 'plugins-v1', 'draft': False, 'prerelease': False}]
        with tempfile.TemporaryDirectory() as scratch:
            for value in [OSError('assets unavailable'), [], [{'id': 2, 'name': 'x.tar.gz', 'state': 'uploaded', 'browser_download_url': 'https://evil.test/x.tar.gz'}]]:
                with patch.object(self.previous, 'read_json', side_effect=[release, value]), self.assertRaises((ValueError, OSError)):
                    self.previous.check(Path(scratch))


class StagingTests(unittest.TestCase):
    def test_asset_redirect_drops_auth_and_refuses_unapproved_hosts(self):
        request = urllib.request.Request('https://api.github.com/repos/enkv-sh/core/releases/assets/1', headers={'Authorization': 'Bearer local-mock'})
        handler = stage_release.AssetRedirects()
        redirected = handler.redirect_request(request, None, 302, 'Found', {}, 'https://release-assets.githubusercontent.com/a?token=public-signed-url')
        self.assertFalse(redirected.has_header('Authorization'))
        for url in ['https://evil.test/a', 'http://github.com/a', 'https://github.com.evil.test/a', 'https://user@github.com/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'Found', {}, url)

    def test_workflow_preflight_compares_spki_identity(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/release.yml'
        text = workflow.read_text().split('      - name: Check owner release inputs\n', 1)[1].split('        run: |\n', 1)[1]
        lines = []
        for line in text.splitlines():
            if line and not line.startswith('          '):
                break
            lines.append(line[10:])
        script = '\n'.join(lines)
        der = bytes.fromhex('302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        other = bytes.fromhex('302a300506032b65700321003d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
        def pem(body, width):
            encoded = base64.b64encode(body).decode()
            return '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(textwrap.wrap(encoded, width)) + '\n-----END PUBLIC KEY-----\n'
        for condition in ['valid', 'valid-rewrapped', 'rewrapped-development', 'same-key', 'swapped-development', 'invalid-source', 'unprotected-source']:
            env = dict(os.environ, SOURCE_COMMIT='1' * 40, SOURCE_PROTECTED='true', CLI_PUBLIC_KEY_PEM=pem(other, 64), PLUGIN_PUBLIC_KEY_PEM=pem(der, 32), DEVELOPMENT_CLI_KEY='0' * 64, DEVELOPMENT_PLUGIN_KEY='0' * 64)
            if condition == 'valid-rewrapped':
                env['CLI_PUBLIC_KEY_PEM'] = pem(other, 16)
            if condition == 'rewrapped-development':
                env['DEVELOPMENT_PLUGIN_KEY'] = hashlib.sha256(der).hexdigest()
            if condition == 'swapped-development':
                env['DEVELOPMENT_CLI_KEY'] = hashlib.sha256(der).hexdigest()
            if condition == 'same-key':
                env['CLI_PUBLIC_KEY_PEM'] = pem(der, 64)
            if condition == 'unprotected-source':
                env['SOURCE_PROTECTED'] = 'false'
            if condition == 'invalid-source':
                env['SOURCE_COMMIT'] = 'main'
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode == 0, condition in ['valid', 'valid-rewrapped'], condition)

    def test_plugin_workflow_uses_dispatch_source_for_every_checkout(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/release.yml').read_text()
        self.assertNotIn('inputs:', text)
        self.assertNotIn('RELEASE_', '\n'.join(line for line in text.splitlines() if 'vars.' in line))
        self.assertIn("github.repository == 'enkv-sh/extensions' && github.ref == 'refs/heads/main'", text)
        references = [line.strip() for line in text.splitlines() if line.strip().startswith('ref:')]
        self.assertEqual(len(references), 12)
        self.assertEqual(set(references), {'ref: ${{ github.sha }}'})
        self.assertEqual(text.count('SOURCE_COMMIT: ${{ github.sha }}'), 3)
        self.assertEqual(text.count('run: python3 tools-source/distribution/previous-catalog.py --source source'), 3)
        self.assertIn('previous=(--previous-catalog "$GITHUB_WORKSPACE/source/distribution/catalog")', text)

    def test_native_build_metadata_sign_and_prepared_source_archive(self):
        extensions = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tools = root / 'tools'
            (tools / 'bin').mkdir(parents=True)
            (tools / 'distribution').mkdir()
            shutil.copyfile(extensions / 'distribution/release.json', tools / 'distribution/release.json')
            env = dict(os.environ, GOWORK='off', GOPROXY='off', GOSUMDB='off')
            for key in ['GOFLAGS', 'GOEXPERIMENT', 'CC', 'CXX', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_FFLAGS', 'CGO_LDFLAGS', 'GOTOOLDIR', 'GOCACHEPROG', 'GOFIPS140', 'GODEBUG']:
                env.pop(key, None)
            def execute(*args):
                result = subprocess.run([str(x) for x in args], env=env, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr.decode()[-8000:])
                return result.stdout
            for tool in ['enkv-release', 'enkv-plugin-build', 'enkv-artifact-sign']:
                execute('go', '-C', extensions / 'sdk/artifact', 'build', '-mod=readonly', '-o', tools / 'bin' / tool, './cmd/' + tool)
            source = root / 'source'
            module = source / 'plugins/manifest-generators/generic-json'
            command = module / 'cmd/enkv-manifest-generic-json'
            command.mkdir(parents=True)
            (module / 'go.mod').write_text('module enkv.sh/plugins/manifest-generators/generic-json\n\ngo 1.27.0\n')
            (module / 'go.sum').write_bytes(b'')
            (module / 'LICENSE').write_text('synthetic test license\n')
            (command / 'main.go').write_text('package main\nfunc main(){panic("payload execution is forbidden")}\n')
            shutil.copyfile(extensions / 'plugins/manifest-generators/generic-json/cmd/enkv-manifest-generic-json/plugin.json', command / 'plugin.json')
            env['PLUGIN_PUBLIC_KEY_PEM'] = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n'
            env['CLI_PUBLIC_KEY_PEM'] = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n-----END PUBLIC KEY-----\n'
            private = root / 'private.pem'
            private.write_text('-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n')
            script = extensions / 'distribution/release.py'
            work = root / 'build'
            execute('python3', script, 'build-plugin', '--source', source, '--tools', tools, '--work', work, '--name', 'generic-json')
            signature = root / 'metadata.sig'
            execute(tools / 'bin/enkv-artifact-sign', '-purpose', 'plugin-executable', '-input', work / 'metadata.json', '-key', private, '-output', signature)
            unpacked = root / 'archive'
            unpacked.mkdir()
            execute('tar', '-xf', work / 'prepared.tar', '-C', unpacked)
            with tarfile.open(work / 'prepared.tar') as transport:
                self.assertFalse(any('private.pem' in name for name in transport.getnames()))
            shutil.copyfile(signature, unpacked / 'metadata.sig')
            self.assertEqual((unpacked / 'source/plugins/manifest-generators/generic-json/go.sum').read_bytes(), (module / 'go.sum').read_bytes())
            marker = json.loads((unpacked / 'build/build.json').read_text())
            self.assertTrue((unpacked / 'build' / marker['directory'] / 'plugin').stat().st_mode & 0o111)
            execute('python3', script, 'archive-plugin', '--source', source, '--tools', tools, '--work', unpacked, '--name', 'generic-json')
            execute(tools / 'bin/enkv-artifact-sign', '-purpose', 'plugin-archive', '-input', unpacked / 'archive/archive.json', '-key', private, '-output', root / 'archive.sig')
            execute(tools / 'bin/enkv-artifact-sign', '-verify', '-purpose', 'plugin-archive', '-input', unpacked / 'archive/archive.json', '-key', unpacked / 'candidate/keys/plugin-public.pem', '-signature', root / 'archive.sig')

    def exercise(self, condition):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / 'one.tar.gz').write_bytes(b'abc')
            calls, uploads, creations = [], [], []
            source, tag = '1' * 40, 'v0.1.0-beta.1'
            base = 'https://api.github.com/repos/enkv-sh/core'
            release = {'id': 19, 'draft': condition != 'published', 'tag_name': tag, 'target_commitish': source}
            if condition == 'wrong-source':
                release['target_commitish'] = '2' * 40
            if condition in ['correct-lightweight', 'correct-annotated']:
                release['target_commitish'] = 'main'
            row = {'id': 21, 'name': 'one.tar.gz', 'state': 'uploaded', 'size': 3}
            tag_reads = 0
            def absent(url):
                error = urllib.error.HTTPError(url, 404, 'not found', {}, None)
                error.close()
                raise error
            def api(method, url, token, data=None, content_type='application/json', **options):
                nonlocal tag_reads
                calls.append((method, url))
                if method == 'POST':
                    if url == base + '/releases':
                        self.assertEqual(json.loads(data)['target_commitish'], source)
                        self.assertTrue(json.loads(data)['draft'])
                        creations.append(data)
                        return release
                    self.assertIn('/releases/19/assets?', url)
                    uploads.append(data)
                    return row
                if url == base + '/git/commits/' + source:
                    if condition == 'missing-source':
                        return absent(url)
                    return {'sha': source}
                if url == base + '/git/ref/tags/' + tag:
                    tag_reads += 1
                    if condition in ['tag-changed-before-upload', 'tag-deleted-before-upload', 'tag-changed-after-upload']:
                        if tag_reads == 1 or condition == 'tag-changed-after-upload' and tag_reads <= 3:
                            return {'ref': 'refs/tags/' + tag, 'object': {'type': 'commit', 'sha': source}}
                        if condition == 'tag-deleted-before-upload':
                            return absent(url)
                        return {'ref': 'refs/tags/' + tag, 'object': {'type': 'commit', 'sha': '2' * 40}}
                    if condition in ['correct-lightweight', 'wrong-lightweight']:
                        return {'ref': 'refs/tags/' + tag, 'object': {'type': 'commit', 'sha': source if condition == 'correct-lightweight' else '2' * 40}}
                    if condition in ['correct-annotated', 'wrong-annotated']:
                        return {'ref': 'refs/tags/' + tag, 'object': {'type': 'tag', 'sha': '3' * 40}}
                    return absent(url)
                if url == base + '/git/tags/' + '3' * 40:
                    return {'sha': '3' * 40, 'object': {'type': 'commit', 'sha': source if condition == 'correct-annotated' else '2' * 40}}
                if url.startswith(base + '/releases?'):
                    page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['page'][0])
                    if condition == 'absent-tag-new-draft':
                        return []
                    if condition == 'draft-later-page':
                        return [dict(release, id=100 + i, tag_name='other-' + str(i)) for i in range(100)] if page == 1 else [release]
                    if condition == 'duplicate-drafts':
                        return [dict(release, id=100 + i, tag_name='other-' + str(i)) for i in range(99)] + [release] if page == 1 else [dict(release, id=20)]
                    return [release]
                if '/releases/19/assets?' in url:
                    if condition in ['missing', 'absent-tag-new-draft', 'tag-changed-before-upload', 'tag-deleted-before-upload', 'tag-changed-after-upload']:
                        return []
                    if condition == 'duplicate':
                        return [row, row]
                    if condition == 'unexpected':
                        return [dict(row, name='unexpected')]
                    if condition == 'incomplete':
                        return [dict(row, state='new')]
                    return [row]
                if url == base + '/releases/assets/21':
                    return b'bad' if condition == 'corrupt' else b'abc'
                if url == base + '/releases/19':
                    return release
                self.fail('unexpected API request: ' + method + ' ' + url)
            success = condition in ['complete', 'missing', 'absent-tag-new-draft', 'correct-lightweight', 'correct-annotated', 'draft-later-page']
            output = io.StringIO()
            with patch.object(stage_release, 'api', api), redirect_stdout(output):
                if success:
                    stage_release.stage('enkv-sh/core', tag, source, root, 'local-mock')
                else:
                    with self.assertRaises((ValueError, urllib.error.HTTPError)):
                        stage_release.stage('enkv-sh/core', tag, source, root, 'local-mock')
            self.assertEqual(uploads, [b'abc'] if condition in ['missing', 'absent-tag-new-draft', 'tag-changed-after-upload'] else [])
            self.assertEqual(len(creations), 1 if condition == 'absent-tag-new-draft' else 0)
            if success:
                facts = json.loads(output.getvalue())
                self.assertEqual(facts['tag_state'], 'present' if condition in ['correct-lightweight', 'correct-annotated'] else 'absent')
                self.assertGreaterEqual(tag_reads, 2)
            if condition == 'draft-later-page':
                self.assertTrue(any('/releases?per_page=100&page=2' in url for _, url in calls))

    def test_stage_refusals_and_exact_partial_reuse(self):
        for condition in ['complete', 'missing', 'published', 'wrong-source', 'duplicate', 'unexpected', 'incomplete', 'corrupt']:
            with self.subTest(condition=condition):
                self.exercise(condition)

    def test_actual_tag_identity_and_paginated_draft_discovery(self):
        for condition in ['absent-tag-new-draft', 'correct-lightweight', 'wrong-lightweight', 'correct-annotated', 'wrong-annotated', 'draft-later-page', 'duplicate-drafts', 'missing-source', 'tag-changed-before-upload', 'tag-deleted-before-upload', 'tag-changed-after-upload']:
            with self.subTest(condition=condition):
                self.exercise(condition)


if __name__ == '__main__':
    unittest.main()
