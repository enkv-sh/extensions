#!/usr/bin/env python3
"""Local draft-staging checks. All HTTP calls use an in-process mock."""
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
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('stage_release', Path(__file__).with_name('stage-release.py'))
stage_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_release)


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
        for condition in ['valid', 'rewrapped-development', 'same-key', 'swapped-development', 'unreviewed-source', 'different-source']:
            env = dict(os.environ, SOURCE_COMMIT='1' * 40, EXPECTED_SOURCE_COMMIT='1' * 40, WORKFLOW_COMMIT='3' * 40, EXPECTED_WORKFLOW_COMMIT='3' * 40, TOOLS_COMMIT='2' * 40, PREVIOUS_CATALOG_COMMIT='none', CLI_PUBLIC_KEY_PEM=pem(other, 64), PLUGIN_PUBLIC_KEY_PEM=pem(der, 32), DEVELOPMENT_CLI_KEY='0' * 64, DEVELOPMENT_PLUGIN_KEY='0' * 64)
            if condition == 'rewrapped-development':
                env['DEVELOPMENT_PLUGIN_KEY'] = hashlib.sha256(der).hexdigest()
            if condition == 'swapped-development':
                env['DEVELOPMENT_CLI_KEY'] = hashlib.sha256(der).hexdigest()
            if condition == 'same-key':
                env['CLI_PUBLIC_KEY_PEM'] = pem(der, 64)
            if condition == 'different-source':
                env['SOURCE_COMMIT'] = '4' * 40
            if condition == 'unreviewed-source':
                env['SOURCE_COMMIT'] = 'main'
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode == 0, condition == 'valid', condition)

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
