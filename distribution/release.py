#!/usr/bin/env python3
"""Native release phases. Keys are opened only by the signing phases."""
import argparse
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tarfile


def call(*args, cwd=None):
    subprocess.run([str(x) for x in args], cwd=cwd, check=True)


def capture(module, destination):
    destination.mkdir(parents=True, exist_ok=True)
    environment = {'ambient_go_env': json.loads(subprocess.check_output(['go', 'env', '-json', 'GOVERSION', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOAMD64', 'GOARM64', 'GOEXPERIMENT', 'GOTOOLCHAIN'], cwd=module))}
    environment['native_uname'] = list(platform.uname())
    environment['cc_version'] = subprocess.check_output(['cc', '--version'], text=True)
    (destination / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    (destination / 'modules.json').write_bytes(subprocess.check_output(['go', 'list', '-mod=readonly', '-m', '-json', 'all'], cwd=module))
    for name in ['go.mod', 'go.sum']:
        if (module / name).exists():
            shutil.copyfile(module / name, destination / name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['build-cli', 'build-plugin', 'sign-metadata', 'archive-plugin', 'finish-cli', 'finish-plugins'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--name')
    parser.add_argument('--commit')
    parser.add_argument('--previous-catalog', type=Path)
    args = parser.parse_args()
    source, tools, work = args.source.resolve(), args.tools.resolve(), args.work.resolve()
    inventory = json.loads((tools / 'distribution/release.json').read_text())
    binaries = tools / 'bin'
    release, builder, signer = (binaries / name for name in ['enkv-release', 'enkv-plugin-build', 'enkv-artifact-sign'])
    phase = args.phase
    work.mkdir(parents=True, exist_ok=True)
    keys = work / 'candidate/keys'
    keys.mkdir(parents=True, exist_ok=True)
    for name in ['cli', 'plugin']:
        body = os.environ[name.upper() + '_PUBLIC_KEY_PEM']
        (keys / (name + '-public.pem')).write_text(body.rstrip() + '\n')
    roots = ['-cli-public-key', keys / 'cli-public.pem', '-plugin-public-key', keys / 'plugin-public.pem']
    if phase.startswith('build-'):
        if phase == 'build-cli':
            module = source / 'compositions/full'
        else:
            plugin = next(p for p in inventory['plugins'] if p['name'] == args.name)
            module = source / plugin['directory']
        before = (module / 'go.mod').read_bytes()
        call('go', 'mod', 'download', 'all', cwd=module)
        if (module / 'go.mod').read_bytes() != before:
            raise RuntimeError('dependency preparation changed go.mod')
        if phase == 'build-cli':
            call(binaries / 'enkv-cli-package', '-directory', module, '-bundle', 'full', '-version', inventory['cli_version'], '-versioned', '-environment', 'production', *roots, '-output', work / 'cli')
            capture(module, work / 'cli/evidence')
        else:
            call(builder, '-directory', module, '-descriptor', plugin['descriptor'], '-command', plugin['command'], '-versioned', '-output', work / 'build')
            marker = json.loads((work / 'build/build.json').read_text())
            shutil.copyfile(work / 'build' / marker['directory'] / 'metadata.json', work / 'metadata.json')
            capture(module, work / 'evidence')
            (work / 'evidence/native-environment.txt').write_bytes(subprocess.check_output([release, 'floor', '-binary', work / 'build' / marker['directory'] / 'plugin']))
            (work / 'evidence/buildinfo.txt').write_bytes(subprocess.check_output(['go', 'version', '-m', work / 'build' / marker['directory'] / 'plugin']))
            with tarfile.open(work / 'prepared.tar', 'w') as archive:
                archive.add(source, arcname='source', filter=lambda item: None if '/.git/' in item.name or item.name.endswith('/.git') else item)
                archive.add(work / 'build', arcname='build')
                archive.add(work / 'evidence', arcname='evidence')
    elif phase == 'sign-metadata':
        # Sign only bounded canonical records. Never extract or execute prepared payloads here.
        for metadata in sorted(work.glob('incoming/*/metadata.json')):
            name = metadata.parent.name
            call(signer, '-purpose', 'plugin-executable', '-input', metadata, '-key', os.environ['PLUGIN_PRIVATE_KEY_FILE'], '-output', work / (name + '.sig'))
            call(signer, '-verify', '-purpose', 'plugin-executable', '-input', metadata, '-key', keys / 'plugin-public.pem', '-signature', work / (name + '.sig'))
    elif phase == 'archive-plugin':
        plugin = next(p for p in inventory['plugins'] if p['name'] == args.name)
        call(builder, '-archive', work / 'build', '-directory', work / 'source' / plugin['directory'], '-command', plugin['command'], '-versioned', '-metadata-signature', work / 'metadata.sig', '-output', work / 'archive')
        shutil.copytree(work / 'evidence', work / 'archive/evidence')
    else:
        candidate = work / 'candidate'
        if phase == 'finish-cli':
            paths = []
            matrix = json.loads(subprocess.check_output([release, 'matrix', '-inventory', tools / 'distribution/release.json', '-kind', 'cli']))
            for row in matrix['include']:
                tuple_name = row['tuple']
                archive_name = row['archive']
                path = work / 'incoming' / tuple_name / archive_name
                destination = candidate / 'cli' / tuple_name
                destination.mkdir(parents=True)
                shutil.copyfile(path, destination / archive_name)
                shutil.copytree(path.parent / 'evidence', candidate / 'evidence' / tuple_name)
                paths.append(destination / archive_name)
            call(binaries / 'enkv-cli-package', '-checksums', candidate / 'cli/checksums.txt', *paths)
            call(signer, '-purpose', 'cli-checksums', '-input', candidate / 'cli/checksums.txt', '-key', os.environ['CLI_PRIVATE_KEY_FILE'], '-output', candidate / 'cli/checksums.sig')
            kind = 'cli'
        else:
            for plugin in inventory['plugins']:
                for row in inventory['platforms']:
                    tuple_name = row['platform'].replace('/', '-')
                    original = work / 'incoming' / (plugin['name'] + '-' + tuple_name)
                    destination = candidate / 'plugins' / plugin['name'] / plugin['version'] / tuple_name
                    destination.mkdir(parents=True)
                    for path in original.iterdir():
                        if path.name == 'evidence':
                            shutil.copytree(path, candidate / 'evidence' / (plugin['name'] + '-' + tuple_name))
                        else:
                            shutil.copyfile(path, destination / path.name)
                    call(signer, '-purpose', 'plugin-archive', '-input', destination / 'archive.json', '-key', os.environ['PLUGIN_PRIVATE_KEY_FILE'], '-output', destination / 'archive.sig')
            kind = 'plugins'
        call(release, 'candidate', '-inventory', tools / 'distribution/release.json', '-kind', kind, '-directory', candidate, '-source', args.commit)
        if kind == 'plugins':
            command = [release, 'catalog', '-inventory', tools / 'distribution/release.json', '-candidate', candidate, '-output', work / 'catalog', *roots]
            if args.previous_catalog is not None:
                command.extend(['-previous', args.previous_catalog.resolve()])
            call(*command)
            for index in sorted((work / 'catalog/pending').glob('*/index.json')):
                call(signer, '-purpose', 'plugin-index', '-input', index, '-key', os.environ['PLUGIN_PRIVATE_KEY_FILE'], '-output', index.with_suffix('.sig'))
            call(release, 'finalize', '-inventory', tools / 'distribution/release.json', '-directory', work / 'catalog', '-plugin-public-key', keys / 'plugin-public.pem')
            shutil.move(work / 'catalog', candidate / 'catalog')
            (candidate / 'candidate.json').unlink()
            call(release, 'candidate', '-inventory', tools / 'distribution/release.json', '-kind', kind, '-directory', candidate, '-source', args.commit)
        call(release, 'verify', '-inventory', tools / 'distribution/release.json', '-directory', candidate, *roots)
        call(release, 'assets', '-inventory', tools / 'distribution/release.json', '-directory', candidate, '-output', work / 'assets', *roots)


if __name__ == '__main__':
    main()
