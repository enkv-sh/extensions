# Release candidates and static catalog

`release.json` is the release inventory. It owns the full CLI version, the two
native platforms, all official executable commands and their independent artifact
versions. `plugin_release_tag` names the GitHub draft that holds this batch; it
is not a plugin version. Go module versions and tags are separate.

The manual workflows in both repositories build signed draft candidates. They
never promote a draft or deploy a site. A successful local check does not prove
public module reachability, native Linux behavior, cloud access or public hosting.

## Tools and inputs

Build the tools from the reviewed extensions source:

```sh
cd sdk/artifact
GOWORK=off go build -mod=readonly -o /ABSOLUTE/tools/enkv-release ./cmd/enkv-release
GOWORK=off go build -mod=readonly -o /ABSOLUTE/tools/enkv-artifact-sign ./cmd/enkv-artifact-sign
GOWORK=off go build -mod=readonly -o /ABSOLUTE/tools/enkv-plugin-build ./cmd/enkv-plugin-build
```

Use stock Go 1.27.3. The artifact module needs no sibling checkout. The native
CLI packaging tool belongs to the core full composition; see its
[packaging guide](https://github.com/enkv-sh/core/blob/main/distribution/cli-packaging.md).
Release payload dependencies must use reachable module versions, with `GOWORK=off`.
Dependency preparation may add sums, but must leave `go.mod` unchanged. Plugin
archive creation uses the same complete prepared source and sums as its native
build. Tar transport preserves the executable modes.

Protect `main` in both repositories and restrict changes to reviewed source.
To build a candidate, open **Actions → Build signed draft candidate → Run
workflow**, select `main`, and click **Run workflow**. GitHub records the
commit at dispatch. Each workflow uses that commit for its own code and
payload. Review and publish the signed drafts as a separate owner action.

The extensions workflow uses its own dispatched commit for tools and inventory.
On its first attempt, the core workflow reads the commit at protected
`enkv-sh/extensions:main`. It saves that SHA as a run artifact before building
and uses that exact tools checkout through staging. A rerun restores the saved
SHA. If the original pin is unavailable, start a new dispatch to select tools
again. Core's native build evidence records the selected extensions SHA.
For a coordinated beta, confirm both candidates used the same release inventory
before promotion.

Configure four repository variables once in each repository:

- `CLI_PUBLIC_KEY_PEM` and `PLUGIN_PUBLIC_KEY_PEM` contain the two production
  Ed25519 SPKI public keys. Each PEM block includes its final newline.
- `DEVELOPMENT_CLI_PUBLIC_KEY_SHA256` and `DEVELOPMENT_PLUGIN_PUBLIC_KEY_SHA256`
  identify the known development keys. Use the SHA-256 of decoded SPKI DER.
  For example, run
  `openssl pkey -pubin -in development-plugin-public.pem -outform DER | shasum -a 256`.

For a later plugin release, include the previous published catalog tree under
`distribution/catalog/` in the reviewed extensions source. Preserve that tree
during promotion of each release. The workflow checks the snapshot against
published extensions releases, including prereleases. It uses the workflow job’s read-only GitHub token
for that lookup. Drafts do not count as published releases. An empty start
requires a successful lookup showing there have been no published releases.
The catalog tool verifies signatures and retained routes before generating
new signed indexes.

Only the `release-signing` environment needs `CLI_SIGNING_KEY_PEM` or
`PLUGIN_SIGNING_KEY_PEM` secrets, as applicable. They contain unencrypted Ed25519
PKCS8 keys. Restrict these environments and `release-draft` to the reviewed
`main` workflow. One owner triggers the candidate and later makes the separate
promotion decision. The workflow does not require a second maintainer.
Build, archive and staging jobs receive no signing key. Signing jobs verify their
own signatures using the independently supplied public root, and do not execute
plugin payloads. Source and action commits are immutable inputs. The workflow
has `contents: write` only in its draft-staging job.

Linux build and archive jobs use the official AlmaLinux 9 container pinned at
`quay.io/almalinuxorg/almalinux@sha256:3b958c0ee1c6f610f39a23143117ebcf5812a17aa42b0b09ebdb6fed18da3ae5`.
They require the actual native glibc version to be 2.34 before building. See the
[official image source](https://wiki.almalinux.org/containers/docker-images.html).
Native jobs verify their actual platform and compiler. Linux ELF imports must
require no glibc version above 2.34. macOS Mach-O load commands provide the actual
minimum OS version; this does not claim support for an untested macOS version.
Apple Developer ID signing and notarization are deferred.

## Candidate files

Each workflow retains a private `candidate.tar` workflow artifact. Its tree is:

```text
candidate/
  candidate.json
  keys/cli-public.pem
  keys/plugin-public.pem
  cli/checksums.txt
  cli/checksums.sig
  cli/<os>-<arch>/enkv-full-<cli-version>-<os>-<arch>.tar.gz
  plugins/<name>/<artifact-version>/<os>-<arch>/archive.json
  plugins/<name>/<artifact-version>/<os>-<arch>/archive.sig
  plugins/<name>/<artifact-version>/<os>-<arch>/<archive.filename>
```

A CLI candidate has the `cli/` files. A plugin candidate has the complete
`plugins/` inventory. The keys directory holds public roots only.
`candidate.json` records the source commit, inventory digest, environment and
exact file sizes, hashes and GitHub asset URLs. Private `evidence/` files retain
compiler/native observations, resolved modules, build info and prepared module sums;
the candidate hashes these files too. It is private build evidence,
not a public release asset. Plugin archives retain their canonical metadata,
compiled and resolved module closure and signed native build facts.

The shared commands, run from the extensions repository root, are:

```sh
/ABSOLUTE/tools/enkv-release matrix -inventory distribution/release.json -kind plugins
/ABSOLUTE/tools/enkv-release candidate -inventory distribution/release.json \
  -kind plugins -directory /ABSOLUTE/candidate -source FULL_40_HEX_SOURCE_COMMIT
/ABSOLUTE/tools/enkv-release verify -inventory distribution/release.json \
  -directory /ABSOLUTE/candidate \
  -cli-public-key /ABSOLUTE/trusted/cli-public.pem \
  -plugin-public-key /ABSOLUTE/trusted/plugin-public.pem
```

Use `-kind cli` for CLI candidates. Use `-environment development` only for
local development candidates. Verification needs independently trusted roots;
a key carried beside downloaded bytes does not establish trust.
Every required platform and plugin must be present. Canonical SDK parsers check
records and signatures. Archive verification extracts bounded bytes into local
scratch storage, checks metadata signatures, then removes scratch storage.
Payloads are never executed. CLI checks cover exact checksum rows, required
legal files, native executable identity, embedded roots, empty production custom TLS roots and actual runtime floor.

`enkv-release assets` takes the same `-inventory`, `-directory`,
`-cli-public-key` and `-plugin-public-key` flags, plus a new `-output` directory.
It verifies first, then copies only the public GitHub asset set into that
folder. `distribution/stage-release.py` accepts `--repository`, `--tag`,
`--source` and `--assets` and reads `GH_TOKEN` only in the owner-run workflow.
It checks that the exact source commit exists, discovers drafts through the
authenticated paginated release list, and requires one matching draft. Published
or duplicate matching releases refuse. Existing lightweight or annotated tags
must resolve to the exact source commit. The helper checks the tag before draft
creation or reuse, before each upload, and after staging. It never creates or
moves a tag. An absent tag remains explicit as `tag_state: "absent"`; the draft's
pending `target_commitish` must then be the exact source. An existing tag is the
source authority; `target_commitish` cannot override it.

The helper inspects every existing partial asset before uploading a missing
asset, never replaces an asset, and checks uploaded bytes by readback. Differing
partial assets refuse. A failed staging
operation can leave a partial draft; inspect that draft before a retry.

## Catalog files and signing order

The public origin is fixed at `https://enkv.sh/releases/`. Payload redirects point
to exact `github.com/enkv-sh/{core,extensions}/releases/download/` asset URLs.
The production CLI follows only its fixed GitHub release redirect-host policy.
There is no arbitrary catalog-origin flag.

Create a new local tree from a verified complete plugin candidate:

```sh
/ABSOLUTE/tools/enkv-release catalog -inventory distribution/release.json \
  -candidate /ABSOLUTE/candidate -previous /ABSOLUTE/current-site \
  -output /ABSOLUTE/new-site \
  -cli-public-key /ABSOLUTE/trusted/cli-public.pem \
  -plugin-public-key /ABSOLUTE/trusted/plugin-public.pem
```

Omit `-previous` for the first catalog. The output must not exist. The complete supplied previous catalog is authenticated before copying it.
Every existing index needs both its canonical record and valid signature; a
missing pair never starts a new empty index. All retained version and artifact
records are authenticated, including records no longer selected by an index.
Their payload redirects must name the exact extensions archive asset. A valid
standalone retained artifact route remains supported. Existing immutable version
and artifact routes are copied and retained. A same-version
replacement refuses. New version and artifact routes contain identical
`archive.json` and `archive.sig` bytes. `redirects.json` explicitly maps each
payload route to its exact GitHub asset. `index.html` is created only from a verified CLI candidate, and provides CLI
installation links. A plugin-only catalog preserves an existing page. Canonical unsigned selecting indexes go under `pending/<name>/index.json`.
Previously selected signed indexes remain in place while new ones are unsigned.

The controlled plugin signing job creates the catalog, signs every pending
index and finalizes it before exporting draft assets. It retains this final
catalog under `candidate/catalog/`, hashes it in `candidate.json`, and stages
signed index records with the same draft. The owner needs no local production
private key to deploy it. The following manual route is also available for
local development candidates.

Sign every pending index with the plugin key using `enkv-artifact-sign` and
purpose `plugin-index`. Put its detached signature beside it as `index.sig`.
Then verify all signatures before selecting the new indexes:

```sh
/ABSOLUTE/tools/enkv-release finalize -inventory distribution/release.json \
  -directory /ABSOLUTE/new-site \
  -plugin-public-key /ABSOLUTE/trusted/plugin-public.pem
```

Finalization checks the indexed version and artifact routes before replacing any
selecting index. Keep private keys outside the candidate and site trees.
For manual exact-byte signing, the existing script takes seven arguments:
`sign-release.sh SIGNER PURPOSE INPUT SHA256 PRIVATE_KEY PUBLIC_KEY NEW_SIGNATURE`.
It checks the selected digest, signs canonical bytes and verifies the result.

The owner publishes checked payloads first, then deploys immutable routes and
payload redirects, and exposes selecting indexes last. Preserve old immutable
routes and payloads needed by retained work. After promotion, anonymous public
download checks must compare with the retained candidate. Local catalog tests
and private draft readback do not prove this public path.

GitHub runner labels and isolation follow the official
[runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [secure workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use).
The workflows pin checkout, setup-go and artifact actions to full reviewed
commits. Runner images themselves receive vendor updates; record actual native
results for the candidate rather than infer its OS floor from a runner label.

## Serve the output at its exact public paths

The plugin workflow has already signed and finalized `candidate/catalog/` with
its controlled CI key. Start with that tree. Add the verified CLI candidate to it:

```sh
/ABSOLUTE/tools/enkv-release catalog -inventory distribution/release.json \
  -candidate /ABSOLUTE/cli-candidate \
  -previous /ABSOLUTE/plugin-candidate/catalog -output /ABSOLUTE/combined-site \
  -cli-public-key /ABSOLUTE/trusted/cli-public.pem \
  -plugin-public-key /ABSOLUTE/trusted/plugin-public.pem
```

This adds the verified CLI page and redirects, preserves the already signed
plugin indexes, and needs no local private key or second finalization. The
combined output has these separate serving targets:

| Local output | Public location |
|---|---|
| `index.html` | `https://enkv.sh/` |
| `keys/cli-public.pem`, `keys/plugin-public.pem` | `https://enkv.sh/keys/cli-public.pem`, `https://enkv.sh/keys/plugin-public.pem` |
| `plugins/**`, `artifacts/**` | `https://enkv.sh/releases/plugins/**`, `https://enkv.sh/releases/artifacts/**` |
| Each `redirects.json` entry | Its exact `/releases/...` path redirects to its exact GitHub release asset URL |
| Separately generated `distribution/go-import/<module>/go-import.html` | `https://enkv.sh/<module>?go-get=1` serves the corresponding Go discovery HTML |

Do not mount the whole mixed output tree at `/releases/`: the installation page
and public keys serve at the root paths above. Do not serve `pending/`, private
`candidate.json`, candidate evidence, private keys or workflow artifacts. Public
key downloads support inspection; independent trust still requires a separate
trusted key source. The redirect map is host-neutral deployment input, not a
new redirect service. The owner configures the existing host to serve those exact
routes, with payloads and immutable records available before selecting indexes.

## Owner tag check immediately before promotion

Staging never creates a Git tag. An absent tag is a pending owner step, not a
claim that the tag already identifies the candidate. Before promoting the exact
numeric draft ID, the owner runs this check using the candidate's reviewed source
commit. For the plugin release, use `enkv-sh/extensions` and the inventory's exact
`plugin_release_tag`; the CLI uses `enkv-sh/core` and `v<cli_version>`.

Run this in Bash with the four assignments set to the reviewed candidate. It
checks an existing lightweight or annotated tag, creates only an absent tag
without force, and reads it back. It does not publish the draft.

```bash
set -euo pipefail
release_repository=enkv-sh/core
release_tag=v0.1.0-beta.1
release_source=FULL_40_HEX_REVIEWED_CANDIDATE_SOURCE_COMMIT
release_checkout=/ABSOLUTE/OWNER/core
release_remote="https://github.com/$release_repository.git"

git -C "$release_checkout" fetch --no-tags -- "$release_remote" "$release_source"
test "$(git -C "$release_checkout" cat-file -t "$release_source")" = commit

release_tag_state() {
  local release_refs
  release_refs=$(git ls-remote --tags -- "$release_remote" \
    "refs/tags/$release_tag" "refs/tags/$release_tag^{}") || return
  python3 - "$release_tag" "$release_source" "$release_refs" <<'PY_TAG'
import re
import sys

tag, source, output = sys.argv[1:]
if not re.fullmatch('[0-9a-f]{40}', source):
    raise SystemExit('exact reviewed source commit is required')
reference = 'refs/tags/' + tag
rows = {}
for line in output.splitlines():
    identity, name = line.split()
    if name not in [reference, reference + '^{}'] or name in rows:
        raise SystemExit('unexpected or duplicate tag reference')
    if not re.fullmatch('[0-9a-f]{40}', identity):
        raise SystemExit('invalid tag object identity')
    rows[name] = identity
if not rows:
    print('absent')
else:
    if reference not in rows or rows.get(reference + '^{}', rows[reference]) != source:
        raise SystemExit('existing tag points to a different source; do not move it')
    print('present')
PY_TAG
}

release_state=$(release_tag_state)
if [ "$release_state" = absent ]; then
  git -C "$release_checkout" push -- "$release_remote" \
    "$release_source:refs/tags/$release_tag"
fi
test "$(release_tag_state)" = present
```

Stop on any failure. Do not use force, delete a tag, or change an existing tag.
If the create loses a race, stop and run the read-only check again; do not retry
with force. Immediately before promotion, recheck that the same numeric release
is still a draft with the expected tag, its assets match the checked candidate,
and `release_tag_state` reports `present` for the exact reviewed source. Then
promote that numeric draft without replacing its assets. A tag mismatch requires
a new reviewed release identity, not an overwrite.

GitHub documents draft visibility in the authenticated
[release list](https://docs.github.com/en/rest/releases/releases#list-releases),
[Git references](https://docs.github.com/en/rest/git/refs#get-a-reference), and
[annotated tag objects](https://docs.github.com/en/rest/git/tags#get-a-tag).
