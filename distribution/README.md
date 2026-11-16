# Source builds and distribution

Plugin authors can build from a detached copy of public source. Start with the
[SDK family index](../sdk/README.md) or an [official plugin](../plugins/README.md).
Use stock Go 1.27.3. Module language minimums remain Go 1.27.0; they do not
select the supported artifact compiler. Installable artifacts support native
`darwin/arm64` and `linux/amd64`.

## Detached public source

Copy the selected module directories with their `go.mod`, `go.sum` when present,
source, tests and license files. Preserve the relative layout shown below.
Keep the public guide tree (`sdk/`, `plugins/` and `distribution/` Markdown files)
with the source kit so its links remain usable. No Core, Crypto, host, private
runner or repository-root workspace is needed.

| Author example | Required module directories |
|---|---|
| Local token generator | `sdk/artifact`, `sdk/generator`, `sdk/protocols/generator`, `sdk/examples/testservice`, `sdk/examples/local-token-generator` |
| Local value output | `sdk/artifact`, `sdk/output`, `sdk/protocols/output`, `sdk/examples/testservice`, `sdk/examples/local-value-output` |
| INI manifest | `sdk/artifact`, `sdk/manifest-generator`, `sdk/protocols/manifest-generator`, `sdk/examples/ini-reference-manifest` |

For an official plugin, include its directory under `plugins/`, `sdk/artifact`,
and its family SDK and protocol. Read each included `go.mod` and retain every
required public module. External service libraries keep their pinned versions;
fetch them through the normal Go module route or provide those exact versions
in the local module cache. Do not rewrite `enkv.sh/...` imports or add checkout
replacements to maintained `go.mod` files.

At the kit root, write a `go.work` file. This complete example selects the local
token generator:

```go
go 1.27.0

use (
    ./sdk/artifact
    ./sdk/generator
    ./sdk/protocols/generator
    ./sdk/examples/testservice
    ./sdk/examples/local-token-generator
)

replace (
    enkv.sh/sdk/artifact v0.1.0 => ./sdk/artifact
    enkv.sh/sdk/generator v0.1.0 => ./sdk/generator
    enkv.sh/sdk/protocols/generator v0.1.0 => ./sdk/protocols/generator
    enkv.sh/sdk/examples/testservice v0.1.0 => ./sdk/examples/testservice
    enkv.sh/sdk/examples/local-token-generator v0.1.0 => ./sdk/examples/local-token-generator
)
```

For the other examples, use the directories in the table and their exact module
names from `go.mod`. Add one `use` entry and one exact-version `replace` entry
for each local owner. These replacements bind the current `v0.1.0` requirements
during complete graph loading; a `use` entry alone does not replace every
required version. A new author module can use the same layout and rules.

Set `GOWORK` to the absolute file, then test and build from the selected module:

```sh
export GOWORK=/absolute/public-kit/go.work
cd /absolute/public-kit/sdk/examples/local-token-generator
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go build .
```

Use `go test -race ./...` when you need race detection. For an offline check,
also set `GOPROXY=off GOSUMDB=off`; all declared external dependencies must
already be cached. These examples use an in-memory HTTP test service, not a
live provider account. The [artifact guide](../sdk/artifact/README.md) takes
this source and workspace to a measured build. The
[installation guide](local-installation.md#trust-a-local-author-build) shows
explicit local trust and application selection.

### Build failures

- A request for an unpublished `enkv.sh/... v0.1.0` usually means a required
  local owner or exact-version replacement is missing. Check the selected
  workspace and every included `go.mod`.
- An offline external-module failure needs the pinned module in the cache.
  Do not change its version to make the build pass.
- A plugin executable is a native protocol child. Do not start it as an
  interactive CLI; run its tests or invoke it through ENKV.

## Author descriptors

The artifact module and its commands use only the standard library. Authors pass
an explicit family descriptor to the build command. The descriptor declares the
family protocol and plugin-owned semantic contracts. The command measures the
executable and its complete build and dependency facts.

The module inventory records maintained source locations. It does not determine
which independent plugin names or modules can be built or installed. See the
[artifact author tools](../sdk/artifact/README.md) for descriptor and build use.
Local trust and project selection are separate. Use the
[local installation guide](local-installation.md) to trust a new or modified
author build for one application. A descriptor, module mapping or project
requirement alone does not grant execution trust. Compatible plugin changes
need no CLI rebuild or publication.

## CLI packaging

CLI release owners use the [CLI packaging recipes](https://github.com/enkv-sh/core/blob/main/distribution/cli-packaging.md).
Archive signing uses the [manual signing instructions](release.md).
Neither is required to trust a local plugin build.

## Module source locations

This section and source development below serve coordinated repository
contributors. They are not prerequisites for the detached author route.

`modules.json` is the maintained module location inventory. It maps program
modules to `github.com/enkv-sh/core` and SDK/plugin modules to
`github.com/enkv-sh/extensions`. Mapping pages contain source locations; they do
not publish module contents or establish that a tag is reachable.

Use stock Go 1.27.3. Module and workspace language minimums remain Go 1.27.0;
they do not select the supported artifact compiler. With both source checkouts
in the sibling layout below, generate the files from `enkv-extensions`:

```sh
GOWORK=off go run distribution/generate.go -root .
GOWORK=off go run distribution/generate.go -root . -check
```

The command generates `go.work`, the implementation runner and failure-source
module tables, and
`distribution/go-import/<module suffix>/go-import.html` for every registered
module. It does not deploy files. Run generation after an inventory or module
requirement change.

For manual deployment at `https://enkv.sh`, serve each generated HTML file at its
module prefix and at every package descendant when the query is `?go-get=1`.
For example, serve `go-import/sdk/generator/go-import.html` at both
`/sdk/generator?go-get=1` and `/sdk/generator/conformance?go-get=1`.
Match complete path segments; return 404 for an unknown prefix. Do not use one
module's mapping as a fallback for another module. Keep the four fields of each
`go-import` meta tag unchanged. These files require Go 1.25 or later for the
module subdirectory field. See the [Go module reference](https://go.dev/ref/mod#vcs-find-repo).

Version changes do not require mapping deployment. A release tag includes the
inventory's `tag_prefix`: for example, `sdk/generator/v0.1.0`. Deployment and a
fetch of the exact published revisions are separate operator checks.

## Source development

Keep `enkv-extensions` and `enkv-core` beside each other. Set `GOWORK` to
the generated absolute `enkv-extensions/go.work` path for coordinated source
builds. The workspace includes existing module owners only. It also replaces
exact required versions of those modules with the same local owners so full
graph loading needs no published first-party versions. The generator reads each
owner's `go.mod` with the stock Go parser; external requirements stay unchanged.
First-party module requirements select `v0.1.0`. Generated
workspace replacements bind that version, not a wildcard. Regenerate after
changing an owner's requirements. Do not rewrite `enkv.sh/...` imports for local
edits or a release.
No root module is required. The test launcher uses `GOWORK=off` with private local
modfiles because Go cannot combine its overlay modfiles with workspace mode.

When cloning into an empty parent directory, specify the local destinations:

```sh
git clone https://github.com/enkv-sh/extensions enkv-extensions
git clone https://github.com/enkv-sh/core enkv-core
cd enkv-extensions
```

The explicit destination names satisfy the source inventory; the remote URL
basename need not match. The generated workspace is a local development file
and does not supply public module versions.

```sh
export GOWORK="$PWD/go.work"
(cd sdk/examples/local-token-generator && go build .)
```

## Versioned dependency builds

This route requires reachable exact module versions at the public source
repositories and deployed Go mappings. Each module uses its directory prefix
for tags, such as `sdk/artifact/v0.1.0`. First-party requirements select
`v0.1.0`; the declarations alone do not prove that these tags are published.
Use a detached main-module build directory with `GOWORK=off` and no filesystem
replacements. A public source fetch needs no private Git credentials or
`GOPRIVATE` setting.

Initial source tags can omit first-party entries from `go.sum`. After their
immutable tags and Go mappings are reachable, preserve the main module's
`go.mod`, download its exact dependencies, require that `go.mod` is unchanged,
and retain the resulting real `go.sum` with the build record. Create the build
record directory first:

```sh
set -eu
cp go.mod /ABSOLUTE/BUILD-RECORD/go.mod.before
GOWORK=off go mod download all
cmp go.mod /ABSOLUTE/BUILD-RECORD/go.mod.before
cp go.sum /ABSOLUTE/BUILD-RECORD/go.sum
GOWORK=off go build -mod=readonly ./...
```

Each main module owns its checksum file; checksum files in dependency modules
do not supply the main module's `go.sum`. Repeat this preparation for each CLI,
tool or plugin main module. Obtain sums from the actual published module bytes;
never fabricate sums or move a published tag to change them. Retain the prepared
`go.mod` and `go.sum` unchanged for the readonly build.

Local fixture module archives can check versioned resolution before public tags exist. Such
fixtures establish no remote publication or deployed vanity fetch. The runner
records local source/replacement facts separately from pinned module versions.

Public protocols, SDKs, tools, examples and plugins use Apache-2.0 licenses.
Program modules and the contract-test fixture use their own license owners in
the core repository.
