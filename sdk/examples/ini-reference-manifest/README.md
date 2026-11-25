# INI reference manifest

This example implements a new INI format through the public manifest SDK. Its
own code validates settings and encodes the complete authorized projection. It
writes plain values as Base64, secret destination references and every excluded
entry. It imports no official plugin or private ENKV package.

The renderer fetches no secret and receives no provider credentials. The caller
still needs a trusted configuration pair and its normal read access to the
selected Store. The resulting INI file is inert reference data.

## Source and settings

| File | Responsibility |
|---|---|
| `plugin.json` | Local plugin identity, family protocol and semantic contracts. |
| `main.go` | Embed the descriptor, check contracts with `native.Bind` and enter `native.Main`. |
| `settings.go` | Own the settings grammar, default and canonical JSON bytes. |
| `render.go` | Own every INI section, field and encoding. |
| `main_test.go` | Compare independently written complete bytes and author callback results. |
| `consumer/` | Read the format using the standard library, independently of ENKV and its SDKs. |

The local plugin name is `workshop-ini`. Its format contract is
`example/ini-reference/v1`; its settings contract is
`example/ini-reference-settings/v1`. None needs a host catalog entry.

The `section_prefix` setting defaults to `enkv`. It starts with an ASCII letter
and contains at most 32 letters, digits, underscores or hyphens. Canonical
settings are compact JSON with that field present:

```json
{"section_prefix":"application"}
```

Ordinary settings may omit the field or use different JSON whitespace. A
canonical request must already contain the exact canonical bytes. The plugin
refuses duplicates, unknown fields, invalid prefixes and changed canonical
spelling. To build your own format, change the descriptor and implement its
settings and renderer in your module. An ENKV source edit is unnecessary.

## Build from a public source kit

Use stock Go 1.27.3. Keep each module's source, `go.mod`, present `go.sum` and
license material. Preserve the source layout and public guides as described in
the [shared source route](../../../distribution/README.md#detached-public-source).
This example needs four public owners:

| Module | Suggested copied location |
|---|---|
| `enkv.sh/sdk/artifact` | `/absolute/public-kit/sdk/artifact` |
| `enkv.sh/sdk/manifest-generator` | `/absolute/public-kit/sdk/manifest-generator` |
| `enkv.sh/sdk/protocols/manifest-generator` | `/absolute/public-kit/sdk/protocols/manifest-generator` |
| `enkv.sh/sdk/examples/ini-reference-manifest` | `/absolute/public-kit/sdk/examples/ini-reference-manifest` |

Create `/absolute/public-kit/go.work` with the following content. Change paths
to your copied owners. Exact replacements bind the selected source versions
without changing imports or adding filesystem replacements to `go.mod`.

```go
go 1.27.0

use (
    ./sdk/artifact
    ./sdk/manifest-generator
    ./sdk/protocols/manifest-generator
    ./sdk/examples/ini-reference-manifest
)

replace (
    enkv.sh/sdk/artifact v0.1.1 => ./sdk/artifact
    enkv.sh/sdk/manifest-generator v0.1.1 => ./sdk/manifest-generator
    enkv.sh/sdk/protocols/manifest-generator v0.1.1 => ./sdk/protocols/manifest-generator
    enkv.sh/sdk/examples/ini-reference-manifest v0.1.1 => ./sdk/examples/ini-reference-manifest
)
```

Run the example tests and build the public author tool. Create the tool and build
parent directories first. These commands run no plugin effect:

```sh
GOWORK=/absolute/public-kit/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  go -C /absolute/public-kit/sdk/examples/ini-reference-manifest test ./...
GOWORK=/absolute/public-kit/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  go -C /absolute/public-kit/sdk/artifact build \
  -o /absolute/tools/enkv-plugin-build ./cmd/enkv-plugin-build
/absolute/tools/enkv-plugin-build \
  -directory /absolute/public-kit/sdk/examples/ini-reference-manifest \
  -descriptor plugin.json -command . \
  -workspace /absolute/public-kit/go.work \
  -output /absolute/builds/workshop-ini
/absolute/tools/enkv-plugin-build -verify /absolute/builds/workshop-ini
```

The builder captures the executable, descriptor and actual dependencies, then
publishes an atomic local build marker. It does not require publication or an
official signature for the explicit local route. See the
[artifact guide](../../artifact/README.md) for exact versioned dependencies.

## Trust and select the local build

Add the build to trusted user settings for the application whose configuration
pair is in `/absolute/application`. For a new settings file, the exact canonical
JSON is:

```json
{
  "schema": "enkv/plugin-settings/v1",
  "applications": [
    {
      "directory": "/absolute/application",
      "plugins": [
        {
          "name": "workshop-ini",
          "directory": "/absolute/builds/workshop-ini"
        }
      ]
    }
  ]
}
```

Write this JSON at
`os.UserConfigDir()/enkv/plugins.json`. This is
`$HOME/Library/Application Support/enkv/plugins.json` on macOS, or
`$XDG_CONFIG_HOME/enkv/plugins.json` on Linux when that variable is set, otherwise
`$HOME/.config/enkv/plugins.json`. Resolve the application directory's symlinks
first. Preserve other applications and plugin selections in an existing file.
Whitespace, a final newline and list order do not change trust. Use JSON escaping
for paths that need it. The
[local installation guide](../../../distribution/local-installation.md) owns the
complete trust and immutable-capture rules.

With a valid existing configuration pair, select the trusted local name:

```sh
enkv manifest --source /absolute/application/configuration.yaml --source-format yaml \
  --out /absolute/application/references.ini --plugin workshop-ini \
  --settings '{"section_prefix":"application"}' --json
```

The default selection is every entry authorized for current Authority,
including shared entries. Use `--recipient app` for a local alias or
`--recipient-id ID` for an exact nonzero 64-character lowercase hexadecimal ID.
The flags cannot be combined. Use repeated `--name NAME` for exact entries,
or `--empty-selection` for an explicit empty set. Add
`--service SEMANTIC-ID` to retain secret destinations whose stored service
contract matches that exact string. The service filter leaves plain entries
included. It uses a semantic service identity, not a plugin name or Store
provider. The host supplies the complete included/excluded input partition.

The settings and render calls use the same admitted build in separate one-shot
processes. A rebuild to the same local output directory can supply a new
compatible implementation to later invocations without rebuilding ENKV. An
invocation keeps its captured exact build. New settings defaults do not rewrite
canonical input.

## Format and consumer checks

Every INI value is a quoted string using JSON string escapes. Sections contain
manifest metadata, numbered included entries, numbered secret destinations and
numbered exclusions. Keys ending in `_base64` use standard padded Base64;
identity fields use lowercase hex. A secret entry contains references only.
The independent `consumer` package reads plain bytes and reference locations.
An application can call `consumer.Read`, then `PlainValues` and `References`.
The parser checks its required syntax and fields; it does not validate every
manifest fact or authenticate the source.
Resolving a secret reference is a separate application action with its own
service credentials.

The [test fixture](main_test.go) derives the complete expected output from fixed
input fields, then checks those bytes through the actual renderer and
`conformance.CheckImplementation`. Its independent consumer assertion compares
plain bytes, reference locations and exclusion fields with explicit expectations.
Use both checks when you change the format. `MeasureArtifact` supplies byte
length and digest only.

Tests cover complete mixed output with a private service filter, empty and
all-excluded partitions, settings normalization/refusal, closed cancellation
and expiry, large opaque policy data and an independent consumer. A deliberate
plain-value encoding defect still completes the common native exchange, but
fails the complete author fixture and expected consumer values.

ENKV reports the selected build, authorized input and exact delivered bytes with
`authorized-input-and-exact-bytes`. The author owns INI validity and complete
semantic correspondence. Native plugin execution uses trusted code with its
actual process access; a conformance pass establishes no sandbox or authenticity
of an arbitrary projection.
