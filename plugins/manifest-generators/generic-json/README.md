# Generic JSON manifest generator

This Apache-2.0 Go module renders the `ENKV/CONSUMPTION-MANIFEST/v3` JSON
format through the public manifest SDK. It requires Go 1.27.0.

The executable embeds its `cmd/enkv-manifest-generic-json/plugin.json`
declaration. `execution.NewImplementation(descriptorBytes)` binds that
descriptor to the settings callback and renderer. The settings contract
`ENKV/CONSUMPTION-MANIFEST-CONFIG/v1` accepts an empty JSON object and
normalizes it to `{}`. Canonical input must contain those exact bytes.
There are no configurable fields or added defaults; nonempty objects and other JSON values are refused.
The renderer needs no credentials and performs no provider request. The CLI
caller needs an installed compatible `enkv`, a valid application configuration,
and its normal authorized Store read access. The renderer receives only the
authorized public projection.

Select a trusted installation with the public command:

```sh
enkv manifest --source /absolute/application/configuration.yaml --source-format yaml \
  --out /absolute/application/references.json --plugin generic-json \
  --settings '{}' --json
```

Use `--service SEMANTIC-ID` for an exact stored-service filter. Select a
recipient with `--recipient app` for its local alias or `--recipient-id ID` for
an exact nonzero 64-character lowercase hexadecimal ID. The flags cannot be
combined; omitting both selects current Authority, including for shared entries.
Use repeated `--name NAME` or `--empty-selection` for an exact entry set. These select the authorized input;
the renderer owns its JSON encoding.

`Render(ctx, manifest.Borrow(projection))` borrows a frozen authorized public
projection and returns one exact-capacity artifact or a closed failure. The
caller owns the returned bytes and clears them when finished. The renderer
retains no alias or unfinished worker.

The artifact has fixed field order, lowercase hexadecimal identities, padded
Base64 and standard JSON escaping. Its header identifies the format and
settings contracts, observation, target Recipient, selection and optional
semantic service filter. Plain values are Base64. Secret destinations contain
only references: service and target contracts, canonical target, resolved
consumer locator, opaque target data, payload encoding and optional opaque
policy identity/data/digest. Binary target and policy data use Base64.

Encoding counts before allocating one exact artifact. The public writer uses
bounded copy windows for plain values and large public policy blobs. The
projection shares the 512-row included/excluded bound, 1,024 destinations,
8 MiB aggregate plain bytes and 36 MiB public destination bytes. The common
artifact ceiling is 246,313,668 bytes. Cancellation and refusal dispose
provisional bytes.

Runtime metadata establishes authorized input and exact delivered bytes.
This plugin's independent literal, consumer and author-conformance tests check
its complete JSON format. Native plugin code remains trusted code.

Use the [public source layout and build setup](../../../distribution/README.md),
then build a local copy through the [artifact tool](../../../sdk/artifact/README.md):

```sh
enkv-plugin-build -directory /absolute/source/plugins/manifest-generators/generic-json \
  -descriptor cmd/enkv-manifest-generic-json/plugin.json \
  -command ./cmd/enkv-manifest-generic-json -workspace /absolute/source/go.work \
  -output /absolute/builds/generic-json
enkv-plugin-build -verify /absolute/builds/generic-json
```

Add the captured build to explicit user trust for the application through the
[local installation guide](../../../distribution/local-installation.md). A local
modified implementation uses the same public API. Keep format/configuration
identities consistent with the meaning implemented by its encoder, settings
callback and independent tests. New format semantics need no ENKV catalog or
runtime parser. The [INI author walkthrough](../../../sdk/examples/ini-reference-manifest/README.md)
shows a separate implementation and a complete detached public-source setup.

From the module in that detached workspace, with dependencies available, run
`GOWORK=/ABSOLUTE/PUBLIC/go.work GOTOOLCHAIN=local go test ./...`.
Maximum codec cases are marked separately for the project runner. Stable
module names resolve through the repository's
[distribution setup](../../../distribution/README.md).
