# OpenTofu reference manifest generator

This Apache-2.0 Go module renders `ENKV/OPENTOFU-TFVARS-MANIFEST/v2` as a
reference-only `.tfvars.json` document. It requires Go 1.27.0 and uses the
public manifest SDK.

The executable embeds `cmd/enkv-manifest-opentofu-tfvars-json/plugin.json`.
`execution.NewImplementation(descriptorBytes)` binds that descriptor to settings
validation and rendering. The settings contract
`ENKV/OPENTOFU-TFVARS-CONFIG/v1` normalizes an empty JSON object to `{}`.
Canonical input must contain those exact bytes.
There are no configurable fields or added defaults; nonempty objects and other JSON values are refused.
The renderer needs no credentials and performs no provider request. The CLI
caller needs an installed compatible `enkv`, a valid application configuration,
and its normal authorized Store read access. The renderer receives only the
authorized public projection.

Select a trusted installation with the public command:

```sh
enkv manifest --source /absolute/application/configuration.yaml --source-format yaml \
  --out /absolute/application/references.tfvars.json --plugin opentofu-tfvars-json \
  --settings '{}' --json
```

Use `--service SEMANTIC-ID` for an exact stored-service filter. Select a
recipient with `--recipient app` for its local alias or `--recipient-id ID` for
an exact nonzero 64-character lowercase hexadecimal ID. The flags cannot be
combined; omitting both selects current Authority, including for shared entries.
Use repeated `--name NAME` or an explicit `--empty-selection` for entry selection. The plugin receives the resulting complete authorized
input partition and performs no secret lookup or infrastructure action.

The `enkv` object holds format/config contracts, observation and selection
facts, an optional semantic service filter, `plain` and `secrets` maps keyed by
entry name, excluded entries and the common evidence limit. Plain values
retain their padded Base64 bytes. Secret destinations retain semantic service
and target contracts, canonical target, resolved consumer locator, Base64
public target data, payload encoding and optional opaque policy data/digest.
They carry no secret value.

The renderer borrows one frozen public projection and returns an owned exact
artifact or a closed failure. Counts and aggregate limits follow the public
SDK; large policy data uses bounded copy windows. The common artifact ceiling
is 246,313,668 bytes. The caller clears returned bytes after use.

The plugin's independent literals, mutation cases and consumer tests establish
its format correctness. Runtime metadata reports authorized input and exact
byte delivery. The [consumer example](consumer/README.md) reads public fixture
data with OpenTofu and keeps secret locations as inert references.

Use the [public source layout and build setup](../../../distribution/README.md),
then build a local copy through the [artifact tool](../../../sdk/artifact/README.md):

```sh
enkv-plugin-build -directory /absolute/source/plugins/manifest-generators/opentofu-tfvars-json \
  -descriptor cmd/enkv-manifest-opentofu-tfvars-json/plugin.json \
  -command ./cmd/enkv-manifest-opentofu-tfvars-json -workspace /absolute/source/go.work \
  -output /absolute/builds/opentofu-tfvars-json
enkv-plugin-build -verify /absolute/builds/opentofu-tfvars-json
```

The [local installation guide](../../../distribution/local-installation.md)
describes explicit application trust and immutable capture. A modified local
plugin uses the same family interface. Its author owns the agreement between
declared format/configuration identities, encoding and consumer tests. The
[INI walkthrough](../../../sdk/examples/ini-reference-manifest/README.md) gives
the complete detached public-source author route for a different format.

From the module in that detached workspace, with dependencies available, run
`GOWORK=/ABSOLUTE/PUBLIC/go.work GOTOOLCHAIN=local go test ./...`. See the
[distribution setup](../../../distribution/README.md) for stable module names.
