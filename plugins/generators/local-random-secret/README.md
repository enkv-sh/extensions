# Local random-secret generator

This plugin generates 32 cryptographically random bytes and returns their
43-byte unpadded base64url representation. That value format belongs to this
implementation. The generator family accepts other value lengths and binary
representations through the same public SDK.

The plugin has no managed resource and requires no credential inputs or service
permissions. Its only settings object is `{}`; it has no configurable fields or
added defaults. Nonempty objects and nonobject JSON are refused. Normalization
emits that exact canonical object; canonical validation preserves it. It supports creation, with no remote
retirement operation.

In an existing project's `entries` map:

```yaml
TOKEN:
  confidentiality: secret
  recipients: []
  source:
    kind: generated
    plugin: local-random-secret
    settings: {}
    epoch: 0
```

The project supplies its normal domain, Store and key settings. Installation
grants no Authority permission; `enkv apply` still uses the project's admitted
operator and Store/KMS routes. Equal canonical intent and epoch reuse the
current value. Explicitly advance the epoch to request new entropy.

## Build and select

Use the [public source layout and build setup](../../../distribution/README.md)
and its pinned Go toolchain. Create an explicit workspace containing this module
plus
`sdk/artifact`, `sdk/generator` and `sdk/protocols/generator`. The public
[generator example](../../../sdk/examples/local-token-generator/README.md)
shows detached workspace bindings; substitute this module for the example and
omit its test-service dependency.

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -directory /ABSOLUTE/PUBLIC/plugins/generators/local-random-secret \
  -descriptor cmd/enkv-generator-local-random-secret/plugin.json \
  -command ./cmd/enkv-generator-local-random-secret \
  -output /ABSOLUTE/PRIVATE/local-random-build -workspace /ABSOLUTE/PUBLIC/go.work
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -verify /ABSOLUTE/PRIVATE/local-random-build
```

The embedded descriptor declares `local-random-secret` and generator wire v5.
Explicitly trust the build for an application through the
[local installation guide](../../../distribution/local-installation.md), then
select its ID in source as above. Publication and official signing are not
prerequisites for an explicitly trusted local build.

From this module, run its implementation and settings checks:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race ./...
```

The implementation checks cancellation before and after entropy acquisition.
It clears its temporary entropy allocation and transfers the returned value to
the SDK for result encoding and disposal. Native admission does not prove OS
confinement or erase immutable runtime copies.
