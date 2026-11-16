# Public plugin SDKs

Use these modules to implement a generator, output or manifest generator for
ENKV. A plugin owns its settings, defaults and service or format behavior.
Build it, explicitly trust its local build and select it in an application.
The plugin can remain private and unpublished. Compatible new behavior works
with the existing ENKV binary.

Each leaf has its own `go.mod` and Apache-2.0 `LICENSE`. The `sdk/` directory is
a source container, not a Go module. Public SDKs and examples need no private
Core, Crypto, host or test-runner source.

## Terms and results

A domain is one independently identified application state and effect scope.
A value entry is a named item with its value and recipient settings. The value
is its application content; encrypted storage bytes are a separate representation.
An output binding connects configured entry selection to an output implementation
and destination. A target identifies the exact service resource or action admitted
for that operation. Plugin names do not grant permission or prove compatibility.

Public results report bounded checked facts. An acknowledgement cannot select
Core state, and a lost reply can remain unknown. A callback error does not prove
that no service effect occurred. Keep safe result codes separate from raw service
errors, credentials and value bytes. Each family guide defines its callback and
result contract.

| Directory | Module | Purpose |
|---|---|---|
| [protocols/generator](protocols/generator/) | `enkv.sh/sdk/protocols/generator` | Typed generator operations and bounded wire codecs. |
| [generator](generator/README.md) | `enkv.sh/sdk/generator` | Generator callbacks, serving and native entry. |
| [protocols/output](protocols/output/) | `enkv.sh/sdk/protocols/output` | Typed output operations and bounded wire codecs. |
| [output](output/README.md) | `enkv.sh/sdk/output` | Output callbacks, serving and native entry. |
| [protocols/manifest-generator](protocols/manifest-generator/README.md) | `enkv.sh/sdk/protocols/manifest-generator` | Public projection and one-shot renderer exchange. |
| [manifest-generator](manifest-generator/README.md) | `enkv.sh/sdk/manifest-generator` | Renderer callbacks, validation of common inputs and owned artifacts. |
| [artifact](artifact/README.md) | `enkv.sh/sdk/artifact` | Author descriptors, measured builds, local records, archives and signatures. |
| [examples/local-token-generator](examples/local-token-generator/README.md) | `enkv.sh/sdk/examples/local-token-generator` | Managed binary-token generation and exact resource retirement. |
| [examples/local-value-output](examples/local-value-output/README.md) | `enkv.sh/sdk/examples/local-value-output` | Create, write and owned deletion for a local value service. |
| [examples/ini-reference-manifest](examples/ini-reference-manifest/README.md) | `enkv.sh/sdk/examples/ini-reference-manifest` | INI encoding and an independent application consumer. |
| [examples/testservice](examples/testservice/README.md) | `enkv.sh/sdk/examples/testservice` | Small in-memory HTTP service for the generator and output examples. |

## Implement a family

Start with the [generator guide](generator/README.md),
[output guide](output/README.md) or
[manifest-generator guide](manifest-generator/README.md). The family operations
and lifetime rules are typed. Plugin-defined semantic identities and bounded
public data describe configuration, resources, targets and formats. Their names
and module paths need no ENKV catalog entry.

Generators normalize their own settings, validate retained canonical intent,
create a private value and, for managed resources, check compatibility and retire
an exact original resource. A generated value can contain arbitrary binary
bytes within the family bounds. The plugin chooses its valid content and length.

Outputs normalize destinations and targets, declare supported actions, and own
service requests, credential discovery and response interpretation. Core retains
operation admission, target ownership and uncertainty rules; Crypto retains
private value custody and payload preparation.

Manifest generators receive the complete authorized public projection and
produce their own bounded format. The runtime evidence limit is
`authorized-input-and-exact-bytes`. It covers selected input/build, framing,
bounds, deadline, process closure and exact delivered bytes. Authors must test
format validity and complete correspondence to the input with independent
expected output or a consumer.

The three examples implement their behavior directly. They import public SDKs
and the standard library, with the local service used by generator/output tests.
They do not import official plugin implementations. Use their own behavior tests
alongside the common serving checks; an exchange that is correctly framed can
still contain an incorrect service request or artifact.

## Build from public source

Use stock Go 1.27.3 on `darwin/arm64` or `linux/amd64` for installable artifacts.
Module language minimums remain Go 1.27.0. The
[distribution instructions](../distribution/README.md) start with a detached public source kit. Coordinated repository
development and exact versioned dependencies are separate routes. A detached kit can contain only the
selected author module, its public SDK/protocol/artifact owners, and declared
service dependencies. Keep their module files and licenses. Use exact workspace
replacements for locally copied owners, without rewriting `enkv.sh/...` imports
or adding checkout replacements to maintained `go.mod` files.

From an author module with its public workspace selected, run its tests:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
```

Add `-race` when you need race detection. Offline checks require the exact dependencies in the local module cache.
The `full_only` comments on test declarations classify the repository runner's
profiles. Ordinary `go test` ignores those comments and remains supported.
The [artifact guide](artifact/README.md) explains how an author descriptor and
one main package become a measured immutable build. The
[local installation guide](../distribution/local-installation.md) shows how to
trust that build for one application and select it without publishing it.
Do not run a native plugin as an interactive CLI.

## Credentials and updates

The selected effect plugin declares its public credential route. ENKV transports
the declared environment inputs privately after admission. The plugin uses
ordinary environment variables or its service SDK's normal credential discovery
and checks the resolved account/target before the effect. AWS and GCP plugins
can use their standard SDK and ADC routes. Secrets belong in neither project
settings nor artifact metadata. Native plugins are trusted code; the exchange
is not an OS sandbox and does not prove one physical service request.

Rebuilding a local plugin produces another exact artifact. Equal canonical intent
at the same epoch reuses the current value even after selecting a new build;
changed intent at that epoch refuses. Accepted generator work keeps its original
support and credential-route identity. A NEW retirement Duty can bind a selected
compatible implementation after passive checks, then retains that exact support.
Credential rotation changes input values, not the admitted target or effect
permission. A lost reply can remain unknown and grants no automatic retry.

Complete-loss recovery emits canonical public settings with local plugin
selections unset. Later dependent effects require an explicit trusted selection;
recovery does not invent trust or apply newer plugin defaults. Keep original
artifact bytes and support needed by accepted work.
