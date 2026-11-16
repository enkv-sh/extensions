# ENKV extensions

This repository contains the public protocols, SDKs, author tools, examples and
official plugins for ENKV. A compatible independent plugin can be built and
installed without rebuilding the ENKV CLI.

Using ENKV to manage application secrets? Start with the
[operator guide](https://github.com/enkv-sh/core/blob/main/docs/README.md), including
[installation](https://github.com/enkv-sh/core/blob/main/docs/install.md) and
[plugin selection](https://github.com/enkv-sh/core/blob/main/docs/plugins.md).
The guides below serve plugin users and authors. Suspected vulnerabilities
belong in the [private reporting route](SECURITY.md).

| Source | Use |
|---|---|
| [SDK guide](sdk/README.md) | Choose the generator, output or manifest-generator family. |
| [Official plugins](plugins/README.md) | Configure the maintained generator, output and format implementations. |
| [Artifact tools](sdk/artifact/README.md) | Build and measure a native plugin, package its exact bytes and verify records. |
| [Source distribution](distribution/README.md) | Build a detached source kit or use exact versioned modules. |
| [Installation](distribution/local-installation.md) | Install a CLI archive and prepare trusted plugins for an application. |

The program, CLI, native hosts and state/cryptographic implementation live in
[enkv-sh/core](https://github.com/enkv-sh/core).

## Build requirements

Use stock Go 1.27.3. Module language minimums are Go 1.27.0. Installable artifacts
support native macOS/arm64 and Linux/x86_64. Module source paths use `enkv.sh/...`;
source versions and plugin artifact versions are separate identities.

For coordinated development, keep `enkv-core` and `enkv-extensions` beside each
other and run the inventory generator from this repository:

```sh
GOWORK=off go run distribution/generate.go -root .
GOWORK=off go run distribution/generate.go -root . -check
```

A plugin author can instead copy only the public modules required by one example.
The [detached source instructions](distribution/README.md#detached-public-source)
give the complete layout and workspace entries. No Core source is required for
that route.

## Trust and permissions

A descriptor declares a plugin's family and semantic contracts. It does not
authorize execution. The operator must trust its source, prepare the exact build
and select it for the application. Native plugins are trusted code; protocol
bounds do not provide OS confinement or restrict broad credentials. Cloud
resources and provider permissions are provisioned by their owner.

Public protocols, SDKs, examples, tools and official plugins in this repository
use [Apache License 2.0](LICENSE). Retain each module's license and third-party
notices when distributing source or binaries.
