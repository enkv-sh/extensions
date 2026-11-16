# Public plugin source modules

This tree contains official plugin implementations. Each leaf is a separate Go
module with its own Apache-2.0 license. The parent directories are source
containers, not Go modules. These implementations use the same public family
interfaces as private or locally modified plugins.

| Directory | Module | Commands |
|---|---|---|
| [generators/cloudflare-account-token](generators/cloudflare-account-token/README.md) | `enkv.sh/plugins/generators/cloudflare-account-token` | `cmd/enkv-generator-cloudflare` |
| [generators/local-random-secret](generators/local-random-secret/README.md) | `enkv.sh/plugins/generators/local-random-secret` | `cmd/enkv-generator-local-random-secret` |
| [outputs/aws-secrets-manager](outputs/aws-secrets-manager/README.md) | `enkv.sh/plugins/outputs/aws-secrets-manager` | `cmd/enkv-output-aws-secrets-manager` |
| [outputs/gcp-secret-manager](outputs/gcp-secret-manager/README.md) | `enkv.sh/plugins/outputs/gcp-secret-manager` | `cmd/enkv-output-gcp-secret-manager` |
| [outputs/github-actions](outputs/github-actions/README.md) | `enkv.sh/plugins/outputs/github-actions` | `cmd/enkv-output-github-repository`, `cmd/enkv-output-github-organization`, `cmd/enkv-output-github-environment` |
| [manifest-generators/generic-json](manifest-generators/generic-json/README.md) | `enkv.sh/plugins/manifest-generators/generic-json` | `cmd/enkv-manifest-generic-json` |
| [manifest-generators/opentofu-tfvars-json](manifest-generators/opentofu-tfvars-json/README.md) | `enkv.sh/plugins/manifest-generators/opentofu-tfvars-json` | `cmd/enkv-manifest-opentofu-tfvars-json` |

Open a module guide above for settings, credentials, supported behavior and
local tests. Use stock Go 1.27.3 and the
[detached source instructions](../distribution/README.md#detached-public-source).
A detached public source kit can contain one plugin and its declared public
SDK/protocol/artifact and service dependencies. Keep module and license files.
Versioned builds use exact requirements with `GOWORK=off`; coordinated builds
use an explicit workspace. Module files contain no checkout replacements.
Provider modules retain their pinned external dependencies, so offline builds
need those exact dependencies in the local module cache.

Each command has its own `plugin.json` author descriptor beside its main.
Build with that descriptor and the actual command path using the
[public artifact tool](../sdk/artifact/README.md). The builder measures the
executable, actual dependency graph and compiled source closure. This table
helps locate shipped source; it does not restrict plugin IDs, module paths,
services or formats admitted through a supported family.

A developer can modify an official implementation or write a new one, build it
locally and explicitly trust it for an application. No publication or ENKV
rebuild is needed. Use the [local installation guide](../distribution/local-installation.md)
for that route and for signed official selection. The
[independent examples](../sdk/README.md) demonstrate direct implementations of
new service and format behavior.

Each effect plugin owns its configuration defaults, canonical meaning,
credentials, account/target checks and provider response interpretation.
Cloudflare uses `CLOUDFLARE_API_TOKEN`; GitHub outputs use `GITHUB_TOKEN`; AWS
uses its standard SDK chain and GCP uses ADC. Generic SDKs and hosts contain no
provider credential switch. Keep credentials out of public settings and records.
A failed or lost send/result does not authorize an automatic retry.

The JSON and OpenTofu plugins own their format encoders and independent format
checks. Generic manifest success establishes authorized input and exact delivered
bytes. It does not certify the plugin's format or correspondence. Native plugin
trust does not establish confinement or truthful provider interpretation.
