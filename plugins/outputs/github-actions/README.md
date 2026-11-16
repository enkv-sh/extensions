# GitHub Actions outputs

This module implements repository, organization and environment secret outputs.
Each command embeds its `plugin.json` descriptor and serves the public output
SDK. Build and install each command with the public artifact tools.

Ordinary settings are JSON. The plugin requires lowercase address fields and
uppercases ASCII entry names for secret names. Its local grammar is given below.

Required settings have no defaults. Unknown or duplicate fields are refused.
The three command settings are:

| Scope | Required settings example |
|---|---|
| Repository | `{"owner":"example","repository":"app"}` |
| Environment | `{"owner":"example","repository":"app","environment":"prod"}` |
| Organization | `{"owner":"example","visibility":"selected","repositories":[7,11]}` |

`owner` uses 1–39 lowercase ASCII letters, digits or `-`, starts with a letter
or digit, and cannot end with `-`. Repository names use 1–100 lowercase ASCII
letters, digits, `.`, `_` or `-`, start and end with a letter or digit, and cannot
end with `.git`. Environment names use the same grammar with a 255-byte limit
and no `.git` restriction. These are local plugin rules.

For organization visibility `all` or `private`, omit `repositories`. For
`selected`, supply 1–65,535 sorted, distinct, positive uint64 IDs. This count is
a local encoding limit; it does not establish a GitHub quota. Other scopes have
no visibility policy. Secret names use 1–100 ASCII letters, digits or `_`, must
start with a letter or `_`, and cannot start with `GITHUB_` after uppercasing.

Merge this fragment into an existing valid application configuration:

```yaml
outputs:
  destinations:
    primary:
      plugin: github-actions-repository
      settings:
        owner: example
        repository: app
  routing:
    default: [primary]
```

Canonical destination settings retain the address fields. The plugin encodes the
organization visibility as its separate opaque policy. Targets contain their
complete scope and path so an owned secret can be deleted after its source
binding is removed.

The commands use `https://api.github.com` and API version `2026-03-10`; they
have no endpoint setting. Reserve each exact target path for ENKV use; GitHub
does not prove that reservation. Existing non-ENKV secrets are not adopted.

Only `GITHUB_TOKEN` supplies credentials. `GH_TOKEN` is not a fallback. The token
must meet the module's bounded printable header grammar. Passive interpretation
uses no credentials or service calls. Invocation preparation captures one token
and reads the exact scoped public key for a value action, or exact selected
visibility metadata for a policy-only action. Deletion uses its admitted exact
path and requires no discovery request.

Supply a token with the applicable secret permissions: fine-grained tokens need
repository `Secrets` write, organization `Secrets` write, or repository
`Environments` write for the selected scope, with access to the target. The
[GitHub REST contract](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10)
lists supported token types and the read permissions used during preparation.
The variable name does not grant workflow-token permissions.

The maximum application payload is 48,000 encoded bytes, including an empty
value. This is a conservative local bound. Raw and padded-Base64
application bytes are sealed without changing their meaning. An organization
policy-only update sends no secret value. It can replace a selected repository
list only when current visibility is already `selected`; it cannot switch
`all` or `private` visibility without a value action. Value create/write actions
send the complete selected visibility policy. All scopes support create with
value, write value, delete owned and delete reserved slot; none supports create
empty or conditional tokens. Each prepared invocation permits one
mutation and owns its token and client resources until `Close` returns. A lost
reply remains unknown; the plugin does not retry.

From this module in the detached public workspace, with dependencies available,
run `GOWORK=/ABSOLUTE/PUBLIC/go.work GOTOOLCHAIN=local go test ./...`. Tests use
controlled HTTP servers and make no GitHub calls. The repository's own checks
use its test runner.

## Local builds and selection

Use the [public source layout and build setup](../../../distribution/README.md)
and [artifact tool](../../../sdk/artifact/README.md). Each scope has its own
descriptor and main package:

| Scope | Main package | Local plugin name |
|---|---|---|
| Repository | `./cmd/enkv-output-github-repository` | `github-actions-repository` |
| Organization | `./cmd/enkv-output-github-organization` | `github-actions-organization` |
| Environment | `./cmd/enkv-output-github-environment` | `github-actions-environment` |

For example, build the repository command with the public artifact tool:

```sh
enkv-plugin-build -directory /absolute/github-actions -descriptor cmd/enkv-output-github-repository/plugin.json -command ./cmd/enkv-output-github-repository -output /absolute/builds/github-repository -workspace /absolute/go.work
enkv-plugin-build -verify /absolute/builds/github-repository
```

Use the module's exact pinned dependencies. Explicitly trust the captured local
build for one application and select its local plugin name in an output binding.
The [installation guide](../../../distribution/local-installation.md) gives the
trusted settings format. Modified local implementations use the same public
SDK; their admission requires no ENKV catalog entry or host rebuild.

Keep project settings and `GITHUB_TOKEN` separate. A new invocation obtains the
current token through its declared route; token rotation does not permit a
changed target or a resend. Removing a binding preserves its passive ownership
and deletion facts. A later deletion chooses a current compatible implementation
explicitly with `--delete-coordinate <coordinate-hex>=<local-plugin-id>`.
