# Local token generator

This example implements a managed token generator for the included [local service](../testservice). It owns its configuration and HTTP behavior. It imports the public SDKs and standard library, with the service module used by its tests.

The generator creates binary token values, retains an exact service resource ID and retires that original resource. Its values have no fixed text encoding or 43-byte requirement.

## Build and test

Use stock Go 1.27.3. For a detached public source kit, copy these complete
module directories, including `go.mod` and `LICENSE`, under
`/ABSOLUTE/PUBLIC`:

- `sdk/artifact`
- `sdk/protocols/generator`
- `sdk/generator`
- `sdk/examples/local-token-generator`
- `sdk/examples/testservice`

The service module is used by tests. The executable uses the SDKs and standard
library. Create `/ABSOLUTE/PUBLIC/go.work` with these exact local bindings:

```go
go 1.27.0

use (
    ./sdk/artifact
    ./sdk/protocols/generator
    ./sdk/generator
    ./sdk/examples/local-token-generator
    ./sdk/examples/testservice
)

replace (
    enkv.sh/sdk/artifact v0.1.0 => ./sdk/artifact
    enkv.sh/sdk/protocols/generator v0.1.0 => ./sdk/protocols/generator
    enkv.sh/sdk/generator v0.1.0 => ./sdk/generator
    enkv.sh/sdk/examples/testservice v0.1.0 => ./sdk/examples/testservice
)
```

The `v0.1.0` requirements bind to these explicit source owners. No private ENKV
or official plugin module is needed. From the copied example directory:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race ./...
```

The tests check its own normalization, exact service requests, independent binary value, consumer read, retirement, account refusal, cancellation and lost acknowledgement. A changed-subject control demonstrates failure of the independent expectations.

Build an installable artifact with the public author tool:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -directory /ABSOLUTE/PUBLIC/sdk/examples/local-token-generator \
  -descriptor plugin.json -command . \
  -output /ABSOLUTE/PRIVATE/token-build -workspace /ABSOLUTE/PUBLIC/go.work
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -verify /ABSOLUTE/PRIVATE/token-build
```

`plugin.json` declares the unpublished `private-local-token` ID, supported family wire, semantic configuration contract and credential recipe. It is embedded before compilation. `generator.Bind` checks the family and
configuration declaration, then the implementation checks the declared route.
The child checks this pre-build identity without knowing its future executable hash. A new local version is declared in this file and captured as a separate immutable build.

To use the build, add it to the trusted user settings described in the
[local installation instructions](../../../distribution/local-installation.md).
For one application, the settings record is:

```json
{
  "schema": "enkv/plugin-settings/v1",
  "applications": [
    {
      "directory": "/ABSOLUTE/APP",
      "plugins": [
        {
          "name": "private-local-token",
          "directory": "/ABSOLUTE/PRIVATE/token-build"
        }
      ]
    }
  ]
}
```

Use the canonical application directory and existing build directory. The
settings file belongs in the user configuration directory, outside the project.
Preserve other applications. Whitespace, a final newline and list order do not
change trust. The linked guide explains the platform paths and settings limits.
The next command that needs this plugin captures its exact build into immutable
installation storage. Project source selects the ID but cannot grant this trust.
Publication and official signing are not prerequisites for this local route.

## Configuration and credentials

Start the included service with its [handler setup](../testservice/README.md)
at the chosen endpoint. It is a Go handler, not a separate service command.
Then add this entry to an
existing project's `entries` map:

```yaml
TOKEN:
  confidentiality: secret
  recipients: []
  source:
    kind: generated
    plugin: private-local-token
    settings:
      endpoint: http://127.0.0.1:12345
      namespace: demo
      subject: api
    epoch: 0
    retirement: manual
```

The complete project still supplies its normal domain, Store and key settings.
`enkv prepare --source /ABSOLUTE/APP/configuration.yaml --source-format yaml --json`
checks preparation. `enkv apply` with the same source and format admits the
requested generation under the project's Authority; plugin installation alone
grants no operation permission.

The plugin-owned settings object is:

```json
{"endpoint":"http://127.0.0.1:12345","namespace":"demo","subject":"api"}
```

The endpoint must be a loopback HTTP address with an explicit port. Normalization removes one trailing slash, normalizes the namespace to lowercase, defaults an omitted namespace to `example`, and defaults an omitted subject to `token`. Namespace is at most 64 lowercase letters, digits or hyphens; subject is 1–256 UTF-8 bytes. Canonical validation preserves the exact normalized JSON without applying defaults again.

Set `ENKV_EXAMPLE_TOKEN` in the ENKV operator environment. The admitted route transports it privately to the child. The child uses normal `os.Getenv`, verifies `/session` resolves the declared namespace, then sends one create or retirement request. The token is not source configuration or public result data.

Creation sends `POST /tokens` with namespace/subject and accepts the exact returned resource ID plus arbitrary decoded binary value. Retirement sends `DELETE /tokens/<original-id>`. Acknowledgement does not claim confirmed invalidation. Lost replies remain unknown and are not retried or adopted through service inspection. The service's test observations grant no Product ownership or cleanup authority.

## Modify and retain a build

The implementation lives in [implementation.go](implementation.go). Change its
settings normalization or HTTP behavior there, update the independent expected
request/value tests, and rebuild through the same artifact command. Keep
`main.go` as the native SDK entry. Change the descriptor's name/version for your
own plugin identity; its public configuration and resource contract identities
must describe the semantics you actually implement.

A rebuild changes the selected executable without rebuilding ENKV. The same
canonical intent and epoch reuse the current value. A changed canonical intent
at that epoch refuses; explicitly advance the epoch to request new generation.
Changing the credential variable or route is separate from intent equality.

Complete-loss recovery emits editable `canonical.settings` with `plugin: null`
and retains the exact canonical intent in the generated companion.
Re-select a trusted compatible local ID for later dependent work. Canonical
validation must preserve those bytes and must not apply newer defaults.
An accepted retirement Duty continues with its recorded exact build and route,
even after another build is selected. Keep that support available. A NEW Duty
may select a compatible current build. After removing or converting an entry,
select that new executor explicitly with
`--retire-generator TOKEN=private-local-token`; this choice cannot replace
support already retained by an accepted Duty.

The example uses a trusted local service and bounded HTTP calls. Its deterministic
service tokens are test data. Native admission does not establish OS confinement,
provider permissions or truthful interpretation by arbitrary plugin code.
