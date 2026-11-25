# Local value output

This example implements a private output plugin for the included
[local service](../testservice/README.md). It owns its settings, canonical target,
HTTP requests, credential/account check and response interpretation. It imports
only public SDKs and the standard library; its tests use the included service.

The implementation supports create with value, write value and delete owned.
It stores raw or prepared Base64 bytes from 0 to 65,536 bytes at a named service
location. Both value actions declare this inclusive interval in the normalized
target; action checks repeat it exactly. It has no publication policy. Its
required `SelectPolicyAction` callback returns zero action and a refusal error;
it performs no credential discovery or service call.
The service assigns an owned-instance ID; writes/deletes require that exact ID.
A lost acknowledgement remains unknown and the same prepared invocation cannot
resend.

## Settings and credentials

Public settings have an HTTP loopback endpoint and a namespace:

```json
{"endpoint":"http://127.0.0.1:8080","namespace":"dev"}
```

Namespace defaults to `dev`. The plugin canonicalizes the endpoint's trailing
slash and emits its own canonical JSON settings. Canonical validation accepts
only those exact retained settings, without reapplying defaults. Namespace is
1–64 lowercase letters, digits or hyphens. Endpoint must use an explicit port
on a loopback IP address.

Set `ENKV_EXAMPLE_TOKEN` to the token used by the local service. The descriptor
names this ordinary environment route. Preparation authenticates `GET /session`
and compares its namespace before requesting payload bytes. Tokens never belong
in public settings, artifacts, diagnostics or results.

An entry named `secret` maps to `/values/dev/c2VjcmV0`, using unpadded URL Base64
for its name. The consumer locator is that exact HTTP URL. The target-data
record contains enough public endpoint/namespace/name data for later guarded
deletion without old configuration or payloads.

## Run author checks

A detached kit needs only these five modules, including their `go.mod` and
`LICENSE` files. Keep the paths below relative to the kit root:

```text
sdk/artifact/
sdk/protocols/output/
sdk/output/
sdk/examples/testservice/
sdk/examples/local-value-output/
```

Use this explicit `go.work` at the kit root for the versions in the
module requirements. Exact replacements also prevent Go from fetching metadata
for those local versions:

```go
go 1.27.0

use (
    ./sdk/artifact
    ./sdk/protocols/output
    ./sdk/output
    ./sdk/examples/testservice
    ./sdk/examples/local-value-output
)

replace (
    enkv.sh/sdk/artifact v0.1.1 => ./sdk/artifact
    enkv.sh/sdk/protocols/output v0.1.0 => ./sdk/protocols/output
    enkv.sh/sdk/output v0.1.1 => ./sdk/output
    enkv.sh/sdk/examples/testservice v0.1.0 => ./sdk/examples/testservice
)
```

From `sdk/examples/local-value-output`, select that absolute workspace path:

```sh
GOWORK=/absolute/output-kit/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
```

The tests start and join their own HTTP service. To embed the same service in
a local application, follow its [handler setup](../testservice/README.md).
The example has no private ENKV or official-plugin dependency.

The tests create/write/delete exact owned values, check empty, binary and
65,536-byte payloads, refuse wrong tokens, namespaces and ownership, check lost
replies and use the common
conformance helper. A deliberately defective author callback sends different
bytes; the independent consumer check detects it even when its public
acknowledgement is well framed.

## Build and install

`plugin.json` is the author descriptor for `private-local-values`. It is embedded
in the executable and declares output wire version 5. The SDK serves
`output-public-v3` for passive checks and `output-wire-v6` for effects.
`output.Bind` checks its family and configuration declaration;
the implementation then checks its declared credential route before serving.
Build the public artifact tool from the kit, then capture the author module:

```sh
GOWORK=/absolute/output-kit/go.work go -C /absolute/output-kit/sdk/artifact build -o /absolute/tools/enkv-plugin-build ./cmd/enkv-plugin-build
/absolute/tools/enkv-plugin-build -directory /absolute/output-kit/sdk/examples/local-value-output -descriptor plugin.json -output /absolute/builds/local-values -workspace /absolute/output-kit/go.work
/absolute/tools/enkv-plugin-build -verify /absolute/builds/local-values
```

Create the tools directory first. Stock Go 1.27.3 builds the current artifacts.
The builder's `-versioned` route requires reachable compatible published versions
of every required module. The current source kit uses the explicit workspace;
its exact `v0.1.0` requirements are bound to the selected local owners.

Authorize this build for one application in the trusted user settings file.
The path is `~/Library/Application Support/enkv/plugins.json` on macOS, and
`$XDG_CONFIG_HOME/enkv/plugins.json` on Linux, with `~/.config` as the default
config directory. For a new file, use this JSON:

```json
{
  "schema": "enkv/plugin-settings/v1",
  "applications": [
    {
      "directory": "/absolute/application",
      "plugins": [
        {
          "name": "private-local-values",
          "directory": "/absolute/builds/local-values"
        }
      ]
    }
  ]
}
```

Use canonical absolute paths. Preserve other applications and plugin entries in
an existing file. Whitespace, a final newline and list order do not change
trust. This user-owned file grants local trust; the project's configuration cannot grant it. The
[installation guide](../../../distribution/local-installation.md) describes the
complete settings and capture rules.

Merge this fragment into the application's editable YAML file:

```yaml
outputs:
  destinations:
    demo:
      plugin: private-local-values
      settings:
        endpoint: http://127.0.0.1:8080
        namespace: dev
  routing:
    default: [demo]
```

With an existing valid configuration pair, preparation reports the selected local
build and checks the public settings:

```sh
enkv prepare --source /absolute/application/configuration.yaml --source-format yaml --json
```

Effect commands also need the local service, `ENKV_EXAMPLE_TOKEN`, and the
configured domain Store/KMS actor's credentials and authority. Set the example
token in that command's environment. It is not a project configuration field.

Rebuild to the same build directory after changing the implementation. The
builder atomically changes its build marker; a later command captures the new
exact build into immutable installation storage. A running invocation keeps its
captured bytes. Public semantic target identity excludes the local plugin name
and build hash: two builds aimed at the same service URL do not create separate
ownership coordinates.

Complete-loss recovery writes the exact canonical destination/target facts with
no local plugin selected. Selecting a compatible installed implementation later
validates those bytes without applying new defaults. Deleting a coordinate after
its binding is removed uses an explicit current choice:
`--delete-coordinate <coordinate-hex>=private-local-values`. A past output
acknowledgement or an unknown result grants no resend right.

The service is a local demonstration. Its tests establish neither provider IAM
nor stock cloud CLI qualification. Plugin code is trusted native code.
