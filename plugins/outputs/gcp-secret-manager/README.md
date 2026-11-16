# GCP Secret Manager output

This module implements an output plugin for Google Cloud Secret Manager. Its
native command embeds `cmd/enkv-output-gcp-secret-manager/plugin.json` and serves
the public output SDK. It owns public settings, canonical targets, credential
discovery, service request encoding and response interpretation.

## Settings and values

A destination uses the canonical positive decimal project number:

```json
{"project_number":"123456789012"}
```

`project_number` is required, has no default, and must be a decimal string from
`1` through `9223372036854775807` with no leading zero or sign. A project ID is
not accepted. Unknown and duplicate fields are refused. Entry names use 1–255
ASCII letters, digits, `_` or `-`.

Merge this fragment into an existing valid application configuration:

```yaml
outputs:
  destinations:
    primary:
      plugin: gcp-secret-manager
      settings:
        project_number: "123456789012"
  routing:
    default: [primary]
```

Each entry name becomes a secret name under
`projects/<project-number>/secrets/<entry-name>`. The consumer reference appends
`/versions/latest`. The project comes from the explicit canonical target, not
an ADC default project. Passive normalization and target interpretation perform
no credential lookup or service call. Canonical validation preserves the exact
retained public settings.

The supported actions are create empty, write value, delete owned and delete
reserved slot. Value writes accept 1–65,536 prepared application bytes. Empty
values are refused before publication effects. Crypto supplies raw or standard
padded Base64 application bytes; the plugin performs the API's request encoding.
Target data retain the complete
project/secret interpretation needed for guarded deletion after the binding is
removed.

The plugin creates secrets with automatic replication and no initial version.
Each value write adds one version and includes a CRC32C checksum. Deletion first
reads the exact secret metadata, then sends the returned etag with its delete
request; failed discovery sends no mutation. It has no IAM-policy, replication,
rotation or endpoint settings. See the service contracts for
[creation](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/create),
[value writes](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/addVersion)
and [deletion](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/delete).

## Credentials and effects

The plugin discovers Application Default Credentials through its pinned Google
auth SDK inside the native process. The descriptor declares the SDK route's
environment inputs; the host transports those bounded inputs privately after
admission. ADC's trusted files and helpers keep their normal requirements.
Credentials and access tokens are absent from project settings and public
results. ADC can use a file selected by `GOOGLE_APPLICATION_CREDENTIALS`, an
existing local ADC file, or the attached service account. See
[ADC sources](https://cloud.google.com/docs/authentication/application-default-credentials).
The pinned discovery library is `cloud.google.com/go/auth v0.14.1`; metadata
calls use `google.golang.org/api v0.222.0`. This plugin accepts only the
`googleapis.com` universe and captures a bearer with a future expiry. It requests
the `cloud-platform` OAuth scope. The acting identity needs the applicable
`secretmanager.secrets.create`, `secretmanager.versions.add`,
`secretmanager.secrets.get` and `secretmanager.secrets.delete` permissions.
The plugin does not configure IAM grants.

Preparation captures one bearer token for the invocation. The admitted command
fixes its exact target. Each prepared invocation allows one mutation and clears
its private credential copies on close. A complete create reply with matching
HTTP 409 and `ALREADY_EXISTS` status returns a qualified rejection. It grants no
ownership, deletion or automatic retry. Other failed, malformed, incomplete or
lost responses after possible effect entry remain unknown. Discovery success
does not establish permission for a future service request.

## Build and select

Start with the [public source layout and build setup](../../../distribution/README.md).
Use the [public artifact tool](../../../sdk/artifact/README.md) with the module's
pinned dependencies and an explicit workspace:

```sh
enkv-plugin-build -directory /absolute/gcp-secret-manager -descriptor cmd/enkv-output-gcp-secret-manager/plugin.json -command ./cmd/enkv-output-gcp-secret-manager -output /absolute/builds/gcp-secret-manager -workspace /absolute/go.work
enkv-plugin-build -verify /absolute/builds/gcp-secret-manager
```

Explicitly trust the captured local build for one application, then select
`plugin: gcp-secret-manager` with the settings above. The
[local installation guide](../../../distribution/local-installation.md)
describes user settings and immutable capture. A modified local build uses this
same public interface without an ENKV rebuild or publication requirement.

From this module in the detached public workspace, with dependencies available:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work GOTOOLCHAIN=local go test ./...
```

The local tests use controlled requests and responses. They do not perform a
cloud login or establish live permissions.
