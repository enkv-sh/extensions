# AWS Secrets Manager output

This module implements an output plugin for AWS Secrets Manager. Its native
command embeds `cmd/enkv-output-aws-secrets-manager/plugin.json` and serves the
public output SDK. Settings, AWS target interpretation, credential discovery,
request construction and response checks belong to this module.

## Settings and values

A destination needs an explicit twelve-digit account and a supported commercial
region:

```json
{"account":"123456789012","region":"ap-southeast-2"}
```

Both fields are required strings with no defaults. Unknown and duplicate fields
are refused. `account` is exactly twelve decimal digits. `region` must occur in
the plugin's [commercial-region list](profile/profile.go); GovCloud and China
partitions are unsupported. Entry names use 1–512 ASCII bytes from
`A–Z a–z 0–9 / _ + = . @ -`.

Merge this fragment into an existing valid application configuration:

```yaml
outputs:
  destinations:
    primary:
      plugin: aws-secrets-manager
      settings:
        account: "123456789012"
        region: ap-southeast-2
  routing:
    default: [primary]
```

Each entry name becomes the secret name. The plugin validates the name and
constructs its planned ARN from these settings. Passive normalization and target
interpretation use no credentials or service calls. Canonical validation checks
the exact retained settings without adding defaults.

The supported actions are create empty, write value, delete owned and delete
reserved slot. Writes accept 1–65,536 prepared bytes. Crypto supplies raw or
standard padded Base64 bytes; the plugin puts them in the service request. Empty
application values cannot use this implementation's value-write action.

Creation returns the complete service-assigned ARN and a consumer reference with
`?stage=AWSCURRENT`. Until its acknowledgement, a planned ARN does not establish
that consumer reference. Retained target data preserve the account, region and
secret name for guarded deletion after an output binding is removed.

The plugin has no policy, KMS-key, replica, rotation or endpoint settings. It
creates an empty secret, writes `SecretBinary` with `AWSCURRENT`, and requests
seven-day recovery on deletion. A deletion acknowledgement establishes the
accepted schedule, not permanent erasure. See the AWS API contracts for
[creation](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html),
[value writes](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html)
and [deletion](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html).

## Credentials and effects

The plugin uses the pinned AWS SDK's standard credential provider chain inside
its native process. Its descriptor declares the SDK route's environment names;
ENKV transports those bounded inputs privately after admission. Shared config,
SSO and other SDK sources keep their normal trusted file/helper requirements.
Credentials do not belong in destination settings or installation metadata.
For environment credentials, set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
and, for temporary credentials, `AWS_SESSION_TOKEN`. `AWS_PROFILE` can select
an existing shared configuration. The pinned client is AWS SDK core `v1.39.0`
with config `v1.31.7`; see the
[SDK credential sources](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html#specifying-credentials).
The acting identity needs the applicable `secretsmanager:CreateSecret`,
`secretsmanager:PutSecretValue` and `secretsmanager:DeleteSecret` permissions.
The plugin does not create IAM grants.

Preparation captures credentials and makes a bounded read-only STS identity
check for the declared account before payload delivery. Each prepared invocation
allows one admitted mutation and disposes its private copies on close. A lost
reply preserves uncertainty; the implementation does not resend the mutation.
Credential discovery and a successful identity check do not establish IAM
permission for a later Secrets Manager operation.

## Build and select

Start with the [public source layout and build setup](../../../distribution/README.md).
Use the [public artifact tool](../../../sdk/artifact/README.md) with the module's
pinned dependencies and an explicit workspace:

```sh
enkv-plugin-build -directory /absolute/aws-secrets-manager -descriptor cmd/enkv-output-aws-secrets-manager/plugin.json -command ./cmd/enkv-output-aws-secrets-manager -output /absolute/builds/aws-secrets-manager -workspace /absolute/go.work
enkv-plugin-build -verify /absolute/builds/aws-secrets-manager
```

Explicitly trust the captured local build for one application, then select
`plugin: aws-secrets-manager` with the settings above in its output declaration.
The [local installation guide](../../../distribution/local-installation.md)
describes user settings and immutable capture. A modified local build uses the
same public family contract without an ENKV rebuild or publication requirement.

From this module in the detached public workspace, with dependencies available:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work GOTOOLCHAIN=local go test ./...
```

The tests use controlled requests and responses. Actual service access and
permissions require separately authorized provider execution.
