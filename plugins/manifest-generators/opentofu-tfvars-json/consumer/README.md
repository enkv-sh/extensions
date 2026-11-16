# Consume reference data with OpenTofu

This example pins OpenTofu `1.13.2`. It declares no resource, provider, data
source, child module or configured backend. It reads a local input document,
decodes one known UTF-8 plain value, and exposes a named secret reference.
It never retrieves the secret value.

`main.tf` declares the exact `enkv` root object. The root cannot be null.
The required `service_filter` and `consumer_policy` attributes can be null.
The header check requires the reference-manifest schema and format/config contracts.

The fixed `example.tfvars.json` contains public fixture facts:

| Entry | Input | Consumer access |
|---|---|---|
| `service_url` | UTF-8 `https://example.invalid`, stored as padded Base64 | `local.service_url` |
| `binary` | bytes `00 ff`, stored as `AP8=` | `local.binary_base64` |
| `api_token` | AWS destination named `primary` | `local.api_token_reference.consumer_locator` |

The fixture contains no token value. Its observation IDs are fixed example
data, not authenticated Reader evidence. For an actual observation, use the
`.tfvars.json` artifact delivered by `enkv manifest`.

With the renderer already trusted and installed for the source application,
create that artifact through the same generic plugin selection used by other
formats:

```sh
enkv manifest --source /absolute/application/configuration.yaml --source-format yaml \
  --out /absolute/application/enkv.tfvars.json --plugin opentofu-tfvars-json \
  --settings '{}' --json
```

This command reads the authorized public projection and writes a local file.
The caller supplies its existing Store read access; the renderer receives no
service credentials and keeps secret references inert.

## Evaluate locally

Use a new consumer directory with no existing state. From the plugin
directory, copy only this consumer configuration and the input document:

```sh
mkdir /absolute/consumer-check || exit 1
cp consumer/main.tf /absolute/consumer-check/main.tf || exit 1
cp consumer/example.tfvars.json /absolute/consumer-check/enkv.tfvars.json || exit 1
```

In a shell for this example, use the same fresh local data directory for all
commands:

```sh
export CHECKPOINT_DISABLE=1
export TF_DATA_DIR=/absolute/consumer-check/.tofu-data
tofu version -json
tofu -chdir=/absolute/consumer-check init -backend=false -get=false -input=false -no-color
tofu -chdir=/absolute/consumer-check validate -no-color
tofu -chdir=/absolute/consumer-check console -state=/absolute/consumer-check/unused.tfstate -var-file=/absolute/consumer-check/enkv.tfvars.json
```

Require version `1.13.2`. The initializer skips backend configuration and module
fetching; this consumer needs no provider installation.
[OpenTofu validation](https://opentofu.org/docs/v1.13/cli/commands/validate/)
checks the configuration. Console evaluates the input through a new local
state path and uses no existing or remote state.

At the console, enter:

```text
local.service_url
local.binary_base64
local.api_token_reference.consumer_locator
exit
```

For the fixed fixture, the results are:

```text
"https://example.invalid"
"AP8="
"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-AbCdEf?stage=AWSCURRENT"
```

The complete `local.api_token_reference` also preserves the destination's
semantic service/target contracts, encoding, opaque policy and identity facts. The secret location
remains a reference.

This example needs no `plan` or `apply`. Run it only in the new consumer
directory, with its own local data/state paths. Use the original padded
Base64 string for arbitrary bytes; `base64decode` is for known UTF-8 text.
The consumer type checks the format used by this plugin. ENKV checks the
common input and delivery contract. The plugin's tests establish format
correctness and correspondence with the supplied projection.
