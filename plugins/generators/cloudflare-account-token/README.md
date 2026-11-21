# Cloudflare account-token generator

`enkv-generator-cloudflare` creates account-owned API tokens and retires exact
retained tokens through generator wire version 5. Operators select the installed
plugin through `enkv`; the SDK carries canonical settings, public resource facts
and private value bytes through separate bounded records.

The plugin owns its settings grammar. Unknown fields and duplicate fields are
refused. Set these fields in a generated entry's `source.settings`:

| Setting | Required | Accepted value or default |
|---|---|---|
| `account` | Yes | 32 lowercase hexadecimal characters. No default. |
| `name` | Yes | 1–120 UTF-8 bytes with no ASCII control bytes or DEL. No default. |
| `policies` | Yes | 1–32 distinct policies. Each needs `effect` (`allow` or `deny`), 1–64 distinct `permission_groups` IDs and 1–256 distinct `resources`. IDs use the same hex form as `account`. |
| `request_ip` | No | Object with optional `in` and `not_in` CIDR arrays; omitted or empty means no request-IP control. |
| `not_before` | No | Whole-second UTC time, year 1970 or later; omitted means no start control. |
| `expires_on` | No | Whole-second UTC time, year 1970 or later; omitted means no expiry control. |

Normalization orders permission groups, resources, policies and network prefixes.
Canonical settings preserve the account, token name and complete controls.

```json
{
  "account": "0123456789abcdef0123456789abcdef",
  "name": "deployment-token",
  "policies": [{
    "effect": "allow",
    "permission_groups": ["1234567890abcdef1234567890abcdef"],
    "resources": [{"kind": "account", "id": "0123456789abcdef0123456789abcdef"}]
  }]
}
```

Policy resources accept `account`, `zone` and `account_zones`. Account and
account-zones resource IDs must equal `account`, and one policy cannot contain
both kinds. Zone IDs are explicit. Replace the example IDs with real account
and permission-group IDs; syntax acceptance does not establish permissions.
Network prefixes must use canonical CIDR form with no host bits. Time controls use whole-second
UTC form, such as `2026-01-01T00:00:00Z`, with the start before expiry.
Each policy has at most 64 permission groups and 256 resources; settings have at
most 32 policies and 128 prefixes per list. Complete settings and intent must
also fit the generator family's byte bounds.

The embedded `cmd/enkv-generator-cloudflare/plugin.json` declares the wire,
canonical settings contract and credential route. The executable accepts its
own exact canonical settings. Retirement compatibility checks the original
canonical intent, account, token identity and complete public provider facts.
It accepts acknowledgement-level retirement only.

## Authentication and permissions

Set `CLOUDFLARE_API_TOKEN` in the local environment. Its public route declares
that variable; the native SDK supplies its captured private value to the plugin.
The plugin validates its bearer form before a provider request. Changing the
credential value retains the admitted account and token target.

The management credential needs `Account API Tokens Write` for the selected
account. The policies in the generated token's settings determine the new token's
permissions. See Cloudflare's
[Create Token API](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/create/).
Effective permission and expiry remain provider facts.

## Effect and completion limits

The production implementation uses `https://api.cloudflare.com/client/v4`.
Each invocation owns a fresh HTTP/1.1 transport, performs at most one request and
closes its response and request-body owners. It has no endpoint setting,
proxy fallback or automatic retry.

A successful creation returns private bearer bytes and public account/token
facts. A creation with an identified token but an unusable value retains that
owned resource for cleanup. Malformed responses, lost replies and transport
failures retain uncertainty. Public provider facts contain bounded status,
control-match and diagnostic-code fields; they contain no bearer value or raw
provider error text.

A matching delete reply establishes deletion acknowledgement. It does not prove
that an old token is unusable. Cleanup names only the exact retained account and
token; it cannot recover an unknown creation through listing or adoption.

## Find the marker for a lost CREATE reply

Each CREATE sends a public marker in its HTTP `User-Agent`. If a reply is
lost, the domain can be free while the token is still active. To identify
the request, run `enkv generated list --source configuration.json --source-format json --json`
with your configuration path. Find the possible-live CREATE warning for that
operation and copy its `hazards[].facts.original_attempt_id`. The human
output labels the same value `Attempt ID`.

Replace `ATTEMPT_ID` below with that value. This local Python 3 command
prints the exact CREATE user agent, including the marker.

```sh
python3 - 'ATTEMPT_ID' <<'PYTHON'
import hashlib
import re
import sys

attempt = sys.argv[1]
if not re.fullmatch(r"[0-9a-f]{64}", attempt) or attempt == "0" * 64:
    sys.exit("Expected the 64 lowercase hex digits of a nonzero CREATE Attempt ID")
marker = hashlib.sha256(b"ENKV/Cloudflare/audit-marker/v1\0" + bytes.fromhex(attempt))
print("enkv-generator-cloudflare/0.1.0 audit/" + marker.hexdigest())
PYTHON
```

The marker can help match a request in the Cloudflare audit log. A match
alone cannot establish the token ID or authorize a retry or deletion.
This procedure applies to CREATEs sent by a plugin build with marker support.

## Building

Start with the [public source layout and build setup](../../../distribution/README.md).
Use an explicit workspace and the public artifact builder with
`cmd/enkv-generator-cloudflare/plugin.json` as the declaration. The selected
command is `./cmd/enkv-generator-cloudflare`.

From a checkout with its explicit public workspace:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -directory /ABSOLUTE/PUBLIC/plugins/generators/cloudflare-account-token \
  -descriptor cmd/enkv-generator-cloudflare/plugin.json \
  -command ./cmd/enkv-generator-cloudflare \
  -output /ABSOLUTE/PRIVATE/cloudflare-build -workspace /ABSOLUTE/PUBLIC/go.work
GOWORK=/ABSOLUTE/PUBLIC/go.work go -C /ABSOLUTE/PUBLIC/sdk/artifact run ./cmd/enkv-plugin-build \
  -verify /ABSOLUTE/PRIVATE/cloudflare-build
```

Use the [local installation guide](../../../distribution/local-installation.md)
to explicitly trust that output for an application. The project then selects
`plugin: cloudflare-account-token` in a generated entry's source and supplies the
settings above. Neither a source path nor settings can grant installation trust.
The public [generator author guide](../../../sdk/generator/README.md) and
[independent example](../../../sdk/examples/local-token-generator/README.md)
show the callback API and detached source workflow.

From a detached public layout with dependencies available, run the module's
request/response and lifecycle checks from its directory:

```sh
GOWORK=/ABSOLUTE/PUBLIC/go.work GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race ./...
```

A modified local build uses these same public interfaces. Keep the canonical
intent equal for same-epoch reuse; changing intent at that epoch refuses. An
accepted Duty retains its original exact executor and credential route.
A NEW retirement after removal or conversion to supplied input requires an
explicit compatible selection, such as
`--retire-generator TOKEN=cloudflare-account-token`. Rotating the environment
credential does not change the retained account/token target or grant a retry.

The `enkv_cloudflare_testartifact` tag builds the separate
`./cmd/enkv-generator-cloudflare-test` command. That fixture injects a local TLS
transport endpoint at link time and disables certificate verification only in
the tagged implementation. Its distinct artifact bytes must be admitted by the
local test fixture. It does not qualify Cloudflare service behavior or production
certificate validation.
