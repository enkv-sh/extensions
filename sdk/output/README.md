# Output SDK

`enkv.sh/sdk/output` provides the native entry point for independently authored
output plugins. The public `enkv.sh/sdk/protocols/output` module owns typed
operations and framing. This SDK owns serving and decoded private-buffer disposal. The artifact module supplies the
shared credential-route codec. These modules import no provider implementation.

A plugin owns its settings grammar, defaults, canonical settings, target
interpretation, credential discovery, service requests and service responses.
ENKV retains operation admission, ownership, selected value and single-send
rules. Plugin metadata supplies no permission or proof of truthful behavior.

The language minimum is Go 1.27.0. Use stock Go 1.27.3 for artifact builds. The
modules use Apache-2.0. Keep their module and license files when copying a
public kit.

## Implement a plugin

Implement `output.Implementation`. Call
`output.Bind(descriptorBytes, configContractID)` with your embedded author
`plugin.json`, check its error, and check that the returned credential route
matches the service discovery route you support. Embed the checked
`output.Binding` in your implementation to supply `Identity` and
`CredentialRoute`.

Use the maintained example's [native entry](../examples/local-value-output/main.go)
and [implementation](../examples/local-value-output/implementation.go). Its
`main` calls `os.Exit(output.Main(implementation))`; startup binding errors stop
the command before serving.

`Identity` returns the protocol and pre-build descriptor identities. The host
supplies the exact artifact-contract binding; the child echoes it. Installation
verification, rather than the child, authenticates executable bytes.

The author's descriptor selects the output family and declares its own plugin
name, configuration contract and credential route. Embed that same descriptor
in the command, as the example's `main.go` does. An arbitrary local name is
accepted through the family contract; adding a service needs no ENKV catalog
entry or host rebuild.

The five passive operations are:

- `NormalizeDestination`: apply plugin defaults and return canonical settings,
  semantic configuration/service contracts, opaque policy and action capabilities.
- `ValidateCanonical`: validate exact retained canonical facts without applying
  new defaults or rewriting bytes.
- `InterpretTarget`: derive one entry's complete public target and consumer
  reference facts and separate `CreateValueBounds`/`WriteValueBounds` intervals
  for encoded payload bytes. Target data must support later checks/deletion without old
  settings, payloads or executable bytes.
- `CheckAction`: validate one exact prospective action and return its payload
  bounds exactly as declared by the target for that action. A successful check
  supplies no send permission.
- `SelectPolicyAction`: choose `UpdatePolicy` or `WriteValue` when an owned
  value is unchanged and its policy differs. Receive the current canonical
  target/policy and an optional qualified previous policy digest. Missing
  evidence is explicit; a digest nonmatch does not identify the old policy.
  Return an explicit refusal when the plugin cannot choose an action. This
  callback must not discover credentials, read payloads or contact a service.

Canonical settings require unique decoded object keys and valid Unicode scalar
strings. Scalar roots and exact JSON numeric tokens remain supported. The SDK
rejects settings outside this common grammar before accepting a destination.

All five methods are required, including for a plugin with no policy support.
Such a plugin returns zero action and an error from `SelectPolicyAction`. The
method signature is:

```go
SelectPolicyAction(context.Context, output.PolicyActionSelection, protocol.Policy) (protocol.Action, error)
```

`PolicyActionSelection` supplies `DomainID`, the exact current `Target`, and
`HasPreviousPolicyDigest` with `PreviousPolicyDigest`. Absence is false plus a
zero digest; presence is true plus a nonzero digest. The separate `Policy`
contains the complete desired canonical identity and bytes. The host qualifies
previous evidence for the current owner; the plugin decides what its digest can
prove about an earlier policy. A successful return must be `ActionUpdatePolicy`
or `ActionWriteValue`. The target must advertise that action, and a value write
must also advertise `CapabilityWriteSetsPolicy`. Return zero and an error for
refusal. No callback result grants permission to prepare or send.

The selector runs only for an unchanged owned value with a changed policy.
Exact no-ops and independently required value writes keep their normal paths.
A selected value write sends the same value with the complete desired policy;
it does not change the value's identity or rotate it. Keep any required service
checks in `Prepare`; a failed metadata check grants no fallback value send.

`Prepare` receives `output.Preparation` with the admitted service facts, an
opaque `protocol.Policy` and borrowed private `[]credentialroute.Input` values.
The SDK handles the complete command and wire correlation. Preparation discovers
credentials and checks the service account/target before
readiness for payload delivery. It must make no mutating request. It returns a
`Prepared` value, whose `Send` method makes at most one admitted mutation and
whose `Close` method disposes private copies and joins owned work. A returned
prepared value is closed even when preparation also returns an error.

The six actions are create empty, create with value, write value, update policy,
delete owned and delete reserved slot. Capabilities describe supported actions;
Core still decides whether an action is permitted. For a dynamic action list,
use `protocol.Capabilities(actions...)` and check its error: unsupported actions
return zero capabilities and an error that matches `protocol.ErrProtocol` with
`errors.Is`. A fixed declaration can use the named capability bits.
Each advertised value action
has an inclusive interval within 0–65,536 bytes. An interval of 0–0 permits only
an empty value. An absent value action has zero bounds. ENKV checks every
scheduled value action before publication effects or private key use; metadata
actions return zero bounds and do not test unscheduled value actions.

Add `CapabilityCreateSetsPolicy` when every advertised create action establishes
the supplied policy on acknowledgement. Add `CapabilityWriteSetsPolicy` when an
acknowledged value write also establishes it. Without these facts, policy needs
its separate admitted update action. These two facts keep the six action choices
unchanged and let Core order policy updates and record their acknowledgements.

Policy bytes are plugin-owned and opaque. The policy frame carries data only;
the command binds its semantic contract and digest. Payload encoding is raw or
standard padded Base64, prepared by Crypto. Provider JSON, service encryption and
request representation belong to the plugin.

The service-contract namespace and canonical physical target determine collision
and ownership identity. Keep them stable across local aliases and compatible
builds. Build identity, local selection and target-schema version do not make
the same physical destination a new coordinate. The value-basis commitment
excludes policy and action capabilities. A changed policy keeps that value
identity; the plugin selects whether the service needs a metadata operation or
a value write carrying the desired policy.

An acknowledged create returns a complete consumer locator. A static locator
must equal the normalized locator. An assigned locator is returned only after
qualified creation; the normalized target remains unchanged. Other actions,
no-effect results and unknown results cannot assign a locator.

## Native process

The family uses output wire version 6. Its protocol identity is
`SHA256("ENKV/OUTPUT-WIRE/v6" || NUL)`. The policy-action request has a maximum
body of 7,094 bytes plus the separate policy frame of at most 524,546 bytes;
the closed result body is 36 bytes. Request correlation binds both exact bodies.

`Main` accepts one mode argument, empty inherited environment, null standard
streams, and `darwin/arm64` or `linux/amd64`:

| Mode | Read FIFOs | Write FIFO | First unassigned descriptor |
|---|---|---|---|
| `output-wire-v6` | 3 control, 4 private inputs, 5 payload/arm | 6 result | 7 |
| `output-public-v3` | 3 control | 4 result | 5 |

Each descriptor has an exact access mode. Unassigned inheritable descriptors,
including high numbers, are refused. `Main` closes its owned descriptors and
writes no diagnostics.

After complete command admission, `Main` installs only the validated declared
private environment inputs before `Prepare`. Plugin code can use ordinary
`os.Getenv` and its SDK's normal credential discovery. The native process
removes these variables when the prepared invocation closes. Passive operations
receive no environment, credential or payload channel. This is trusted native
code, without a sandbox or universal credential-worker join guarantee.

Status 0 means a complete exchange, including explicit preparation refusal;
status 1 means exchange/owned-close failure; status 2 means invalid arguments or
native shape. The host also checks exact frames, EOF and positive child closure.
Status alone proves no service effect or no-effect result.

## Stream use and ownership

`Run(ctx, output.Endpoints, implementation)` and
`RunPublic(ctx, output.PublicEndpoints, implementation)` borrow streams and
close none. They are synchronous and start no goroutines. Their caller must
bound stream lifetime and unblock I/O on cancellation. A context alone cannot
interrupt an arbitrary reader/writer.

Stream calls do not change process environment. `Prepare` receives the decoded
borrowed input values; tests of implementations using normal environment
lookup must set their test environment explicitly.

Passive callback byte slices are read-only borrows until callback return.
`Preparation.Target`, policy bytes and decoded private inputs can be used by
the returned `Prepared` until its `Close` returns. Payload bytes are read-only
borrows during `Send`; join their users before it returns. The SDK clears its
private input and payload buffers after `Close`. Do not retain any borrow past
its lifetime. Make an owned copy for transport work that can continue later;
[`CopyRequestBody`](body.go) and `TakeRequestBody` supply explicit body ownership. Value actions receive a nonnil payload, including an
empty value. Metadata actions receive nil through the separate Arm exchange.
Preparation refusal occurs before any payload read.

Return an `output.Outcome` from `Send`, using `Acknowledged`,
`QualifiedNoEffect` or `Unknown`. These constructors check bounded evidence
shape and return `protocol.ErrProtocol` on invalid input. They do not prove
service truth. `Outcome{}` is invalid. The SDK supplies command correlation and
checks assigned-locator use. A callback error or invalid outcome becomes
may-have-entered and unproved, including when the callback also returned an
acknowledgement.

Callback error, malformed evidence or a lost reply after possible effect entry
preserves unknown. No failure supplies a resend, adoption or deletion right.

## Author tests and local builds

The [local value output example](../examples/local-value-output/README.md)
implements a service and settings behavior of its own. Its tests check the real
HTTP request/result and independently read the consumer bytes. The generic
`conformance.CheckImplementation` helper checks callback bindings, raw returns,
read-only borrowing, disposal and complete serving. It does not check provider
truth or request correctness. `conformance.Check(output.Run, output.RunPublic)`
checks the shared serving entry points with an independent implementation.
`conformance.CheckPublicImplementation` checks all five passive operations,
including exact `PolicyAction`/`PolicyActionPolicy` inputs and independently
stated `ExpectedPolicyAction`/`PolicyActionAccepted` results. Supply a complete
public selection fixture even when the expected result is an unsupported-policy
refusal.

A detached public kit contains this module, the output protocol, artifact module
and the author's module. Use the explicit detached workspace in the example
for local source development. Its module requirements select exact source
versions; declarations alone do not prove publication. Versioned builds need
reachable compatible published versions of every module and `GOWORK=off`. Run each module's ordinary Go
tests; an offline populated cache can use:

```sh
GOPROXY=off GOSUMDB=off go test -race ./...
```

Use the [artifact builder](../artifact/README.md) with the author's descriptor.
Explicit local trust/install and project selection are still required. Neither
publication nor an official plugin name is required.
The example's [build and installation walkthrough](../examples/local-value-output/README.md#build-and-install)
includes the five-module detached workspace, trusted application selection and
editable output declaration. Keep executable selection in trusted user settings;
public project settings contain no executable path or credential.

After complete local source loss, recovery preserves canonical destination and
target facts with executable selections unset. A later effect request needs an
explicit compatible installed plugin. Historical output state retains the
passive facts needed for ownership and deletion, without an old payload or a
right to rerun the old executable. Removed-binding deletion selects its current
implementation explicitly by coordinate.
