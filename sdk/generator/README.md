# Generator serving API

This Apache-2.0 Go module serves `ENKV-GENERATOR-WIRE/v5`. A plugin owns its settings grammar, defaults, canonical settings, credential discovery and resource interpretation. New local services use the same API without an ENKV provider entry.

Use stock Go 1.27.3. The public module path is `enkv.sh/sdk/generator`; its dependencies are the public generator protocol and artifact credential-route codec. The [local token example](../examples/local-token-generator/README.md) implements its own managed service behavior and gives a complete detached build, local trust and project-selection workflow.

## Implement a generator

Call `Bind(descriptorBytes, configContractID)` with your embedded author
`plugin.json` and the semantic configuration contract your implementation
supports. Check the returned error, then check that `binding.CredentialRoute()`
matches your service's supported discovery route. Set `Implementation.Binding`
to that checked binding and provide these callbacks:

- `Normalize` returns an owned canonical `protocol.Intent` from public JSON settings.
- `ValidateCanonical` validates the exact existing intent. It returns no replacement bytes or new defaults.
- The SDK calls `CheckRetirementCompatibility` only when `Retire` is implemented. The check accepts or refuses the exact original intent/resource facts and required completion class. An implementation used only for retirement can omit `Create`.
- `Create` returns typed public facts and an owned private value.
- `Retire` returns typed public facts for the exact original resource, with no value.

Managed-resource implementations provide both retirement callbacks. A generator with no external resource can omit them. Lifecycle and resource facts come from normalization, rather than a provider catalog.

Start with the example's [native entry](../examples/local-token-generator/main.go)
and [implementation](../examples/local-token-generator/implementation.go). The
entry embeds `plugin.json`; the implementation calls `Bind` and checks its
credential route before any callback can serve. The implementation contains the settings
parser and actual service requests. For your plugin, choose your own module,
local plugin name and semantic contracts, then implement these callbacks in that
module. A descriptor can declare a new identity within this family; it cannot
add a new Core operation.

Keep normalization and compatibility checks passive. They must not load a
credential or perform a create, retirement or provider discovery request.
Normalization returns deterministic canonical JSON with defaults applied once.
Canonical validation checks that existing representation without replacing it.
Canonical settings require unique decoded object keys and valid Unicode scalar
strings. Scalar roots and exact JSON numeric tokens remain supported. The SDK
rejects settings outside this common grammar before accepting the intent.
Canonical requests use `CanonicalHistorical` to check existing intent or
`CanonicalFreshCreate` to check new creation. Historical validation needs only
`ValidateCanonical`. Fresh creation also needs `Create`; managed creation needs
`Retire` and `CheckRetirementCompatibility`. These checks use public input only.
Compatibility checks the original resource contract, target, resource data and
required completion class before a new retirement Duty can accept the build.

Call `os.Exit(generator.Main(implementation))` from `main`. `Main` requires the `generator-wire-v5` argument and owns descriptors 3–6. It checks the native standard streams, FIFO directions and extra inheritable descriptors. The supported tuples are `darwin/arm64` and `linux/amd64`.

The executable starts with an empty environment. After exact Hello, command and credential-route checks, `Main` installs only the privately transported declared environment variables for the effect callback. Implementations can use `os.Getenv` and standard service SDK discovery. `Main` removes those variables at return and clears mutable private input buffers. Passive callbacks receive no private environment. This does not confine trusted native code or clear immutable SDK/runtime copies.

`Run` serves the same exchange using borrowed streams. It does not change process environment. Its effect `Invocation.Inputs` borrows the decoded private environment values; use these directly in in-process checks or arrange the author test environment explicitly. The caller must bound I/O, unblock its owned streams on cancellation and join every user.

## Identities and outcomes

Hello binds the supported protocol and the author's pre-build descriptor. The host's measured artifact-contract identity is echoed as an invocation binding; the child does not authenticate its own executable. Explicit local installation and exact measured-byte checks belong to the host.

Intent commits only its configuration contract, lifecycle, resource contract and exact canonical JSON settings. Build selection and credential recipe are separate. An implementation can validate an earlier semantic contract without a host catalog. New retirement compatibility does not replace the exact executor/route retained by accepted work.

A completed create transfers the returned bytes without conversion. The host checks them against the entry’s input encoding: raw uses 1–65,536 bytes; strict padded Base64 uses at most 87,384 retained bytes for 1–65,536 decoded bytes. The SDK transport permits at most 87,384 retained value bytes and a complete result body of 91,618 bytes. Managed creation also returns exact public target/resource facts. Owned-unusable creation preserves the resource without a usable value. Confirmed no-effect, retirement acknowledged and unknown are distinct dispositions. Native retirement proves acknowledgement, not confirmed invalidation. A lost response, malformed return or callback error cannot grant a retry.

## Ownership and lifetime

Callbacks borrow request bytes and private input values only until synchronous return. Do not change, retain or clear them. Join all users before return. Returned variable facts, canonical settings and private values transfer their complete mutable allocations to the SDK even when a callback also returns an error. Expose the complete capacity, with no borrowed-input alias, hidden prefix or retained user.

The private value and each public fact must have separate backing through their exposed capacities. The SDK checks this before encoding the response. It clears transferred values and variable backing after encoding or refusal, including failed writes. It checks observable input overlap, but cannot prove absence of hidden aliases or immutable copies. Implementations must dispose their own request/response resources and copies that they do not transfer.

Callback contexts cannot exceed the issued deadline. Cancellation before callback entry refuses. Valid original managed-resource evidence can still be returned after cancellation; discarding it cannot establish no effect. A no-managed-resource result is discarded after cancellation. No write or callback is retried.

## Tests and author checks

Use the detached module layout and explicit workspace in the
[local token example](../examples/local-token-generator/README.md#build-and-test).
With that public source workspace selected, run this module's tests:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race ./...
```

The [conformance package](conformance/README.md) checks supplied callback returns before SDK normalization, full exchange correlation and observable disposal. Keep independent service request, response and consumer expectations beside the plugin. SDK conformance supplies no operation authority, installation trust, provider permission or native confinement.
