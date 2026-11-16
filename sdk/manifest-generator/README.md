# Manifest-generator SDK

This Apache-2.0 Go module defines a bounded public consumption projection,
read-only renderer views, settings callbacks and native serving. A plugin owns
its format, settings grammar, defaults and semantic correctness. The SDK and
native host use no provider or format catalog.

Start with the [independent INI example](../examples/ini-reference-manifest/README.md).
Its walkthrough builds from four public modules, tests its own format and consumer,
captures an unpublished artifact, adds explicit application trust and renders with
the existing CLI. The example implements the format directly.

Implement `Implementation.ValidateFormatSettings` and `Implementation.Render`.
The first callback receives public JSON settings and declared format/configuration
identities. Return one owned exact-capacity canonical JSON byte slice, or a closed
failure with no bytes. Canonical input must be returned byte-for-byte unchanged.
The render callback borrows one complete authorized projection and returns one
owned exact-capacity artifact of 1–246,313,668 bytes, or a closed failure. Join all
callback work before return and retain no mutable input or result alias.

Use `native.Bind` with the embedded descriptor bytes, your supported settings
contract, your supported format contract and both callbacks. Pass the returned
`native.Implementation` to `native.Main`. Binding checks the family and declared
contracts and derives the pre-build identity. See the complete
[example entry point](../examples/ini-reference-manifest/main.go) for imports,
embedding and error handling. The descriptor
declares the plugin name, supported family wire and your format/configuration
contracts. It contains no final executable hash. The public artifact builder
measures executable and dependency facts after compilation.

`Projection` owns canonical format settings, selection, observation, included
plain values, secret destination references, opaque policy facts and exclusions.
It contains no secret values, credentials, Store client or operation capability.
`Validate` checks common structure, exact partition and finite aggregate bounds.
It does not authenticate state or interpret declared service/target/format data.
`MaxLocatorBytes` bounds both consumer locators and canonical target text.

`FailureFromContextError(ctx.Err())` maps the original context error to the
closed cancellation or expiry failure. Check your API's nil-context policy
before calling `Err`. The helper does not unwrap errors or change that policy.

Views expose immutable scalar metadata and bounded copy accessors. No accessor
returns mutable owner backing. Settings, plain values, target data and policy
bytes use caller-owned windows of at most 49,152 bytes. Check
`EntryView.Metadata().Kind` before reading a plain value: `PlainLength() == 0`
can mean an empty plain value, a secret entry or an invalid view.
`CopyPlainValue` instead copies a complete value of up to 65,536 bytes into a
sufficient caller-owned destination. It allocates no backing and leaves an
unused tail unchanged; the caller still owns encoding, artifact construction and
clearing its destination. The owner must freeze its
projection until every borrower returns. Views expire when the owner is disposed.
`EntryCount`/`Entry`, `DestinationCount`/`Destination` and
`ExcludedCount`/`Excluded` traverse the complete input. Preserve its exact
included/excluded partition, observation, resolved target and selector modes in
the artifact. Empty and all-excluded selections are legal. A nonnull service
filter compares the stored semantic service contract; plain entries are not
filtered. The renderer receives the selected facts and performs no provider
lookup to resolve them.

`ValidateResult` checks the observable owned-return shape. `MeasureArtifact`
reports length and SHA-256 of the exact bytes; it performs no format or semantic
comparison. Runtime success means authorized input, selected build, correlation,
framing, bounds, deadline, positive child/transport closure and exact delivered
bytes. A plugin's own complete-output and consumer tests establish format meaning.
Native code remains trusted and has its actual process reach.

Use `native.Main(implementation)` for an executable plugin. Its identity contains
the protocol identity and the pre-build descriptor identity. Public build tools
measure executable/dependency facts separately. Native serving consumes one
settings or render request on descriptors 3/4/5. Both operations release owned
buffers after the transport closes, including malformed and cancelled returns.
The parent owns finite process lifetime and unblocks borrowed reads on cancellation.

Use the [conformance package](conformance/implementation.go) with the actual
author callbacks, independently expected canonical settings and complete artifact
bytes, or an exact closed failure. Its package documentation describes fixture
ownership and check limits. These checks define no format fixture or verifier.

Keep format expectations in the author module. Supply literal complete expected
bytes derived from the fixture fields, and pass those bytes to an independent
consumer. Include a real encoder mistake that the author check and consumer
comparison detect. A protocol-valid but wrong body can pass the common runtime
contract; `MeasureArtifact` must not be used as a format verifier.

`CopySettingsResult` makes an independent exact-capacity copy of valid JSON.
Validate your grammar and canonicalize settings first. The source and its spare
capacity remain yours to clear; the returned allocation transfers to the receiver.
The helper does not remove JSON encoding or format work.

`jsonwriter` supplies optional bounded count/write, text, ID and Base64 mechanics.
Every layout stays in the plugin. The
[INI example](../examples/ini-reference-manifest/README.md) implements its own
settings, format, complete-byte tests and independent consumer.

The module language minimum is Go 1.27.0; stock Go 1.27.3 is used for normal
artifact builds. Follow the [INI walkthrough](../examples/ini-reference-manifest/README.md)
for a public source workspace, tests, artifact capture and selection. See the
[distribution guide](../../distribution/README.md) for shared source and
exact-version build prerequisites and the
[local installation guide](../../distribution/local-installation.md) for trust rules.
