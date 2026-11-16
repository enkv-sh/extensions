# Manifest protocol

This Apache-2.0 module defines `manifest-wire-v2` on request/artifact/status
descriptors 3/4/5. It carries public settings or one complete authorized public
projection and inert bytes. It grants no Reader authority or provider capability.

Each one-shot request binds a nonzero correlation and pre-build descriptor
identity. `OperationValidateSettings` carries declared format/configuration
identities and at most 16,384 JSON settings bytes. Its response echoes the digest
of the exact request and returns canonical settings. Canonical validation requires
byte equality. `OperationRender` carries those settings and the complete bounded
projection. The parent uses the same exact installed build for both operations.

`WriteRequest` and `WriteRenderRequest` stream borrowed data through return.
Keep that data unchanged until the call returns. Context checks between I/O calls
do not stop blocked I/O; the transport owner must arrange cancellation and closure. `ReadRequest`
constructs one owned request, enforces field/vector/aggregate bounds before
allocation and requires exact EOF. Call `Dispose` after all borrowers join.
Large opaque policy and value fields use 49,152-byte windows.

Status is exactly 58 bytes: magic/version, correlation, closed failure code and
artifact length, then EOF. Success declares 1–246,313,668 bytes; failure declares
zero. The sender closes status before writing artifact bytes. The parent must
compare correlation, check the declared operation's length bound and require exact
artifact EOF. Settings response parsing also checks the exact request digest.

Protocol validation establishes structural facts only. Artifact format validity
and correspondence belong to the author. The native serving helper is
`enkv.sh/sdk/manifest-generator/native`; the parent owns exact installed-byte
admission, finite lifetime, cancellation and positive child/transport joins.

The projection schema is `ENKV/CONSUMPTION-PROJECTION/v1`; it is separate from
the plugin's format contract. Public semantic contract strings are bounded to
256 UTF-8 bytes. The request retains at most 512 included/excluded entries,
1,024 destinations, 8 MiB of plain values and 36 MiB of public destination facts.
An empty selection still carries a complete observation and selector header.
The service filter is an optional exact semantic string, independent of the
Store provider and installed plugin name.

Authors normally use the [SDK](../../manifest-generator/README.md) and
`native.Serve` instead of implementing pipe lifetime and framing themselves.
The [independent INI example](../../examples/ini-reference-manifest/README.md)
owns its settings and output grammar while using this same protocol.
