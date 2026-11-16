# Native manifest serving

`Main` validates fixed native descriptors, the `manifest-wire-v2` argument and an
empty environment, then serves one operation through `Serve`. Descriptors 3, 4
and 5 are request, artifact and status pipes. Standard descriptors must point to
`/dev/null`; unexpected inheritable descriptors are refused.

Call `native.Bind` with your descriptor bytes, supported config and format
contracts, and both callbacks in `manifest.Implementation`. Pass the resulting
`native.Implementation` to `Main` or `Serve`. Binding checks the descriptor
family, wire and contract declarations; serving checks the bound identity and
callback presence before either callback. Settings validation
and rendering use separate one-shot processes. The parent retains the same exact
installed build, sets the finite deadline, unblocks I/O on cancellation and joins
its child and transport. This is trusted native execution, with no sandbox claim.

`Serve` borrows its request and owns both output writers. It closes status before
artifact output and releases every owned settings, projection and return buffer
on success or failure. Exit zero means a complete legal exchange, including a
closed failure; one means incomplete I/O and two means an invalid invocation.
Common success reports exact bytes, not format validity or semantic correspondence.

Use `native.Main` only as the entry point of a captured plugin executable. A
shell invocation does not supply its required descriptor layout. For direct
author tests, call `Serve` through
`conformance.CheckSettingsImplementation` or `CheckImplementation` with your
bound callbacks and independently expected bytes. See the
[conformance package](../conformance/implementation.go) for fixture and lifetime rules. The
[INI walkthrough](../../examples/ini-reference-manifest/README.md) shows local
artifact capture, explicit trust and CLI selection with `--plugin` and
`--settings`.
