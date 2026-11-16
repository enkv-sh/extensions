# Output conformance

This package checks the public output serving contract with ordinary Go tests.
It imports no official provider implementation or private ENKV package.

Use `Check(output.Run, output.RunPublic)` for a serving wrapper. Use
`CheckImplementation` for the implementation itself. Prefer
`NewFixture(implementation, Request, expectedOutcome)`: supply the preparation
facts, opaque policy, synthetic private inputs, payload and independently
expected `output.Outcome`. The helper supplies synthetic host correlation from
the checked binding. It does not derive expected service behavior from the
implementation. Keep slices stable during the check; clear caller-owned private
data afterward.

The lower-level `Fixture` remains supported for raw command/correlation tests.
It contains a command, policy, inputs, payload and independently expected wire
result. `CheckPublicImplementation` uses `PublicFixture` to check all five
passive callbacks, including acceptance/refusal, exact expected destination,
target and bounds, with no effect callback entry. `PolicyAction` and
`PolicyActionPolicy` supply the fifth call's public selection and desired policy;
`ExpectedPolicyAction` and `PolicyActionAccepted` state its independent result.
Supply an explicit refusal expectation when policy selection is unsupported.
For a deletion action fixture, it also checks the retained deletion-only target:
the selected deletion capability remains and both value intervals are zero.
Supply the original ownership facts and independently expected acceptance.
Target capabilities are a supported subset; complete destination declarations
still require exact equality. Added capabilities and nonzero bounds for absent
value actions are invalid.

Construct expected outcomes or raw `Expected` results from independent service facts. A successful creation, for
example, needs the expected status, nonempty `SafeResourceID` for the owned
instance and complete consumer locator; do not copy the implementation's returned result into the fixture.
Use a finite context. `Run` borrows its streams and cannot interrupt arbitrary
blocking I/O by context cancellation alone.

The helper invokes the supplied implementation, checks its raw result before
serving normalization, verifies callback count and complete correlated frames,
and checks private disposal. The effect helper expects successful preparation,
send and close; author tests must cover preparation refusal and partial failures. It rejects changes to borrowed inputs/payloads and
records result overflow even if the serving wrapper ignores the write error.

A passing helper establishes this local common exchange only. Keep service
request bytes, retry behavior, result interpretation, consumer bytes and
credential/account checks in implementation-owned tests. Native descriptor
shape, immutable installation, Core authority, restart continuity and live
service behavior need their owning checks.

The [local output example](../../examples/local-value-output/implementation_test.go)
shows the distinction. Its defective implementation sends `BAD` instead of the
requested binary bytes. The common helper accepts its truthful family-shaped
acknowledgement, while an independent GET of the service value detects the wrong
payload. The same example checks exact normalization, target identity, guarded
ownership, empty/maximum values, namespace credentials and lost replies.

Run the author tests from their module with the explicit public workspace or
exact versioned dependencies selected. The
[example guide](../../examples/local-value-output/README.md#run-author-checks)
lists the complete detached module set. No private test facade or official
plugin implementation is required.
