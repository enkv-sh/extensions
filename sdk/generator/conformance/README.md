# Generator author checks

`conformance.Check(generator.Run)` checks the serving exchange with a synthetic managed resource that imports no official implementation.

Build a semantic fixture with `NewFixture(implementation, Request, Expectation)`.
`Request` supplies the canonical intent, action, original retirement facts when
needed, and declared synthetic private inputs. `Expectation` supplies independent
public facts and exact value bytes. The helper fills synthetic host correlation
from the checked binding; it does not call the implementation to derive expected
service facts.

Then call `CheckImplementation(ctx, generator.Run, implementation, fixture)`
with a finite context. The lower-level `Fixture` remains available for exact raw
commands, correlation damage and serving tests. It contains the exact `Command`,
`Inputs`, independent `ExpectedFacts`, `ExpectedValue` and `ExpectedFailure`.
Keep fixture slices stable during the check and clear caller-owned private data
afterward.

For a random value, leave `ExpectedValue` nil and set `CheckValue` to an
independently derived property check. This is supported only for successful
complete creation. The check borrows a bounded capture: do not change, retain
or log it. The helper still compares the exact serialized bytes with that
capture. A passing property is only as strong as the property you assert.

The helper checks the raw callback result before SDK validation, callback arguments/deadline, one invocation, observable borrowed-input preservation, transferred-buffer disposal, complete result correlation, status and EOF. A malformed callback cannot pass merely because serving correctly refuses it. Error text uses fixed check names and includes no input or returned value.

The [local token example](../../examples/local-token-generator/README.md) checks its actual HTTP create/retire behavior, independent binary value and consumer response. Its changed-subject control must fail the author check. Service semantics remain the implementation's responsibility.

Derive the fixture from the service contract. In the example, the first resource
is the literal `t1`, and its raw value is `00 ff` followed by `demo/api/t1`.
Expected target and resource JSON are independent literals. The service request
is checked separately against `{"namespace":"demo","subject":"api"}`, and an
ordinary HTTP consumer reads the created resource. Do not generate expected
provider facts or values by calling the implementation under test.

`CheckImplementation` checks one effect exchange. Test `Normalize`, exact
canonical validation and retirement compatibility directly in the author
module. Keep credential/namespace refusal, owned-but-unusable results, lost
acknowledgements and cancellation tests there when those behaviors exist.

Run with the explicit public source workspace:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race ./conformance
```

Checks cannot interrupt arbitrary callback code, find every hidden alias, or establish installation trust, effect authority, provider permissions, one physical request or OS confinement. Keep callback work finite, close its resources and join all users before return.

The protocol's fixed frame/intent vectors are independently specified literals. The new intent vector is `U16(1) || R(1) || managed:u8(2) || R(2) || B("{}")`, where `R(n)` is 32 copies of byte `n` and `B` is a big-endian u32 length plus bytes. It has 73 bytes. The v3 Hello frame is 43 bytes of `ENKG`, version 3, kind 1, correlation and body length, followed by three 32-byte identities. No provider-specific fixture or second codec supplies the expected bytes.
