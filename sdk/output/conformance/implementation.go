package conformance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// Fixture is the raw effect-exchange fixture. Prefer NewFixture for semantic
// inputs with synthetic host correlation. Expected must be independently derived
// public evidence, not a copy of the callback's result. Slices remain caller-owned
// and read-only until the check returns; clear private inputs and payload afterward.
type Fixture struct {
	Command  protocol.Command
	Policy   protocol.Policy
	Inputs   []credentialroute.Input
	Payload  []byte
	Expected protocol.Result
}

// Serve is a synchronous effect entry, normally output.Run. It must join all
// users before returning; the helper cannot interrupt arbitrary callback code.
type Serve func(context.Context, output.Endpoints, output.Implementation) int

// ServePublic is a synchronous passive entry, normally output.RunPublic.
type ServePublic func(context.Context, output.PublicEndpoints, output.Implementation) int

// CheckImplementation checks the supplied callbacks before serving can reduce
// a malformed return to unknown. Provider requests need implementation tests.
// This helper expects successful Prepare, Send and Close, then checks exact
// correlation and observable disposal. Test refusals and partial failures in the
// author module. It changes no process environment and cannot interrupt blocking
// callback or stream code. Check failures match protocol.ErrProtocol; fixture
// errors preserve validation causes. A diagnosed caller-context failure also
// matches context.Canceled or context.DeadlineExceeded. An earlier observed
// contract failure takes precedence over cancellation. Diagnostics omit private
// data and raw callback errors.
func CheckImplementation(ctx context.Context, serve Serve, impl output.Implementation, f Fixture) error {
	if ctx == nil || serve == nil {
		return fixtureError("fixture.serve", "missing context or serving function", protocol.ErrProtocol)
	}
	if err := validateFixture(impl, f); err != nil {
		return err
	}
	if err := callerContextError(ctx); err != nil {
		return err
	}
	command, err := protocol.EncodeCommand(f.Command)
	if err != nil {
		return fixtureError("fixture.command", "invalid encoding", err)
	}
	private, err := credentialroute.EncodeInputs(impl.CredentialRoute(), f.Inputs)
	if err != nil {
		return failure("fixture.inputs: invalid declared inputs")
	}
	defer clear(private)
	routeID, err := credentialroute.Identity(impl.CredentialRoute())
	if err != nil || protocol.ID(routeID) != f.Command.CredentialRouteID {
		return failure("fixture.command.credential_route_id: binding mismatch")
	}
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: impl.Identity().ProtocolID, DescriptorID: impl.Identity().DescriptorID, ArtifactContractID: protocol.ID{31}})
	if err != nil || f.Command.DescriptorID != impl.Identity().DescriptorID {
		return failure("fixture.command.descriptor_id: binding mismatch")
	}
	var control, credentials, payload bytes.Buffer
	write := func(w io.Writer, kind uint8, b []byte) error {
		return protocol.WriteFrame(w, protocol.Frame{Kind: kind, CorrelationID: f.Command.AttemptID, Body: b})
	}
	for _, row := range []struct {
		kind uint8
		b    []byte
	}{{protocol.KindHello, hello}, {protocol.KindCommand, command}, {protocol.KindPolicy, f.Policy.Data}} {
		if write(&control, row.kind, row.b) != nil {
			return failure("serving.control: frame refused")
		}
	}
	if write(&credentials, protocol.KindCredential, private) != nil {
		return failure("serving.inputs: frame refused")
	}
	defer clear(credentials.Bytes())
	kind := uint8(protocol.KindArm)
	value := f.Command.Action == protocol.ActionCreateWithValue || f.Command.Action == protocol.ActionWriteValue
	if value {
		kind = protocol.KindPayload
	}
	if write(&payload, kind, f.Payload) != nil {
		return failure("serving.payload: frame refused")
	}
	defer clear(payload.Bytes())
	saved := cloneFixture(f)
	defer func() {
		for _, input := range saved.Inputs {
			clear(input.Value)
		}
		clear(saved.Payload)
	}()
	observed := &observedImplementation{Implementation: impl, fixture: saved, caller: ctx}
	result := boundedResult{owned: make([]byte, 3*protocol.HeaderLength+protocol.HelloBytes+protocol.MaximumResultBytes)}
	defer clear(result.owned)
	status := serve(ctx, output.Endpoints{Control: &control, Credential: &credentials, Payload: &payload, Result: &result}, observed)
	if observed.failure != "" {
		return failure(observed.failure)
	}
	if result.refused {
		return failure("serving.result: exceeds output bound")
	}
	if observed.closes != observed.acquired {
		return failure("callback.close.count: prepared resource not closed")
	}
	for _, input := range observed.inputs {
		if !cleared(input.Value) {
			return failure("disposal.inputs: nonzero backing")
		}
	}
	if !cleared(observed.payload) {
		return failure("disposal.payload: nonzero backing")
	}
	if status != 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return failure("serving.completion: incomplete exchange")
	}
	if observed.prepares != 1 || observed.sends != 1 || observed.closes != 1 {
		return failure("callback.count: expected one prepare, send and close")
	}
	reader := bytes.NewReader(result.owned[:result.used])
	if b, err := protocol.ReadExpectedFrame(reader, protocol.KindHelloAck, f.Command.AttemptID, protocol.HelloBytes); err != nil || !bytes.Equal(b, hello) {
		return failure("serialized.hello_ack: binding mismatch")
	}
	if _, err := protocol.ReadExpectedFrame(reader, protocol.KindReadyForPayload, f.Command.AttemptID, 0); err != nil {
		return failure("serialized.ready: frame or correlation invalid")
	}
	b, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, f.Command.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		return failure("serialized.result: frame or correlation invalid")
	}
	got, err := protocol.DecodeResult(b)
	if err != nil || got != saved.Expected || protocol.RequireEOF(reader) != nil {
		return failure("serialized.result: exact evidence mismatch")
	}
	return callerContextError(ctx)
}
func cloneFixture(f Fixture) Fixture {
	f.Command.Target.TargetData = bytes.Clone(f.Command.Target.TargetData)
	f.Policy.Data = bytes.Clone(f.Policy.Data)
	f.Payload = bytes.Clone(f.Payload)
	inputs := make([]credentialroute.Input, len(f.Inputs))
	for i, input := range f.Inputs {
		inputs[i] = input
		inputs[i].Value = bytes.Clone(input.Value)
	}
	f.Inputs = inputs
	return f
}

type observedImplementation struct {
	output.Implementation
	fixture                 Fixture
	caller                  context.Context
	preparation             output.Preparation
	policy                  protocol.Policy
	acquired                int
	failure                 string
	prepares, sends, closes int
	inputs                  []credentialroute.Input
	payload                 []byte
}

func (p *observedImplementation) record(valid bool, field string) {
	if !valid && p.failure == "" {
		p.failure = field
	}
}

// Prepare records raw input and resource acquisition before serving can
// convert a refusal into a protocol result.
func (p *observedImplementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	p.prepares++
	p.inputs = inputs
	p.preparation, p.policy = c, policy
	p.record(p.prepares == 1, "callback.prepare.count: expected one entry")
	p.record(samePreparation(c, p.fixture.Command), "callback.prepare.command: changed input")
	p.record(samePolicy(policy, p.fixture.Policy), "callback.prepare.policy: changed input")
	p.record(sameInputs(inputs, p.fixture.Inputs), "callback.prepare.inputs: changed input")
	prepared, err := p.Implementation.Prepare(ctx, c, policy, inputs)
	cancelled := callerContextError(p.caller) != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
	p.record(err == nil || cancelled, "callback.prepare.error: unexpected refusal")
	p.record(prepared != nil || cancelled, "callback.prepare.result: missing prepared value")
	p.record(samePreparation(p.preparation, p.fixture.Command), "callback.prepare.command: mutated input")
	p.record(samePolicy(p.policy, p.fixture.Policy), "callback.prepare.policy: mutated input")
	p.record(sameInputs(inputs, p.fixture.Inputs), "callback.prepare.inputs: mutated input")
	if prepared == nil {
		return nil, err
	}
	p.acquired++
	return &observedPrepared{Prepared: prepared, owner: p}, err
}

type observedPrepared struct {
	output.Prepared
	owner *observedImplementation
}

// Send checks the raw author outcome before the runtime can reduce it to unknown.
func (p *observedPrepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	o := p.owner
	o.sends++
	o.payload = payload
	value := o.fixture.Command.Action == protocol.ActionCreateWithValue || o.fixture.Command.Action == protocol.ActionWriteValue
	o.record(o.sends == 1, "callback.send.count: expected one entry")
	o.record((payload != nil) == value && bytes.Equal(payload, o.fixture.Payload), "callback.send.payload: wrong value or presence")
	r, err := p.Prepared.Send(ctx, payload)
	o.record(err == nil, "callback.send.error: unexpected error state")
	o.record(r.Valid(), "callback.send.outcome: invalid raw outcome")
	o.record(r == expectedOutcome(o.fixture), "callback.send.outcome: expectation mismatch")
	o.record(samePreparation(o.preparation, o.fixture.Command), "callback.send.command: mutated input")
	o.record(samePolicy(o.policy, o.fixture.Policy), "callback.send.policy: mutated input")
	o.record(bytes.Equal(payload, o.fixture.Payload), "callback.send.payload: mutated input")
	o.record(sameInputs(o.inputs, o.fixture.Inputs), "callback.send.inputs: mutated input")
	return r, err
}

// Close checks borrows before the runtime clears them and records the join point.
func (p *observedPrepared) Close() error {
	o := p.owner
	o.closes++
	err := p.Prepared.Close()
	o.record(err == nil, "callback.close.error: close failed")
	o.record(o.closes == 1, "callback.close.count: expected one entry")
	o.record(sameInputs(o.inputs, o.fixture.Inputs), "callback.close.inputs: mutated input")
	o.record(samePreparation(o.preparation, o.fixture.Command), "callback.close.command: mutated input")
	o.record(samePolicy(o.policy, o.fixture.Policy), "callback.close.policy: mutated input")
	if o.sends != 0 {
		o.record(bytes.Equal(o.payload, o.fixture.Payload), "callback.close.payload: mutated input")
	}
	return err
}

type boundedResult struct {
	owned   []byte
	used    int
	refused bool
}

// Write records overflow even when a serving wrapper ignores the write error.
func (w *boundedResult) Write(b []byte) (int, error) {
	if len(b) > len(w.owned)-w.used {
		w.refused = true
		return 0, io.ErrShortWrite
	}
	copy(w.owned[w.used:], b)
	w.used += len(b)
	return len(b), nil
}
func cleared(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func samePolicy(a, b protocol.Policy) bool {
	return a.ContractID == b.ContractID && bytes.Equal(a.Data, b.Data)
}
func sameInputs(a, b []credentialroute.Input) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Present != b[i].Present || !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

func expectedOutcome(f Fixture) output.Outcome {
	r := f.Expected
	locator := ""
	if f.Command.Target.LocatorRequiresCreation {
		locator = r.ConsumerLocator
	}
	return output.Outcome{Entry: r.Entry, Class: r.Class, NormalizedStatus: r.NormalizedStatus, SafeRequestID: r.SafeRequestID, SafeResourceID: r.SafeResourceID, AssignedLocator: locator}
}
func samePreparation(a output.Preparation, b protocol.Command) bool {
	return a.Action == b.Action && sameTarget(a.Target, b.Target) && a.AttemptID == b.AttemptID && a.OwnedInstance == b.OwnedInstance && a.ConditionalToken == b.ConditionalToken && a.PayloadLengthMode == b.PayloadLengthMode && a.PayloadLength == b.PayloadLength
}

func sameTarget(a, b protocol.Target) bool {
	dataA, dataB := a.TargetData, b.TargetData
	a.TargetData, b.TargetData = nil, nil
	return reflect.DeepEqual(a, b) && bytes.Equal(dataA, dataB)
}
