// Package conformance checks public serving and author callback behavior.
package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// Serve is a synchronous generator serving function, normally generator.Run.
// It must return after all callback and stream users have joined.
type Serve func(context.Context, io.Reader, io.Reader, io.Writer, io.Writer, generator.Implementation) int

// Fixture is the lower-level raw command fixture for an effect exchange.
// Prefer NewFixture to supply synthetic host correlation. Command and Inputs
// describe the exact invocation; ExpectedFacts and ExpectedValue must come from
// independent service expectations. Slices remain caller-owned and read-only
// until CheckImplementation returns. Clear caller-owned private data afterward.
type Fixture struct {
	Command         protocol.Command
	Inputs          []credentialroute.Input
	ExpectedFacts   protocol.SafeFacts
	ExpectedValue   []byte
	ExpectedFailure bool
	// CheckValue substitutes a read-only value-property check for ExpectedValue.
	// It follows Expectation.CheckValue's lifetime and successful-create rules.
	CheckValue func([]byte) error
}

// CheckImplementation invokes the supplied implementation and checks its raw
// callback return before SDK validation, then the complete exchange and disposal.
// Expected facts/value must be independently derived synthetic test data.
// The check is synchronous and cannot interrupt arbitrary callback or stream code;
// keep both finite. It does not change the environment or establish service
// request correctness. Check failures match protocol.ErrProtocol; fixture errors
// preserve validation causes. A diagnosed caller-context failure also matches
// context.Canceled or context.DeadlineExceeded with errors.Is. An earlier observed
// contract failure takes precedence over cancellation. Diagnostics exclude private
// values and raw callback error text.
func CheckImplementation(ctx context.Context, serve Serve, implementation generator.Implementation, fixture Fixture) error {
	fail := func(name string) error {
		return fmt.Errorf("generator author check: %s: %w", name, protocol.ErrProtocol)
	}
	if err := validateFixture(ctx, implementation, fixture); err != nil {
		return err
	}
	if serve == nil {
		return fixtureError("fixture.serve", "missing serving function", protocol.ErrProtocol)
	}
	if err := callerContextError(ctx); err != nil {
		return err
	}
	command, err := protocol.EncodeCommand(fixture.Command)
	if err != nil {
		return fixtureError("fixture.command", "invalid encoding", err)
	}
	private, err := credentialroute.EncodeInputs(implementation.CredentialRoute(), fixture.Inputs)
	if err != nil {
		return fixtureError("fixture.inputs", "invalid declared inputs", err)
	}
	defer clear(private)
	var control, environment bytes.Buffer
	id := fixture.Command.AttemptID
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: repeatedID(90)})
	if err != nil {
		return fail("fixture.implementation.identity: invalid encoding")
	}
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CommandID: id, Body: hello}, {Kind: protocol.KindCommand, CommandID: id, Body: command}} {
		if protocol.WriteFrame(&control, frame) != nil {
			return fail("serving.control: frame refused")
		}
	}
	if protocol.WriteFrame(&environment, protocol.Frame{Kind: protocol.KindEnvironment, CommandID: id, Body: private}) != nil {
		return fail("serving.inputs: frame refused")
	}
	defer clear(environment.Bytes())
	result := boundedBuffer{body: make([]byte, protocol.HeaderLength+protocol.MaximumResultBody)}
	status := boundedBuffer{body: make([]byte, 2*protocol.HeaderLength+protocol.HelloBodyLength+protocol.StatusBodyLength)}
	defer clear(result.body)
	calls := 0
	callbackFailure := ""
	record := func(valid bool, failure string) {
		if !valid && callbackFailure == "" {
			callbackFailure = failure
		}
	}
	inputFailure := ""
	var borrowed, returned [][]byte
	var callbackContext context.Context
	var capture []byte
	defer func() { clear(capture[:cap(capture)]) }()
	valueFailure := ""
	observe := func(ctx context.Context, inv generator.Invocation, facts protocol.SafeFacts, value []byte, callbackErr error) {
		calls++
		callbackContext = ctx
		deadline, bounded := ctx.Deadline()
		if inputFailure == "" {
			switch {
			case !commandsEqual(inv.Command, fixture.Command):
				inputFailure = "callback.command: changed input"
			case !inputsEqual(inv.Inputs, fixture.Inputs):
				inputFailure = "callback.inputs: changed input"
			}
		}
		record(calls == 1, "callback.count: expected one entry")
		record(bounded && deadline.UnixMilli() <= int64(inv.Command.DeadlineUnixMillis), "callback.context: missing or extended deadline")
		record(factsEqual(facts, fixture.ExpectedFacts), "callback.facts: expectation mismatch")
		record((callbackErr != nil) == fixture.ExpectedFailure, "callback.error: unexpected error state")
		if !fixture.ExpectedFailure && protocol.ValidateResult(fixture.Command, fixture.Command.NewResult(facts, value)) != nil {
			record(false, "callback.result: invalid facts or value relation")
		}
		if fixture.CheckValue == nil {
			record(bytes.Equal(value, fixture.ExpectedValue), "callback.value: exact bytes mismatch")
		} else if len(value) > protocol.MaximumSecretLength {
			valueFailure = "callback.value: exceeds limit"
		} else if calls == 1 {
			capture = make([]byte, len(value))
			copy(capture, value)
			digest := sha256.Sum256(capture)
			propertyErr := fixture.CheckValue(capture)
			if sha256.Sum256(capture) != digest || sha256.Sum256(value) != digest {
				valueFailure = "callback.value: property mutated borrowed bytes"
			} else if propertyErr != nil {
				valueFailure = "callback.value: property refused"
			}
		}
		borrowed = append(borrowed, inv.Command.Intent, inv.Command.OriginalFacts)
		for _, input := range inv.Inputs {
			borrowed = append(borrowed, input.Value)
			record(cap(input.Value) == len(input.Value), "callback.inputs.value: invalid borrowed capacity")
		}
		for _, out := range [][]byte{value[:cap(value)], facts.Target[:cap(facts.Target)], facts.ResourceData[:cap(facts.ResourceData)], facts.ProviderFacts[:cap(facts.ProviderFacts)]} {
			returned = append(returned, out)
			for _, input := range borrowed {
				record(!overlap(out, input), "callback.result: aliases borrowed input")
			}
		}
	}
	originalCreate, originalRetire := implementation.Create, implementation.Retire
	implementation.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
		beforeCommand := commandsEqual(inv.Command, fixture.Command)
		beforeInputs := inputsEqual(inv.Inputs, fixture.Inputs)
		f, v, e := originalCreate(ctx, inv)
		if !beforeCommand {
			inputFailure = "callback.command: changed input"
		}
		if !beforeInputs {
			inputFailure = "callback.inputs: changed input"
		}
		observe(ctx, inv, f, v, e)
		return f, v, e
	}
	if originalRetire != nil {
		implementation.Retire = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, error) {
			beforeCommand := commandsEqual(inv.Command, fixture.Command)
			beforeInputs := inputsEqual(inv.Inputs, fixture.Inputs)
			f, e := originalRetire(ctx, inv)
			if !beforeCommand {
				inputFailure = "callback.command: changed input"
			}
			if !beforeInputs {
				inputFailure = "callback.inputs: changed input"
			}
			observe(ctx, inv, f, nil, e)
			return f, e
		}
	}
	code := serve(ctx, &control, &environment, &result, &status, implementation)
	if valueFailure != "" {
		return fail(valueFailure)
	}
	if inputFailure != "" {
		return fail(inputFailure)
	}
	if callbackFailure != "" {
		return fail(callbackFailure)
	}
	if calls > 1 {
		return fail("callback.count: expected one entry")
	}
	if calls == 1 && (callbackContext == nil || callbackContext.Err() == nil) {
		return fail("callback.context: not cancelled after return")
	}
	if result.refused {
		return fail("serving.result: exceeds output bound")
	}
	if status.refused {
		return fail("serving.status: exceeds output bound")
	}
	for _, body := range append(borrowed, returned...) {
		if !allZero(body) {
			return fail("disposal.borrowed_or_returned: nonzero backing")
		}
	}
	if calls == 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return fail("callback.count: expected one entry")
	}
	statusReader := bytes.NewReader(status.body[:status.used])
	ack, err := protocol.ReadExpectedFrame(statusReader, protocol.KindHelloAck, id, 96)
	if err != nil || !bytes.Equal(ack, hello) {
		return fail("serialized.hello_ack: binding mismatch")
	}
	terminal, err := protocol.ReadExpectedFrame(statusReader, protocol.KindStatus, id, 3)
	if err != nil {
		return fail("serialized.status: frame or correlation invalid")
	}
	state, err := protocol.DecodeStatus(terminal)
	if err != nil || protocol.RequireEOF(statusReader) != nil {
		return fail("serialized.status: invalid encoding or EOF")
	}
	if fixture.ExpectedFailure {
		if code == 0 || result.used != 0 || state.Category == protocol.StatusOK {
			return fail("serialized.failure: unexpected result or status")
		}
		return callerContextError(ctx)
	}
	if code != 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
	}
	if code != 0 || state != (protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}) {
		return fail("serving.result: unexpected status")
	}
	reader := bytes.NewReader(result.body[:result.used])
	body, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, id, protocol.MaximumResultBody)
	if err != nil {
		return fail("serialized.result: frame or correlation invalid")
	}
	defer clear(body)
	got, err := protocol.DecodeResult(body)
	expectedValue := fixture.ExpectedValue
	if fixture.CheckValue != nil {
		expectedValue = capture
	}
	if err != nil || protocol.RequireEOF(reader) != nil || got.AttemptID != fixture.Command.AttemptID || got.ResultID != fixture.Command.ResultID || got.ResultContractID != fixture.Command.ResultContractID || got.ExecutorID != fixture.Command.ExecutorID || !factsEqual(got.SafeFacts, fixture.ExpectedFacts) || !bytes.Equal(got.Value, expectedValue) {
		return fail("serialized.result: exact facts or value mismatch")
	}
	return callerContextError(ctx)
}

func commandsEqual(a, b protocol.Command) bool {
	if !bytes.Equal(a.Intent, b.Intent) || !bytes.Equal(a.OriginalFacts, b.OriginalFacts) {
		return false
	}
	a.Intent, b.Intent = nil, nil
	a.OriginalFacts, b.OriginalFacts = nil, nil
	return reflect.DeepEqual(a, b)
}

func inputsEqual(a, b []credentialroute.Input) bool {
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

func overlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for i := range a {
		if &a[i] == &b[0] {
			return true
		}
	}
	for i := range b {
		if &b[i] == &a[0] {
			return true
		}
	}
	return false
}
func allZero(body []byte) bool {
	for _, b := range body {
		if b != 0 {
			return false
		}
	}
	return true
}

type boundedBuffer struct {
	body    []byte
	used    int
	refused bool
}

// Write records overflow even if a serving wrapper discards the returned error.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > len(b.body)-b.used {
		b.refused = true
		return 0, io.ErrShortWrite
	}
	n := copy(b.body[b.used:], p)
	b.used += n
	return n, nil
}

func factsEqual(a, b protocol.SafeFacts) bool {
	return a.Schema == b.Schema && a.Action == b.Action && a.LifecycleMode == b.LifecycleMode && a.Disposition == b.Disposition && a.Reason == b.Reason && a.RequestDigest == b.RequestDigest && a.IntentDigest == b.IntentDigest && a.ResourceContractID == b.ResourceContractID && bytes.Equal(a.Target, b.Target) && bytes.Equal(a.ResourceData, b.ResourceData) && bytes.Equal(a.ProviderFacts, b.ProviderFacts)
}
