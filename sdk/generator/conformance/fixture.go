package conformance

import (
	"context"
	"errors"
	"fmt"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// Request contains author-owned effect inputs for NewFixture. Action selects
// create or retire; Intent is already canonical. OriginalFacts supplies the exact
// managed resource for retirement. Inputs contains declared synthetic private data.
type Request struct {
	Action        uint8
	Intent        protocol.Intent
	OriginalFacts *protocol.SafeFacts
	Inputs        []credentialroute.Input
}

// Expectation contains independently derived service facts and either exact
// Value bytes or CheckValue. Failure expects a callback error; it is not proof of
// no effect. All slices remain owned by the caller and must stay stable during
// the check.
type Expectation struct {
	Disposition, Reason                 uint8
	Target, ResourceData, ProviderFacts []byte
	Value                               []byte
	// CheckValue checks a random value's independent property instead of exact
	// Value bytes. It borrows a bounded capture until return: do not change,
	// retain or log it. It is allowed only for successful complete creation,
	// with Value nil. The serialized value must still equal that capture.
	CheckValue func([]byte) error
	Failure    bool
}

func fixtureError(field, reason string, cause error) error {
	return fmt.Errorf("generator fixture: %s: %s: %w", field, reason, cause)
}

// NewFixture adds synthetic host correlation to semantic author inputs and
// validates the resulting fixture without invoking implementation callbacks.
// It encodes Intent and optional OriginalFacts into fresh command buffers. The
// returned Inputs, populated ExpectedFacts byte fields and ExpectedValue retain
// the corresponding caller slices without copying. Keep those slices unchanged
// until checks return and clear caller-owned private data afterward. Success
// establishes neither service truth nor authority. Errors preserve validation causes.
func NewFixture(implementation generator.Implementation, request Request, expected Expectation) (Fixture, error) {
	intent, err := protocol.EncodeIntent(request.Intent)
	if err != nil {
		return Fixture{}, fixtureError("fixture.intent", "invalid encoding", err)
	}
	if request.Intent.ConfigContractID != implementation.ConfigContractID() {
		return Fixture{}, fixtureError("fixture.intent.config_contract_id", "binding mismatch", protocol.ErrProtocol)
	}
	digest, err := protocol.IntentDigest(intent)
	if err != nil {
		return Fixture{}, fixtureError("fixture.intent", "invalid encoding", err)
	}
	routeID, err := credentialroute.Identity(implementation.CredentialRoute())
	if err != nil {
		return Fixture{}, fixtureError("fixture.inputs", "invalid route", err)
	}
	command := protocol.Command{Schema: protocol.Schema, Action: request.Action, DeadlineUnixMillis: 4102444800000, DomainID: repeatedID(1), OperationID: repeatedID(2), RequestIdentityDigest: repeatedID(3), PlanGraphID: repeatedID(4), LineageID: repeatedID(5), AttemptID: repeatedID(6), TransmissionID: repeatedID(7), ResultID: repeatedID(8), ResultContractID: repeatedID(9), DescriptorID: implementation.Identity().DescriptorID, ExecutorID: repeatedID(10), RequestDigest: repeatedID(11), IntentDigest: digest, ResourceContractID: request.Intent.ResourceContractID, CredentialRouteID: protocol.ID(routeID), LifecycleMode: request.Intent.LifecycleMode, Intent: intent}
	if request.OriginalFacts != nil {
		command.OriginalFacts, err = protocol.EncodeSafeFacts(*request.OriginalFacts)
		if err != nil {
			return Fixture{}, fixtureError("fixture.original_facts", "invalid encoding", err)
		}
	}
	facts := command.NewFacts(expected.Disposition, expected.Reason)
	facts.Target, facts.ResourceData, facts.ProviderFacts = expected.Target, expected.ResourceData, expected.ProviderFacts
	if expected.Failure && expected.Disposition == 0 {
		if expected.Reason != 0 || len(expected.Target) != 0 || len(expected.ResourceData) != 0 || len(expected.ProviderFacts) != 0 || len(expected.Value) != 0 {
			return Fixture{}, fixtureError("fixture.expected_result", "invalid empty failure expectation", protocol.ErrProtocol)
		}
		facts = protocol.SafeFacts{}
	}
	fixture := Fixture{Command: command, Inputs: request.Inputs, ExpectedFacts: facts, ExpectedValue: expected.Value, CheckValue: expected.CheckValue, ExpectedFailure: expected.Failure}
	if err := validateFixture(context.Background(), implementation, fixture); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}

func validateFixture(ctx context.Context, implementation generator.Implementation, f Fixture) error {
	if ctx == nil || implementation.Create == nil || implementation.Normalize == nil || implementation.ValidateCanonical == nil || implementation.Identity().ProtocolID != protocol.ProtocolID() {
		return fixtureError("fixture.implementation", "invalid callbacks or identity", protocol.ErrProtocol)
	}
	if err := protocol.ValidateCommand(f.Command); err != nil {
		return fixtureError("fixture.command", "invalid structure", err)
	}
	if f.Command.DescriptorID != implementation.Identity().DescriptorID {
		return fixtureError("fixture.command.descriptor_id", "binding mismatch", protocol.ErrProtocol)
	}
	route, err := credentialroute.Identity(implementation.CredentialRoute())
	if err != nil {
		return fixtureError("fixture.inputs", "invalid route", err)
	}
	if f.Command.CredentialRouteID != protocol.ID(route) {
		return fixtureError("fixture.command.credential_route_id", "binding mismatch", protocol.ErrProtocol)
	}
	intent, err := protocol.DecodeIntent(f.Command.Intent)
	if err != nil {
		return fixtureError("fixture.command.intent", "invalid encoding", err)
	}
	if intent.ConfigContractID != implementation.ConfigContractID() {
		return fixtureError("fixture.command.intent.config_contract_id", "binding mismatch", protocol.ErrProtocol)
	}
	if f.Command.LifecycleMode == protocol.LifecycleManaged && (implementation.Retire == nil || implementation.CheckRetirementCompatibility == nil) {
		return fixtureError("fixture.implementation.retire", "missing managed callback", protocol.ErrProtocol)
	}
	if f.CheckValue != nil && (f.ExpectedValue != nil || f.ExpectedFailure || f.ExpectedFacts.Disposition != protocol.DispositionCompleteCreate) {
		return fixtureError("fixture.expected_value", "conflicting property expectation", protocol.ErrProtocol)
	}
	value := f.ExpectedValue
	if f.CheckValue != nil {
		value = []byte{1}
	}
	if !f.ExpectedFailure || !factsEqual(f.ExpectedFacts, protocol.SafeFacts{}) || len(value) != 0 {
		if err := protocol.ValidateResult(f.Command, f.Command.NewResult(f.ExpectedFacts, value)); err != nil {
			return fixtureError("fixture.expected_result", "invalid result", err)
		}
	}
	private, err := credentialroute.EncodeInputs(implementation.CredentialRoute(), f.Inputs)
	clear(private[:cap(private)])
	if err != nil {
		return fixtureError("fixture.inputs", "invalid declared inputs", err)
	}
	return nil
}

func callerContextError(ctx context.Context) error {
	cause := ctx.Err()
	if cause == nil {
		return nil
	}
	reason := "cancelled"
	sentinel := error(context.Canceled)
	if errors.Is(cause, context.DeadlineExceeded) {
		reason = "deadline exceeded"
		sentinel = context.DeadlineExceeded
	}
	return fmt.Errorf("generator author check: caller.context: %s: %w: %w", reason, protocol.ErrProtocol, sentinel)
}
