package conformance

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// Request holds semantic author inputs for NewFixture. Preparation describes
// the exact action, Policy its opaque policy and Inputs synthetic credentials.
// Payload is the prepared value bytes, or nil for a metadata action. The two
// deletion digests supply retained uncertain-create/exclusive-namespace evidence.
type Request struct {
	Preparation                                        output.Preparation
	Policy                                             protocol.Policy
	Inputs                                             []credentialroute.Input
	Payload                                            []byte
	UncertainCreateAttemptID, ExclusiveNamespaceDigest protocol.ID
}

func fixtureError(field, reason string, cause error) error {
	return fmt.Errorf("output fixture: %s: %s: %w", field, reason, cause)
}
func nilImplementation(impl output.Implementation) bool {
	if impl == nil {
		return true
	}
	v := reflect.ValueOf(impl)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// NewFixture supplies synthetic host correlation and validates author inputs
// against the checked implementation binding and independent expected outcome.
// A zero Preparation.AttemptID selects a synthetic attempt; an explicit ID is
// preserved. The function invokes no callbacks. The returned target data, policy
// data, Inputs and Payload retain the corresponding caller slices without copying.
// Keep those slices stable through checks and clear caller-owned private data
// afterward. Errors preserve validation causes; success grants neither authority
// nor service proof.
func NewFixture(impl output.Implementation, request Request, expected output.Outcome) (Fixture, error) {
	if nilImplementation(impl) {
		return Fixture{}, fixtureError("fixture.implementation", "missing implementation", protocol.ErrProtocol)
	}
	p := request.Preparation
	routeID, err := credentialroute.Identity(impl.CredentialRoute())
	if err != nil {
		return Fixture{}, fixtureError("fixture.inputs", "invalid route", err)
	}
	attempt := p.AttemptID
	if attempt.IsZero() {
		attempt = repeatedID(3)
	}
	c := protocol.Command{Schema: 1, Action: p.Action, DomainID: repeatedID(1), OperationID: repeatedID(2), AttemptID: attempt, CoordinateID: repeatedID(4), ProjectionCommitment: repeatedID(5), DispatchContextDigest: repeatedID(6), RequestContractDigest: repeatedID(7), ResponseContractDigest: repeatedID(8), DescriptorID: impl.Identity().DescriptorID, CredentialRouteID: protocol.ID(routeID), BindingIncarnationID: repeatedID(11), EntryIncarnationID: repeatedID(12), TargetRowDigest: repeatedID(13), DeadlineUnixMillis: 4102444800000, BindingDestinationID: "author-output", Target: p.Target, OwnedInstance: p.OwnedInstance, ConditionalToken: p.ConditionalToken, PayloadLengthMode: p.PayloadLengthMode, PayloadLength: p.PayloadLength, UncertainCreateAttemptID: request.UncertainCreateAttemptID, ExclusiveNamespaceDigest: request.ExclusiveNamespaceDigest, PolicyContractID: request.Policy.ContractID}
	if p.Action == protocol.ActionCreateWithValue || p.Action == protocol.ActionWriteValue {
		c.ValueBasisDigest = repeatedID(14)
	}
	if p.OwnedInstance != "" {
		c.OwnedBirthAttemptID, c.BirthTargetRowDigest = repeatedID(15), repeatedID(16)
	}
	if request.Policy.Present() {
		c.PolicyDigest, err = protocol.PolicyDigest(c.DomainID, request.Policy)
		if err != nil {
			return Fixture{}, fixtureError("fixture.policy", "invalid policy", err)
		}
	}
	if !expected.Valid() {
		return Fixture{}, fixtureError("fixture.expected", "invalid outcome", protocol.ErrProtocol)
	}
	r := c.NewResult()
	r.Entry, r.Class, r.NormalizedStatus, r.SafeRequestID, r.SafeResourceID = expected.Entry, expected.Class, expected.NormalizedStatus, expected.SafeRequestID, expected.SafeResourceID
	if expected.Class == protocol.ClassAcknowledged && (c.Action == protocol.ActionCreateEmpty || c.Action == protocol.ActionCreateWithValue) {
		r.ConsumerLocator = c.Target.ConsumerLocator
		if c.Target.LocatorRequiresCreation {
			r.ConsumerLocator = expected.AssignedLocator
		} else if expected.AssignedLocator != "" {
			return Fixture{}, fixtureError("fixture.expected.assigned_locator", "unexpected static locator", protocol.ErrProtocol)
		}
	} else if expected.AssignedLocator != "" {
		return Fixture{}, fixtureError("fixture.expected.assigned_locator", "unexpected noncreate locator", protocol.ErrProtocol)
	}
	f := Fixture{Command: c, Policy: request.Policy, Inputs: request.Inputs, Payload: request.Payload, Expected: r}
	if err := validateFixture(impl, f); err != nil {
		return Fixture{}, err
	}
	return f, nil
}
func validateFixture(impl output.Implementation, f Fixture) error {
	if nilImplementation(impl) || impl.Identity().ProtocolID != protocol.ProtocolID() {
		return fixtureError("fixture.implementation", "invalid identity", protocol.ErrProtocol)
	}
	if !f.Command.Valid() {
		return fixtureError("fixture.command", "invalid structure", protocol.ErrProtocol)
	}
	if f.Command.DescriptorID != impl.Identity().DescriptorID {
		return fixtureError("fixture.command.descriptor_id", "binding mismatch", protocol.ErrProtocol)
	}
	route, err := credentialroute.Identity(impl.CredentialRoute())
	if err != nil {
		return fixtureError("fixture.inputs", "invalid route", err)
	}
	if f.Command.CredentialRouteID != protocol.ID(route) {
		return fixtureError("fixture.command.credential_route_id", "binding mismatch", protocol.ErrProtocol)
	}
	if err := protocol.ValidatePolicy(f.Command, f.Policy); err != nil {
		return fixtureError("fixture.policy", "binding mismatch", err)
	}
	if len(f.Payload) != int(f.Command.PayloadLength) {
		return fixtureError("fixture.payload", "length mismatch", protocol.ErrProtocol)
	}
	if err := protocol.ValidateResult(f.Command, f.Expected); err != nil {
		return fixtureError("fixture.expected", "invalid result", err)
	}
	private, err := credentialroute.EncodeInputs(impl.CredentialRoute(), f.Inputs)
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
	return fmt.Errorf("output author check: caller.context: %s: %w: %w", reason, protocol.ErrProtocol, sentinel)
}
