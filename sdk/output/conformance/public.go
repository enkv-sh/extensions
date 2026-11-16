package conformance

import (
	"bytes"
	"context"
	"reflect"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// PublicFixture supplies independent expectations for all five passive calls.
// Settings feeds normalization; TargetRequest.Destination feeds canonical
// validation. ActionCheck and Policy feed the action check; PolicyAction and
// PolicyActionPolicy feed the required fifth exchange, including explicit
// refusal for implementations without policy support. Each Accepted flag
// states whether that callback must accept; a refused value-producing callback
// must return a zero result. All byte slices are caller-owned read-only data
// through CheckPublicImplementation return.
type PublicFixture struct {
	Settings                                                             []byte
	ExpectedDestination                                                  protocol.Destination
	TargetRequest                                                        output.TargetRequest
	ExpectedTarget                                                       protocol.Target
	ActionCheck                                                          output.ActionCheck
	Policy                                                               protocol.Policy
	PolicyAction                                                         output.PolicyActionSelection
	PolicyActionPolicy                                                   protocol.Policy
	ExpectedPolicyAction                                                 protocol.Action
	PolicyActionAccepted                                                 bool
	ExpectedBounds                                                       protocol.PayloadBounds
	NormalizeAccepted, CanonicalAccepted, TargetAccepted, ActionAccepted bool
}

// CheckPublicImplementation runs the five passive exchanges, plus the retained
// deletion-only target for deletion fixtures, and checks raw
// returns, unchanged borrowed inputs, exact result correlation and no effect
// callback entry. It grants no service or format qualification. Use a finite
// context and callbacks; cancellation cannot interrupt arbitrary code. Check
// failures match protocol.ErrProtocol; fixture errors preserve validation causes.
// A diagnosed caller-context failure also matches the applicable context sentinel.
// An earlier observed contract failure takes precedence over cancellation.
// It does not change process environment.
func CheckPublicImplementation(ctx context.Context, serve ServePublic, impl output.Implementation, f PublicFixture) error {
	if ctx == nil || serve == nil || nilImplementation(impl) || impl.Identity().ProtocolID != protocol.ProtocolID() {
		return fixtureError("fixture.implementation", "invalid passive implementation", protocol.ErrProtocol)
	}
	const deadline = 4102444800000
	normalize := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: deadline, Settings: f.Settings}
	canonical := protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: f.TargetRequest.Destination}
	interpret := protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: f.TargetRequest.Destination, EntryName: f.TargetRequest.EntryName, PayloadEncoding: f.TargetRequest.PayloadEncoding}
	a := f.ActionCheck
	action := protocol.ActionCheckRequest{Schema: 1, DeadlineUnixMillis: deadline, DomainID: repeatedID(1), DescriptorID: impl.Identity().DescriptorID, Action: a.Action, Target: a.Target, OwnedInstance: a.OwnedInstance, OwnershipMode: a.OwnershipMode, OwnedInstanceDigest: a.OwnedInstanceDigest, UncertainCreateAttemptID: a.UncertainCreateAttemptID, ExclusiveNamespaceDigest: a.ExclusiveNamespaceDigest, ConditionalTokenLength: a.ConditionalTokenLength, PayloadLengthMode: a.PayloadLengthMode, PayloadLength: a.PayloadLength, PolicyContractID: f.Policy.ContractID}
	var err error
	if f.Policy.Present() {
		action.PolicyDigest, err = protocol.PolicyDigest(action.DomainID, f.Policy)
		if err != nil {
			return fixtureError("fixture.policy", "invalid policy", err)
		}
	}
	if err := protocol.ValidateActionCheckPolicy(action, f.Policy); err != nil {
		return fixtureError("fixture.policy", "invalid action policy", err)
	}
	selection := protocol.PolicyActionRequest{Schema: 1, DeadlineUnixMillis: deadline, DomainID: f.PolicyAction.DomainID, DescriptorID: impl.Identity().DescriptorID, Target: f.PolicyAction.Target, HasPreviousPolicyDigest: f.PolicyAction.HasPreviousPolicyDigest, PreviousPolicyDigest: f.PolicyAction.PreviousPolicyDigest, PolicyContractID: f.PolicyActionPolicy.ContractID}
	selection.PolicyDigest, err = protocol.PolicyDigest(selection.DomainID, f.PolicyActionPolicy)
	if err != nil || protocol.ValidatePolicyActionPolicy(selection, f.PolicyActionPolicy) != nil {
		return fixtureError("fixture.policy_action", "invalid selection policy", protocol.ErrProtocol)
	}
	type exchange struct {
		kind, result uint8
		body         []byte
		target       protocol.Target
	}
	requests := []exchange{{kind: protocol.KindNormalizeRequest, result: protocol.KindNormalizeResult}, {kind: protocol.KindCanonicalRequest, result: protocol.KindCanonicalResult}, {kind: protocol.KindInterpretRequest, result: protocol.KindInterpretResult}, {kind: protocol.KindActionCheckRequest, result: protocol.KindActionCheckResult}, {kind: protocol.KindPolicyActionRequest, result: protocol.KindPolicyActionResult}}
	requests[0].body, err = protocol.EncodeNormalizeRequest(normalize)
	if err != nil {
		return fixtureError("fixture.settings", "invalid normalization request", err)
	}
	requests[1].body, err = protocol.EncodeCanonicalRequest(canonical)
	if err != nil {
		return fixtureError("fixture.destination", "invalid canonical request", err)
	}
	requests[2].body, err = protocol.EncodeInterpretRequest(interpret)
	if err != nil {
		return fixtureError("fixture.target_request", "invalid interpretation request", err)
	}
	requests[3].body, err = protocol.EncodeActionCheckRequest(action)
	if err != nil {
		return fixtureError("fixture.action_check", "invalid action request", err)
	}
	requests[3].target = action.Target
	requests[4].body, err = protocol.EncodePolicyActionRequest(selection)
	if err != nil {
		return fixtureError("fixture.policy_action", "invalid selection request", err)
	}
	if action.Action == protocol.ActionDeleteOwned || action.Action == protocol.ActionDeleteReservedSlot {
		retained := action
		retained.Target.Capabilities = protocol.CapabilityDeleteOwned
		if action.Action == protocol.ActionDeleteReservedSlot {
			retained.Target.Capabilities = protocol.CapabilityDeleteReservedSlot
		}
		retained.Target.CreateValueBounds, retained.Target.WriteValueBounds = protocol.PayloadBounds{}, protocol.PayloadBounds{}
		body, err := protocol.EncodeActionCheckRequest(retained)
		if err != nil {
			return fixtureError("fixture.action_check", "invalid retained deletion request", err)
		}
		requests = append(requests, exchange{kind: protocol.KindActionCheckRequest, result: protocol.KindActionCheckResult, body: body, target: retained.Target})
	}
	// Validate independent expected unions before any callback entry.
	if _, err := protocol.EncodeNormalizeResult(protocol.NormalizeResult{Schema: 1, RequestDigest: repeatedID(1), Accepted: f.NormalizeAccepted, Destination: f.ExpectedDestination}); err != nil {
		return fixtureError("fixture.expected_destination", "invalid result", err)
	}
	if err := protocol.ValidateInterpretResult(interpret, protocol.InterpretResult{Schema: 1, RequestDigest: repeatedID(1), Accepted: f.TargetAccepted, Target: f.ExpectedTarget}); err != nil {
		return fixtureError("fixture.expected_target", "invalid result", err)
	}
	if err := protocol.ValidateActionCheckResult(action, protocol.ActionCheckResult{Schema: 1, RequestDigest: repeatedID(1), Accepted: f.ActionAccepted, PayloadBounds: f.ExpectedBounds}); err != nil {
		return fixtureError("fixture.expected_bounds", "invalid result", err)
	}
	if err := protocol.ValidatePolicyActionResult(selection, protocol.PolicyActionResult{Schema: 1, RequestDigest: repeatedID(1), Accepted: f.PolicyActionAccepted, Action: f.ExpectedPolicyAction}); err != nil {
		return fixtureError("fixture.expected_policy_action", "invalid result", err)
	}
	if err := callerContextError(ctx); err != nil {
		return err
	}
	observed := &publicImplementation{Implementation: impl, fixture: f, valid: true}
	result := boundedResult{owned: make([]byte, 2*protocol.HeaderLength+protocol.HelloBytes+protocol.MaximumPublicResultBytes)}
	defer clear(result.owned)
	for i, r := range requests {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		id := repeatedID(byte(20 + i))
		hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: impl.Identity().ProtocolID, DescriptorID: impl.Identity().DescriptorID, ArtifactContractID: repeatedID(31)})
		if err != nil {
			return fixtureError("fixture.implementation.identity", "invalid identity", err)
		}
		var control bytes.Buffer
		for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CorrelationID: id, Body: hello}, {Kind: r.kind, CorrelationID: id, Body: r.body}} {
			if protocol.WriteFrame(&control, frame) != nil {
				return failure("serving.control: frame refused")
			}
		}
		var policy []byte
		switch r.kind {
		case protocol.KindActionCheckRequest:
			observed.fixture.ActionCheck.Target = r.target
			policy = f.Policy.Data
		case protocol.KindPolicyActionRequest:
			policy = f.PolicyActionPolicy.Data
		}
		if r.kind == protocol.KindActionCheckRequest || r.kind == protocol.KindPolicyActionRequest {
			if protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindPolicy, CorrelationID: id, Body: policy}) != nil {
				return failure("serving.policy: frame refused")
			}
		}
		clear(result.owned)
		result.used, result.refused = 0, false
		code := serve(ctx, output.PublicEndpoints{Control: &control, Result: &result}, observed)
		if !observed.valid || observed.effects != 0 {
			stage := "action"
			switch r.kind {
			case protocol.KindNormalizeRequest:
				stage = "normalize"
			case protocol.KindCanonicalRequest:
				stage = "canonical"
			case protocol.KindInterpretRequest:
				stage = "target"
			case protocol.KindPolicyActionRequest:
				stage = "policy_action"
			}
			return failure("callback." + stage + ": wrong input or raw outcome")
		}
		if result.refused {
			return failure("serving.result: exceeds output bound")
		}
		if code != 0 {
			if err := callerContextError(ctx); err != nil {
				return err
			}
			return failure("serving.passive: incomplete exchange")
		}
		reader := bytes.NewReader(result.owned[:result.used])
		ack, err := protocol.ReadExpectedFrame(reader, protocol.KindHelloAck, id, protocol.HelloBytes)
		if err != nil || !bytes.Equal(ack, hello) {
			return failure("serving.hello_ack: correlation mismatch")
		}
		body, err := protocol.ReadExpectedFrame(reader, r.result, id, protocol.MaximumPublicResultBytes)
		if err != nil || protocol.RequireEOF(reader) != nil {
			return failure("serving.result: frame or EOF invalid")
		}
		digest, err := protocol.PublicRequestDigest(id, r.kind, r.body, policy)
		if err != nil {
			return failure("serving.request_digest: invalid request")
		}
		switch r.kind {
		case protocol.KindNormalizeRequest:
			got, e := protocol.DecodeNormalizeResult(body)
			if e != nil || got.RequestDigest != digest || got.Accepted != f.NormalizeAccepted || !sameDestination(got.Destination, f.ExpectedDestination) {
				return failure("serialized.normalize: unexpected result")
			}
		case protocol.KindCanonicalRequest:
			got, e := protocol.DecodeCanonicalResult(body)
			if e != nil || got.RequestDigest != digest || got.Accepted != f.CanonicalAccepted {
				return failure("serialized.canonical: unexpected result")
			}
		case protocol.KindInterpretRequest:
			got, e := protocol.DecodeInterpretResult(body)
			if e != nil || got.RequestDigest != digest || got.Accepted != f.TargetAccepted || !sameTarget(got.Target, f.ExpectedTarget) {
				return failure("serialized.target: unexpected result")
			}
		case protocol.KindActionCheckRequest:
			got, e := protocol.DecodeActionCheckResult(body)
			if e != nil || got.RequestDigest != digest || got.Accepted != f.ActionAccepted || got.PayloadBounds != f.ExpectedBounds {
				return failure("serialized.action: unexpected result")
			}
		case protocol.KindPolicyActionRequest:
			got, e := protocol.DecodePolicyActionResult(body)
			if e != nil || protocol.ValidatePolicyActionResponse(id, selection, f.PolicyActionPolicy, got) != nil || got.Accepted != f.PolicyActionAccepted || got.Action != f.ExpectedPolicyAction {
				return failure("serialized.policy_action: unexpected result")
			}
		}
	}
	if !observed.valid || observed.calls != [5]int{1, 1, 1, len(requests) - 4, 1} || observed.effects != 0 {
		return failure("callback.passive: wrong input or raw outcome")
	}
	return callerContextError(ctx)
}
func sameDestination(a, b protocol.Destination) bool {
	return a.ConfigContractID == b.ConfigContractID && a.ServiceContractID == b.ServiceContractID && a.Capabilities == b.Capabilities && bytes.Equal(a.CanonicalSettings, b.CanonicalSettings) && samePolicy(a.Policy, b.Policy)
}

type publicImplementation struct {
	output.Implementation
	fixture PublicFixture
	valid   bool
	calls   [5]int
	effects int
}

// NormalizeDestination checks raw semantics and unchanged borrowed settings.
func (p *publicImplementation) NormalizeDestination(ctx context.Context, b []byte) (protocol.Destination, error) {
	p.calls[0]++
	p.valid = p.valid && bytes.Equal(b, p.fixture.Settings)
	got, err := p.Implementation.NormalizeDestination(ctx, b)
	p.valid = p.valid && bytes.Equal(b, p.fixture.Settings) && (err == nil) == p.fixture.NormalizeAccepted
	if err == nil {
		p.valid = p.valid && got.Valid() && sameDestination(got, p.fixture.ExpectedDestination)
	} else {
		p.valid = p.valid && sameDestination(got, protocol.Destination{})
	}
	return got, err
}

// ValidateCanonical checks the exact retained destination before and after use.
func (p *publicImplementation) ValidateCanonical(ctx context.Context, d protocol.Destination) error {
	p.calls[1]++
	p.valid = p.valid && sameDestination(d, p.fixture.TargetRequest.Destination)
	err := p.Implementation.ValidateCanonical(ctx, d)
	p.valid = p.valid && sameDestination(d, p.fixture.TargetRequest.Destination) && (err == nil) == p.fixture.CanonicalAccepted
	return err
}

// InterpretTarget checks independently expected target facts before serialization.
func (p *publicImplementation) InterpretTarget(ctx context.Context, r output.TargetRequest) (protocol.Target, error) {
	p.calls[2]++
	same := func() bool {
		return sameDestination(r.Destination, p.fixture.TargetRequest.Destination) && r.EntryName == p.fixture.TargetRequest.EntryName && r.PayloadEncoding == p.fixture.TargetRequest.PayloadEncoding
	}
	p.valid = p.valid && same()
	got, err := p.Implementation.InterpretTarget(ctx, r)
	p.valid = p.valid && same() && (err == nil) == p.fixture.TargetAccepted
	if err == nil {
		p.valid = p.valid && got.Valid() && sameTarget(got, p.fixture.ExpectedTarget)
	} else {
		p.valid = p.valid && sameTarget(got, protocol.Target{})
	}
	return got, err
}

// CheckAction checks exact public facts, policy and independently expected bounds.
func (p *publicImplementation) CheckAction(ctx context.Context, r output.ActionCheck, policy protocol.Policy) (protocol.PayloadBounds, error) {
	p.calls[3]++
	same := func() bool {
		a, b := r, p.fixture.ActionCheck
		a.Target, b.Target = protocol.Target{}, protocol.Target{}
		return reflect.DeepEqual(a, b) && sameTarget(r.Target, p.fixture.ActionCheck.Target) && samePolicy(policy, p.fixture.Policy)
	}
	p.valid = p.valid && same()
	got, err := p.Implementation.CheckAction(ctx, r, policy)
	p.valid = p.valid && same() && (err == nil) == p.fixture.ActionAccepted
	if err == nil {
		p.valid = p.valid && got == p.fixture.ExpectedBounds
	} else {
		p.valid = p.valid && got == (protocol.PayloadBounds{})
	}
	return got, err
}

// Prepare records forbidden effect entry during a passive check.
func (p *publicImplementation) Prepare(context.Context, output.Preparation, protocol.Policy, []credentialroute.Input) (output.Prepared, error) {
	p.effects++
	return nil, protocol.ErrProtocol
}

// SelectPolicyAction checks exact public borrows and the raw closed action return.
func (p *publicImplementation) SelectPolicyAction(ctx context.Context, r output.PolicyActionSelection, policy protocol.Policy) (protocol.Action, error) {
	p.calls[4]++
	same := func() bool {
		a, b := r, p.fixture.PolicyAction
		a.Target, b.Target = protocol.Target{}, protocol.Target{}
		return reflect.DeepEqual(a, b) && sameTarget(r.Target, p.fixture.PolicyAction.Target) && samePolicy(policy, p.fixture.PolicyActionPolicy)
	}
	p.valid = p.valid && same()
	got, err := p.Implementation.SelectPolicyAction(ctx, r, policy)
	p.valid = p.valid && same() && (err == nil) == p.fixture.PolicyActionAccepted
	if err == nil {
		p.valid = p.valid && got == p.fixture.ExpectedPolicyAction
	} else {
		p.valid = p.valid && got == 0
	}
	return got, err
}
