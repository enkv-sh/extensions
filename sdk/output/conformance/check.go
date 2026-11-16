// Package conformance checks the public output serving and author boundaries.
package conformance

import (
	"bytes"
	"context"
	"fmt"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

func failure(text string) error {
	return fmt.Errorf("output conformance: %s: %w", text, protocol.ErrProtocol)
}
func repeatedID(v byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = v
	}
	return id
}

type synthetic struct {
	output.Binding
	command                      protocol.Command
	policy                       protocol.Policy
	calls                        int
	valid                        bool
	callbackError, invalidResult bool
}

func newImplementation() (*synthetic, error) {
	routeBytes, err := credentialroute.Encode(credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"TOKEN"}})
	if err != nil {
		return nil, err
	}
	descriptor, err := artifact.EncodeDescriptor(artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "synthetic-output", Role: "output", Version: "1.0.0", Wire: output.DescriptorWire(), Output: &artifact.OutputDeclaration{ConfigContractID: "private-config", CredentialRoute: routeBytes}})
	if err != nil {
		return nil, err
	}
	binding, err := output.Bind(descriptor, "private-config")
	if err != nil {
		return nil, err
	}
	p := &synthetic{Binding: binding, valid: true}
	route, _ := credentialroute.Identity(p.CredentialRoute())
	p.command = protocol.Command{Schema: 1, Action: protocol.ActionCreateWithValue, DomainID: repeatedID(1), OperationID: repeatedID(2), AttemptID: repeatedID(3), CoordinateID: repeatedID(4), ProjectionCommitment: repeatedID(5), DispatchContextDigest: repeatedID(6), RequestContractDigest: repeatedID(7), ResponseContractDigest: repeatedID(8), DescriptorID: binding.Identity().DescriptorID, CredentialRouteID: protocol.ID(route), BindingIncarnationID: repeatedID(11), EntryIncarnationID: repeatedID(12), TargetRowDigest: repeatedID(13), ValueBasisDigest: repeatedID(14), DeadlineUnixMillis: 4102444800000, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5, BindingDestinationID: "private-output", Target: protocol.Target{ServiceContractID: "private-service", TargetContractID: "private-target", CanonicalTarget: "service/account/key", ConsumerLocator: "service/account/key", PayloadEncoding: protocol.EncodingRaw, Capabilities: (protocol.CapabilityCreateWithValue | protocol.CapabilityCreateEmpty), CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}}
	return p, nil
}

// NormalizeDestination accepts unknown plugin-owned settings without a host catalog.
func (*synthetic) NormalizeDestination(_ context.Context, settings []byte) (protocol.Destination, error) {
	return protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: bytes.Clone(settings), Capabilities: protocol.CapabilityCreateWithValue}, nil
}

// ValidateCanonical accepts the synthetic fixture's public retained facts.
func (*synthetic) ValidateCanonical(context.Context, protocol.Destination) error { return nil }

// InterpretTarget refuses: this synthetic wrapper fixture has no target grammar.
func (*synthetic) InterpretTarget(context.Context, output.TargetRequest) (protocol.Target, error) {
	return protocol.Target{}, protocol.ErrProtocol
}

// CheckAction supplies only the bounds needed by this synthetic action fixture.
func (*synthetic) CheckAction(_ context.Context, r output.ActionCheck, _ protocol.Policy) (protocol.PayloadBounds, error) {
	if r.Action == protocol.ActionCreateWithValue {
		return protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, nil
	}
	return protocol.PayloadBounds{}, nil
}

// Prepare records private borrows so the check can observe disposal after Close.
func (p *synthetic) Prepare(_ context.Context, c output.Preparation, _ protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	p.valid = p.valid && len(inputs) == 1 && bytes.Equal(inputs[0].Value, []byte("credential"))
	return p, nil
}

// Send supplies the selected synthetic raw outcome without a provider request.
func (p *synthetic) Send(_ context.Context, payload []byte) (output.Outcome, error) {
	p.calls++
	r := output.Outcome{}
	r.Entry, r.Class, r.NormalizedStatus, r.SafeResourceID = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 201, "synthetic-resource"
	if p.invalidResult {
		r.Class = protocol.OutcomeClass(99)
	}
	if p.callbackError {
		return r, fmt.Errorf("private callback error")
	}
	return r, nil
}

// Close owns no independent resources; the serving layer clears its borrows.
func (*synthetic) Close() error { return nil }
func fixture(p *synthetic) Fixture {
	r := p.command.NewResult()
	r.Entry, r.Class, r.NormalizedStatus, r.SafeResourceID = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 201, "synthetic-resource"
	r.ConsumerLocator = p.command.Target.ConsumerLocator
	return Fixture{Command: p.command, Policy: p.policy, Inputs: []credentialroute.Input{{Name: "TOKEN", Present: true, Value: []byte("credential")}}, Payload: []byte("value"), Expected: r}
}

// Check validates serving with an independent implementation and a public
// unknown-contract normalization. It is not provider or installation qualification.
func Check(serve Serve, public ServePublic) error {
	if serve == nil || public == nil {
		return failure("missing serving function")
	}
	for _, empty := range []bool{false, true} {
		p, err := newImplementation()
		if err != nil {
			return err
		}
		f := fixture(p)
		if empty {
			f.Payload = []byte{}
			f.Command.PayloadLength = 0
		}
		if err := CheckImplementation(context.Background(), serve, p, f); err != nil {
			return err
		}
	}
	p, err := newImplementation()
	if err != nil {
		return err
	}
	id := repeatedID(7)
	request := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Settings: []byte(`{"unlisted":true}`)}
	b, err := protocol.EncodeNormalizeRequest(request)
	if err != nil {
		return err
	}
	hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: p.Identity().DescriptorID, ArtifactContractID: repeatedID(31)})
	var control, result bytes.Buffer
	if protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindHello, CorrelationID: id, Body: hello}) != nil || protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindNormalizeRequest, CorrelationID: id, Body: b}) != nil {
		return failure("public fixture")
	}
	if public(context.Background(), output.PublicEndpoints{Control: &control, Result: &result}, p) != 0 {
		return failure("public serving")
	}
	if _, err = protocol.ReadExpectedFrame(&result, protocol.KindHelloAck, id, protocol.HelloBytes); err != nil {
		return failure("public acknowledgement")
	}
	b, err = protocol.ReadExpectedFrame(&result, protocol.KindNormalizeResult, id, protocol.MaximumPublicResultBytes)
	if err != nil {
		return failure("public result")
	}
	r, err := protocol.DecodeNormalizeResult(b)
	if err != nil || !r.Accepted || protocol.ValidateNormalizeResult(id, request, r) != nil || !bytes.Equal(r.Destination.CanonicalSettings, request.Settings) || protocol.RequireEOF(&result) != nil || p.calls != 0 {
		return failure("public meaning")
	}
	policy := protocol.Policy{ContractID: "unsupported-policy", Data: []byte("public policy")}
	selection := protocol.PolicyActionRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, DomainID: repeatedID(1), DescriptorID: p.Identity().DescriptorID, PolicyContractID: policy.ContractID, Target: p.command.Target}
	selection.PolicyDigest, err = protocol.PolicyDigest(selection.DomainID, policy)
	if err != nil {
		return err
	}
	b, err = protocol.EncodePolicyActionRequest(selection)
	if err != nil {
		return err
	}
	control.Reset()
	result.Reset()
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CorrelationID: id, Body: hello}, {Kind: protocol.KindPolicyActionRequest, CorrelationID: id, Body: b}, {Kind: protocol.KindPolicy, CorrelationID: id, Body: policy.Data}} {
		if protocol.WriteFrame(&control, frame) != nil {
			return failure("public selection fixture")
		}
	}
	if public(context.Background(), output.PublicEndpoints{Control: &control, Result: &result}, p) != 0 {
		return failure("public selection serving")
	}
	if _, err = protocol.ReadExpectedFrame(&result, protocol.KindHelloAck, id, protocol.HelloBytes); err != nil {
		return failure("public selection acknowledgement")
	}
	b, err = protocol.ReadExpectedFrame(&result, protocol.KindPolicyActionResult, id, protocol.MaximumPolicyActionResultBytes)
	if err != nil {
		return failure("public selection result")
	}
	selected, err := protocol.DecodePolicyActionResult(b)
	if err != nil || selected.Accepted || selected.Action != 0 || protocol.ValidatePolicyActionResponse(id, selection, policy, selected) != nil || protocol.RequireEOF(&result) != nil || p.calls != 0 {
		return failure("public selection meaning")
	}
	return nil
}

func (p *synthetic) SelectPolicyAction(context.Context, output.PolicyActionSelection, protocol.Policy) (protocol.Action, error) {
	return 0, protocol.ErrProtocol
}
