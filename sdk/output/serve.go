package output

import (
	"context"
	"errors"
	"io"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

// Implementation owns service interpretation and credential discovery. Embed a
// checked Binding to supply Identity and CredentialRoute. All methods are required.
// Passive callbacks receive only public read-only borrows until return and must
// not discover credentials or make service requests. Return independent public
// result bytes and no retained input aliases. Join all input users before return.
// Prepare has the longer lifetime described by Preparation and Prepared.
type Implementation interface {
	// Identity returns the fixed family and pre-build descriptor identities.
	Identity() ImplementationIdentity
	// CredentialRoute returns the declared public route, stable for the exchange.
	CredentialRoute() credentialroute.Route
	// NormalizeDestination applies defaults once to public settings and returns
	// canonical settings, contracts, opaque policy and supported action facts.
	NormalizeDestination(context.Context, []byte) (protocol.Destination, error)
	// ValidateCanonical checks exact retained facts without defaults or rewriting.
	ValidateCanonical(context.Context, protocol.Destination) error
	// InterpretTarget returns complete public target/consumer facts and separate
	// inclusive bounds for each advertised value action.
	InterpretTarget(context.Context, TargetRequest) (protocol.Target, error)
	// CheckAction validates the exact prospective action and policy, returning the
	// target's bounds for that value action or zero bounds for metadata actions.
	// Success grants no send authority.
	CheckAction(context.Context, ActionCheck, protocol.Policy) (protocol.PayloadBounds, error)
	// SelectPolicyAction chooses UpdatePolicy or WriteValue for equal value and
	// changed policy. It must use only these public facts, without credentials,
	// service access or payload. Missing prior evidence must remain absent.
	SelectPolicyAction(context.Context, PolicyActionSelection, protocol.Policy) (protocol.Action, error)
	// Prepare discovers credentials and checks the account/target without a
	// mutating service request. A nonnil Prepared transfers to the SDK for Close
	// even when an error is also returned. Error refuses before payload delivery;
	// success requires a nonnil Prepared.
	Prepare(context.Context, Preparation, protocol.Policy, []credentialroute.Input) (Prepared, error)
}

// ImplementationIdentity holds the family ProtocolID and canonical pre-build
// DescriptorID from Bind. The zero value cannot serve. The host supplies the
// measured artifact binding separately; the child echoes it and does not
// authenticate its executing bytes.
type ImplementationIdentity struct{ ProtocolID, DescriptorID protocol.ID }

// Prepared owns discovery/client resources until Close returns. The SDK calls
// Send at most once and Close once for every nonnil Prepared, including when
// Prepare also returns an error. Early cancellation or I/O failure can omit Send.
// Methods are synchronous; Close must join owned work and dispose private copies
// before returning, including after a failed Send. The SDK then clears its private
// input and payload buffers. The implementation must arrange cleanup for any
// transport-owned copies whose lifetime continues separately.
type Prepared interface {
	// Send borrows a read-only nonnil payload for a value action (even when empty)
	// and nil for metadata. Join all users of that borrow before returning.
	// Make at most one admitted mutation; no failure grants a resend. An error
	// or malformed Outcome is serialized as may-have-entered and unproved.
	Send(context.Context, []byte) (Outcome, error)
	// Close releases prepared resources and joins their owned work. Its error is
	// joined with any exchange error and does not undo a possible service effect.
	Close() error
}

// Endpoints contains the finite streams for one effect exchange: public control,
// private credential inputs, payload/arm input and correlated public result.
// All fields are required. Serving borrows them and closes none.
type Endpoints struct {
	Control, Credential, Payload io.Reader
	Result                       io.Writer
}

// PublicEndpoints contains the required public control and result streams for
// one passive exchange. There is no credential or payload channel.
type PublicEndpoints struct {
	Control io.Reader
	Result  io.Writer
}

func acknowledge(control io.Reader, result io.Writer, identity ImplementationIdentity) (protocol.ID, error) {
	if identity.ProtocolID != protocol.ProtocolID() || identity.DescriptorID.IsZero() {
		return protocol.ID{}, protocol.ErrProtocol
	}
	first, err := protocol.ReadFrame(control, protocol.HelloBytes)
	if err != nil {
		return protocol.ID{}, err
	}
	defer clear(first.Body)
	if first.Kind != protocol.KindHello {
		return protocol.ID{}, protocol.ErrProtocol
	}
	hello, err := protocol.DecodeHello(first.Body)
	if err != nil || hello.ProtocolID != identity.ProtocolID || hello.DescriptorID != identity.DescriptorID {
		return protocol.ID{}, protocol.ErrProtocol
	}
	ack, err := protocol.EncodeHello(hello)
	if err != nil {
		return protocol.ID{}, err
	}
	if err = protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindHelloAck, CorrelationID: first.CorrelationID, Body: ack}); err != nil {
		return protocol.ID{}, err
	}
	return first.CorrelationID, nil
}

// Serve borrows streams. Its caller must unblock I/O on cancellation and join
// the call. Private input/payload buffers are cleared only after Prepared closes.
// It never changes process environment. Preparation refusal can complete without
// an error and without reading payload. Send errors and invalid outcomes become
// unproved results; they are not returned as proof of no effect. Other framing,
// I/O, context and close errors can be returned, with close causes joined.
// protocol.ErrProtocol is usable with errors.Is for protocol refusals; returned
// errors can contain underlying I/O or implementation close details.
func Serve(ctx context.Context, e Endpoints, implementation Implementation) (err error) {
	if ctx == nil || implementation == nil || e.Control == nil || e.Credential == nil || e.Payload == nil || e.Result == nil {
		return protocol.ErrProtocol
	}
	checkID, err := acknowledge(e.Control, e.Result, implementation.Identity())
	if err != nil {
		return err
	}
	b, err := protocol.ReadExpectedFrame(e.Control, protocol.KindCommand, checkID, protocol.MaximumCommandBytes)
	if err != nil {
		return err
	}
	command, err := protocol.DecodeCommand(b)
	if err != nil || command.AttemptID != checkID || command.DescriptorID != implementation.Identity().DescriptorID {
		return protocol.ErrProtocol
	}
	policyBytes, err := protocol.ReadExpectedFrame(e.Control, protocol.KindPolicy, checkID, protocol.MaximumPolicyBytes)
	if err != nil {
		return err
	}
	policy, err := protocol.DecodePolicy(command.PolicyContractID, policyBytes)
	if err != nil || protocol.ValidatePolicy(command, policy) != nil || protocol.RequireEOF(e.Control) != nil {
		return protocol.ErrProtocol
	}
	callCtx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(command.DeadlineUnixMillis)))
	defer cancel()
	if err = callCtx.Err(); err != nil {
		return err
	}
	check := command.ActionCheck()
	bounds, callErr := implementation.CheckAction(callCtx, actionFacts(check), policy)
	if callErr != nil || protocol.ValidatePayloadBounds(check, bounds) != nil {
		return protocol.ErrProtocol
	}
	if err = callCtx.Err(); err != nil {
		return err
	}
	route := implementation.CredentialRoute()
	routeID, routeErr := credentialroute.Identity(route)
	if routeErr != nil || protocol.ID(routeID) != command.CredentialRouteID {
		return protocol.ErrProtocol
	}
	var payload []byte
	defer func() { clear(payload) }()
	private, err := protocol.ReadExpectedFrame(e.Credential, protocol.KindCredential, checkID, protocol.MaximumCredentialBytes)
	if err != nil {
		return err
	}
	defer clear(private)
	inputs, err := credentialroute.DecodeInputs(route, private)
	if err != nil || protocol.RequireEOF(e.Credential) != nil {
		return protocol.ErrProtocol
	}
	if err = callCtx.Err(); err != nil {
		return err
	}
	prepared, prepareErr := implementation.Prepare(callCtx, preparationFacts(command), policy, inputs)
	// Register Close before handling refusal. Private input and payload defers
	// run after it, so a prepared invocation can join users before clearing.
	if prepared != nil {
		defer func() { err = errors.Join(err, prepared.Close()) }()
	}
	if prepareErr != nil {
		return protocol.WriteFrame(e.Result, protocol.Frame{Kind: protocol.KindPreparationRefused, CorrelationID: checkID})
	}
	if prepared == nil {
		return protocol.ErrProtocol
	}
	if err = callCtx.Err(); err != nil {
		return err
	}
	if err = protocol.WriteFrame(e.Result, protocol.Frame{Kind: protocol.KindReadyForPayload, CorrelationID: checkID}); err != nil {
		return err
	}
	kind := uint8(protocol.KindArm)
	if command.PayloadLengthMode == protocol.LengthExact {
		kind = protocol.KindPayload
	}
	payload, err = protocol.ReadExpectedFrame(e.Payload, kind, checkID, protocol.MaximumPayloadBytes)
	if err != nil {
		return err
	}
	if len(payload) != int(command.PayloadLength) || protocol.RequireEOF(e.Payload) != nil {
		return protocol.ErrProtocol
	}
	if command.PayloadLengthMode != protocol.LengthExact {
		payload = nil
	}
	if err = callCtx.Err(); err != nil {
		return err
	}
	outcome, callErr := prepared.Send(callCtx, payload)
	result, outcomeErr := correlateOutcome(command, outcome)
	if callErr != nil || outcomeErr != nil {
		result = command.NewResult()
		result.Entry, result.Class = protocol.EntryMayHaveEntered, protocol.ClassUnproved
	}
	encoded, err := protocol.EncodeResult(result)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(e.Result, protocol.Frame{Kind: protocol.KindResult, CorrelationID: checkID, Body: encoded})
}

// ServePublic handles exactly one passive operation and exposes no private pipes.
// It borrows streams and closes none. The caller must bound and unblock I/O on
// cancellation and join the call. Callback refusal is encoded as a negative
// result; framing, context and I/O failures are returned. It sets no environment.
func ServePublic(ctx context.Context, e PublicEndpoints, implementation Implementation) error {
	if ctx == nil || implementation == nil || e.Control == nil || e.Result == nil {
		return protocol.ErrProtocol
	}
	checkID, err := acknowledge(e.Control, e.Result, implementation.Identity())
	if err != nil {
		return err
	}
	frame, err := protocol.ReadFrame(e.Control, protocol.MaximumPublicRequestBytes)
	if err != nil {
		return err
	}
	if frame.CorrelationID != checkID {
		return protocol.ErrProtocol
	}
	var policyBytes []byte
	if frame.Kind == protocol.KindActionCheckRequest || frame.Kind == protocol.KindPolicyActionRequest {
		maximum := protocol.MaximumActionCheckRequestBytes
		if frame.Kind == protocol.KindPolicyActionRequest {
			maximum = protocol.MaximumPolicyActionRequestBytes
		}
		if len(frame.Body) > maximum {
			return protocol.ErrCapacity
		}
		policyBytes, err = protocol.ReadExpectedFrame(e.Control, protocol.KindPolicy, checkID, protocol.MaximumPolicyBytes)
		if err != nil {
			return err
		}
	}
	if protocol.RequireEOF(e.Control) != nil {
		return protocol.ErrProtocol
	}
	digest, err := protocol.PublicRequestDigest(checkID, frame.Kind, frame.Body, policyBytes)
	if err != nil {
		return err
	}
	var deadline uint64
	var normalize protocol.NormalizeRequest
	var canonical protocol.CanonicalRequest
	var interpret protocol.InterpretRequest
	var check protocol.ActionCheckRequest
	var selection protocol.PolicyActionRequest
	switch frame.Kind {
	case protocol.KindNormalizeRequest:
		normalize, err = protocol.DecodeNormalizeRequest(frame.Body)
		if err != nil {
			return err
		}
		deadline = normalize.DeadlineUnixMillis
	case protocol.KindCanonicalRequest:
		canonical, err = protocol.DecodeCanonicalRequest(frame.Body)
		if err != nil {
			return err
		}
		deadline = canonical.DeadlineUnixMillis
	case protocol.KindInterpretRequest:
		interpret, err = protocol.DecodeInterpretRequest(frame.Body)
		if err != nil {
			return err
		}
		deadline = interpret.DeadlineUnixMillis
	case protocol.KindActionCheckRequest:
		check, err = protocol.DecodeActionCheckRequest(frame.Body)
		if err != nil || check.DescriptorID != implementation.Identity().DescriptorID {
			return protocol.ErrProtocol
		}
		deadline = check.DeadlineUnixMillis
	case protocol.KindPolicyActionRequest:
		selection, err = protocol.DecodePolicyActionRequest(frame.Body)
		if err != nil || selection.DescriptorID != implementation.Identity().DescriptorID {
			return protocol.ErrProtocol
		}
		deadline = selection.DeadlineUnixMillis
	default:
		return protocol.ErrProtocol
	}
	callCtx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(deadline)))
	defer cancel()
	if callCtx.Err() != nil {
		return callCtx.Err()
	}
	var kind uint8
	var encoded []byte
	switch frame.Kind {
	case protocol.KindNormalizeRequest:
		value, callErr := implementation.NormalizeDestination(callCtx, normalize.Settings)
		result := protocol.NormalizeResult{Schema: 1, RequestDigest: digest}
		if callErr == nil && value.Valid() {
			result.Accepted = true
			result.Destination = value
		}
		kind = protocol.KindNormalizeResult
		encoded, err = protocol.EncodeNormalizeResult(result)
	case protocol.KindCanonicalRequest:
		callErr := implementation.ValidateCanonical(callCtx, canonical.Destination)
		kind = protocol.KindCanonicalResult
		encoded, err = protocol.EncodeCanonicalResult(protocol.CanonicalResult{Schema: 1, RequestDigest: digest, Accepted: callErr == nil})
	case protocol.KindInterpretRequest:
		value, callErr := implementation.InterpretTarget(callCtx, TargetRequest{Destination: interpret.Destination, EntryName: interpret.EntryName, PayloadEncoding: interpret.PayloadEncoding})
		result := protocol.InterpretResult{Schema: 1, RequestDigest: digest}
		candidate := protocol.InterpretResult{Schema: 1, RequestDigest: digest, Accepted: true, Target: value}
		if callErr == nil && protocol.ValidateInterpretResult(interpret, candidate) == nil {
			result = candidate
		}
		kind = protocol.KindInterpretResult
		encoded, err = protocol.EncodeInterpretResult(result)
	case protocol.KindActionCheckRequest:
		policy, decodeErr := protocol.DecodePolicy(check.PolicyContractID, policyBytes)
		if decodeErr != nil || protocol.ValidateActionCheckPolicy(check, policy) != nil {
			return protocol.ErrProtocol
		}
		value, callErr := implementation.CheckAction(callCtx, actionFacts(check), policy)
		result := protocol.ActionCheckResult{Schema: 1, RequestDigest: digest}
		if callErr == nil && protocol.ValidatePayloadBounds(check, value) == nil {
			result.Accepted = true
			result.PayloadBounds = value
		}
		kind = protocol.KindActionCheckResult
		encoded, err = protocol.EncodeActionCheckResult(result)
	case protocol.KindPolicyActionRequest:
		policy, decodeErr := protocol.DecodePolicy(selection.PolicyContractID, policyBytes)
		if decodeErr != nil || protocol.ValidatePolicyActionPolicy(selection, policy) != nil {
			return protocol.ErrProtocol
		}
		value, callErr := implementation.SelectPolicyAction(callCtx, PolicyActionSelection{DomainID: selection.DomainID, Target: selection.Target, HasPreviousPolicyDigest: selection.HasPreviousPolicyDigest, PreviousPolicyDigest: selection.PreviousPolicyDigest}, policy)
		result := protocol.PolicyActionResult{Schema: 1, RequestDigest: digest}
		candidate := protocol.PolicyActionResult{Schema: 1, RequestDigest: digest, Accepted: true, Action: value}
		if callErr == nil && protocol.ValidatePolicyActionResult(selection, candidate) == nil {
			result = candidate
		}
		kind = protocol.KindPolicyActionResult
		encoded, err = protocol.EncodePolicyActionResult(result)
	}
	if err != nil {
		return err
	}
	if callCtx.Err() != nil {
		return callCtx.Err()
	}
	return protocol.WriteFrame(e.Result, protocol.Frame{Kind: kind, CorrelationID: checkID, Body: encoded})
}
