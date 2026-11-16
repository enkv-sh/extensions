// Package generator serves the bounded public generator family protocol.
package generator

import (
	"context"
	"errors"
	"io"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

const (
	exitSuccess           = 0
	exitInvalidArguments  = 20
	exitHelloRead         = 21
	exitHelloDecode       = 22
	exitHelloAck          = 23
	exitEnvironmentRead   = 24
	exitEnvironmentDecode = 25
	exitCommandRead       = 26
	exitCommandDecode     = 27
	exitCommandBinding    = 28
	exitExecution         = 29
	exitResultEncode      = 30
	exitResultWrite       = 31
	exitStatusWrite       = 32
	exitDescriptorClose   = 33
)

// ImplementationIdentity contains the family ProtocolID and canonical pre-build
// DescriptorID supplied by Bind. Its zero value cannot serve an exchange.
// The host's measured artifact identity is echoed, not self-authenticated here.
type ImplementationIdentity struct{ ProtocolID, DescriptorID protocol.ID }

// Invocation borrows its command and private input values until callback return.
// Do not change or retain them. Join every user before returning.
type Invocation struct {
	Command protocol.Command
	Inputs  []credentialroute.Input
}

// Implementation owns settings and resource interpretation. Obtain Binding with
// Bind before serving; the zero value is invalid. Callback requirements are
// checked for each operation. Fresh managed CREATE requires both retirement callbacks.
//
// All callbacks run synchronously. Their inputs are read-only borrows until
// return; join every user before returning. Passive callbacks must not discover
// credentials or perform service effects. Context deadlines do not exceed the
// issued deadline, but cancellation cannot stop callback code on its own.
//
// Returned settings, variable facts and value allocations transfer to the SDK
// even on error. Expose each complete allocation from its beginning through its
// capacity, with no borrowed-input alias or retained user. The SDK clears that
// capacity after encoding or refusal, including failed writes. Hidden aliases and
// immutable copies remain the author's responsibility.
type Implementation struct {
	Binding
	// Normalize applies defaults once and returns owned canonical settings and
	// semantic lifecycle/resource contracts for public settings.
	Normalize func(context.Context, protocol.NormalizeRequest) (protocol.Intent, error)
	// ValidateCanonical checks the exact retained intent without rewriting bytes
	// or applying new defaults. It also runs before create receives private inputs.
	ValidateCanonical func(context.Context, protocol.Intent) error
	// CheckRetirementCompatibility checks the exact original intent/resource facts
	// for new retirement work. It does not replace an accepted Duty's executor.
	CheckRetirementCompatibility func(context.Context, protocol.RetirementCompatibilityRequest) (bool, error)
	// Create returns public facts and a retained private value. A complete create
	// needs 1–MaximumSecretLength bytes; the host checks the declared input
	// representation and logical content limit. An owned-unusable result
	// preserves the resource facts.
	Create func(context.Context, Invocation) (protocol.SafeFacts, []byte, error)
	// Retire addresses the exact original resource and returns no value.
	// Native success establishes acknowledgement, not confirmed invalidation.
	Retire func(context.Context, Invocation) (protocol.SafeFacts, error)
}

func (v Implementation) valid() bool {
	if v.Identity().ProtocolID != protocol.ProtocolID() || v.Identity().DescriptorID.IsZero() || v.ConfigContractID().IsZero() {
		return false
	}
	_, err := credentialroute.Encode(v.route)
	return err == nil
}

func (v Implementation) createReady(intent protocol.Intent) bool {
	return v.Create != nil && (intent.LifecycleMode != protocol.LifecycleManaged || v.Retire != nil && v.CheckRetirementCompatibility != nil)
}

type environmentInstaller func([]credentialroute.Input) (func() error, error)

// Run borrows finite streams and serves exactly one operation. It never changes
// process environment. Effect callbacks receive decoded private Inputs; passive
// callbacks receive no private inputs. The caller owns I/O cancellation and joins.
// Run closes no streams, retries no callback or write, and returns zero only for
// a complete exchange. A nonzero status grants no retry or no-effect evidence.
// Valid managed-resource results can survive cancellation after callback entry;
// no-resource results are refused after cancellation. Callback errors refuse the
// result, but all returned allocations still transfer for clearing.
func Run(ctx context.Context, control, environment io.Reader, result, status io.Writer, implementation Implementation) int {
	return run(ctx, control, environment, result, status, implementation, nil)
}

func run(ctx context.Context, control, environment io.Reader, result, status io.Writer, implementation Implementation, install environmentInstaller) (code int) {
	if ctx == nil || control == nil || environment == nil || result == nil || status == nil || !implementation.valid() {
		return exitInvalidArguments
	}
	helloFrame, err := protocol.ReadFrame(control, protocol.HelloBodyLength)
	if err != nil || helloFrame.Kind != protocol.KindHello {
		clear(helloFrame.Body)
		return exitHelloRead
	}
	hello, err := protocol.DecodeHello(helloFrame.Body)
	clear(helloFrame.Body)
	if err != nil || hello.ProtocolID != implementation.Identity().ProtocolID || hello.DescriptorID != implementation.Identity().DescriptorID {
		return exitHelloDecode
	}
	helloBody, err := protocol.EncodeHello(hello)
	if err != nil {
		return exitHelloAck
	}
	defer clear(helloBody)
	if protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindHelloAck, CommandID: helloFrame.CommandID, Body: helloBody}) != nil {
		return exitHelloAck
	}
	frame, err := protocol.ReadFrame(control, protocol.MaximumPublicBody)
	if err != nil {
		return failureStatus(status, helloFrame.CommandID, protocol.StatusStageCommand, protocol.StatusProtocol, exitCommandRead)
	}
	defer clear(frame.Body)
	if frame.CommandID != helloFrame.CommandID || protocol.RequireEOF(control) != nil {
		return failureStatus(status, helloFrame.CommandID, protocol.StatusStageCommand, protocol.StatusProtocol, exitCommandBinding)
	}
	if frame.Kind != protocol.KindCommand {
		if protocol.RequireEOF(environment) != nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageEnvironment, protocol.StatusInvalid, exitEnvironmentDecode)
		}
		return runPassive(ctx, frame, result, status, implementation)
	}
	command, err := protocol.DecodeCommand(frame.Body)
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandDecode)
	}
	routeID, err := credentialroute.Identity(implementation.route)
	if err != nil || command.DescriptorID != implementation.Identity().DescriptorID || command.CredentialRouteID != protocol.ID(routeID) {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandBinding)
	}
	callbackContext, cancel, err := callbackDeadline(ctx, command.DeadlineUnixMillis)
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusCancelled, exitExecution)
	}
	defer cancel()
	if command.Action == protocol.ActionCreate {
		intent, err := protocol.DecodeIntent(command.Intent)
		if err != nil || implementation.ValidateCanonical == nil || !implementation.createReady(intent) || implementation.ValidateCanonical(callbackContext, intent) != nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitExecution)
		}
		actualDigest, digestErr := protocol.IntentDigest(command.Intent)
		if digestErr != nil || actualDigest != command.IntentDigest {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitExecution)
		}
	} else if implementation.Retire == nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusUnavailable, exitExecution)
	}
	privateBody, err := protocol.ReadExpectedFrame(environment, protocol.KindEnvironment, frame.CommandID, protocol.MaximumEnvironmentBody)
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageEnvironment, protocol.StatusProtocol, exitEnvironmentRead)
	}
	defer clear(privateBody)
	inputs, err := credentialroute.DecodeInputs(implementation.route, privateBody)
	if err != nil || protocol.RequireEOF(environment) != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageEnvironment, protocol.StatusInvalid, exitEnvironmentDecode)
	}
	if callbackContext.Err() != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusCancelled, exitExecution)
	}
	if install != nil {
		cleanup, err := install(inputs)
		if err != nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageEnvironment, protocol.StatusUnavailable, exitEnvironmentDecode)
		}
		defer func() {
			if cleanup() != nil && code == exitSuccess {
				code = exitDescriptorClose
			}
		}()
	}
	invocation := Invocation{Command: command, Inputs: inputs}
	var facts protocol.SafeFacts
	var value []byte
	if command.Action == protocol.ActionCreate {
		facts, value, err = implementation.Create(callbackContext, invocation)
	} else {
		facts, err = implementation.Retire(callbackContext, invocation)
	}
	defer clearFacts(facts)
	defer clear(full(value))
	// Keep valid original managed-resource evidence after cancellation: dropping
	// that evidence would not undo a possible service effect.
	callbackErr := callbackContext.Err()
	if command.LifecycleMode == protocol.LifecycleNone && err == nil {
		err = callbackErr
	}
	cancel()
	if err != nil {
		stage, category := protocol.StatusStageResponse, errorCategory(err)
		if command.LifecycleMode == protocol.LifecycleNone {
			stage = protocol.StatusStageCommand
			switch {
			case callbackErr != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
				category = protocol.StatusCancelled
			case errors.Is(err, protocol.ErrProtocol):
				category = protocol.StatusInvalid
			default:
				category = protocol.StatusUnavailable
			}
		}
		return failureStatus(status, frame.CommandID, stage, category, exitExecution)
	}
	if overlapsReturned(facts, value, frame.Body, privateBody) {
		return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
	}
	response := command.NewResult(facts, value)
	if protocol.ValidateResult(command, response) != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
	}
	body, err := protocol.EncodeResult(response)
	clear(full(value))
	clearFacts(facts)
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
	}
	defer clear(body)
	if protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindResult, CommandID: frame.CommandID, Body: body}) != nil {
		return exitResultWrite
	}
	if !writeStatus(status, frame.CommandID, protocol.StatusStageReturn, protocol.StatusOK) {
		return exitStatusWrite
	}
	return exitSuccess
}

func runPassive(ctx context.Context, frame protocol.Frame, result, status io.Writer, implementation Implementation) int {
	var deadline uint64
	var input protocol.ID
	var request any
	switch frame.Kind {
	case protocol.KindNormalize:
		v, err := protocol.DecodeNormalizeRequest(frame.Body)
		if err != nil || v.ConfigContractID != implementation.ConfigContractID() {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandDecode)
		}
		deadline, input, request = v.DeadlineUnixMillis, v.InputDigest, v
	case protocol.KindValidateCanonical:
		v, err := protocol.DecodeCanonicalRequest(frame.Body)
		if err != nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandDecode)
		}
		deadline, input, request = v.DeadlineUnixMillis, v.InputDigest, v
	case protocol.KindRetirementCompatibility:
		v, err := protocol.DecodeRetirementCompatibilityRequest(frame.Body)
		if err != nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandDecode)
		}
		deadline, input, request = v.DeadlineUnixMillis, v.InputDigest, v
	default:
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusInvalid, exitCommandBinding)
	}
	callbackContext, cancel, err := callbackDeadline(ctx, deadline)
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusCancelled, exitExecution)
	}
	defer cancel()
	var body []byte
	var kind uint8
	switch v := request.(type) {
	case protocol.NormalizeRequest:
		if implementation.Normalize == nil || implementation.ValidateCanonical == nil || implementation.Create == nil {
			return failureStatus(status, frame.CommandID, protocol.StatusStageCommand, protocol.StatusUnavailable, exitExecution)
		}
		intent, callbackErr := implementation.Normalize(callbackContext, v)
		defer clear(full(intent.Settings))
		accepted := callbackErr == nil && callbackContext.Err() == nil
		currentDigest, digestErr := protocol.NormalizeInputDigest(v)
		if accepted && (digestErr != nil || currentDigest != input) {
			return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
		}
		var encoded []byte
		if accepted {
			if intent.ConfigContractID != implementation.ConfigContractID() || !implementation.createReady(intent) || overlaps(intent.Settings, frame.Body) {
				return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
			}
			encoded, err = protocol.EncodeIntent(intent)
			if err != nil {
				return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
			}
			defer clear(encoded)
		}
		body, err = protocol.EncodeNormalizeResponse(protocol.NormalizeResponse{Schema: protocol.Schema, InputDigest: input, Accepted: accepted, Intent: encoded})
		kind = protocol.KindNormalized
	case protocol.CanonicalRequest:
		intent, decodeErr := protocol.DecodeIntent(v.Intent)
		accepted := decodeErr == nil && implementation.ValidateCanonical != nil &&
			(v.Purpose != protocol.CanonicalFreshCreate || implementation.createReady(intent)) &&
			implementation.ValidateCanonical(callbackContext, intent) == nil && callbackContext.Err() == nil
		currentDigest, digestErr := protocol.CanonicalInputDigest(v)
		accepted = accepted && digestErr == nil && currentDigest == input
		body, err = protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: protocol.Schema, InputDigest: input, Accepted: accepted})
		kind = protocol.KindCanonicalValidation
	case protocol.RetirementCompatibilityRequest:
		accepted := false
		if v.CompletionClass == protocol.CompletionAcknowledged && implementation.CheckRetirementCompatibility != nil {
			accepted, err = implementation.CheckRetirementCompatibility(callbackContext, v)
			accepted = accepted && err == nil && callbackContext.Err() == nil
		}
		currentDigest, digestErr := protocol.RetirementCompatibilityInputDigest(v)
		accepted = accepted && digestErr == nil && currentDigest == input
		body, err = protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: protocol.Schema, InputDigest: input, Accepted: accepted})
		kind = protocol.KindRetirementCompatibilityResult
	}
	if err != nil {
		return failureStatus(status, frame.CommandID, protocol.StatusStageResponse, protocol.StatusProtocol, exitResultEncode)
	}
	defer clear(body)
	if protocol.WriteFrame(result, protocol.Frame{Kind: kind, CommandID: frame.CommandID, Body: body}) != nil {
		return exitResultWrite
	}
	if !writeStatus(status, frame.CommandID, protocol.StatusStageReturn, protocol.StatusOK) {
		return exitStatusWrite
	}
	return exitSuccess
}

func callbackDeadline(ctx context.Context, n uint64) (context.Context, context.CancelFunc, error) {
	deadline := time.UnixMilli(int64(n))
	if ctx.Err() != nil || !deadline.After(time.Now()) {
		return nil, nil, context.DeadlineExceeded
	}
	callback, cancel := context.WithDeadline(ctx, deadline)
	if callback.Err() != nil {
		cancel()
		return nil, nil, callback.Err()
	}
	return callback, cancel, nil
}
func errorCategory(err error) uint16 {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return protocol.StatusCancelled
	}
	return protocol.StatusUnavailable
}
func failureStatus(w io.Writer, id protocol.ID, stage uint8, category uint16, code int) int {
	if !writeStatus(w, id, stage, category) {
		return exitStatusWrite
	}
	return code
}
func writeStatus(w io.Writer, id protocol.ID, stage uint8, category uint16) bool {
	b, err := protocol.EncodeStatus(protocol.Status{Stage: stage, Category: category})
	return err == nil && protocol.WriteFrame(w, protocol.Frame{Kind: protocol.KindStatus, CommandID: id, Body: b}) == nil
}
func full(b []byte) []byte { return b[:cap(b)] }
func clearFacts(f protocol.SafeFacts) {
	clear(full(f.Target))
	clear(full(f.ResourceData))
	clear(full(f.ProviderFacts))
}
func overlapsReturned(f protocol.SafeFacts, value []byte, inputs ...[]byte) bool {
	for _, out := range [][]byte{full(value), full(f.Target), full(f.ResourceData), full(f.ProviderFacts)} {
		for _, in := range inputs {
			if overlaps(out, in) {
				return true
			}
		}
	}
	return false
}
func overlaps(a, b []byte) bool {
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
