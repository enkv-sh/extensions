package generator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

var processValue = []byte{0, 255, 1, 7, 0}

const processToken = "private-input-test"

func processID(n byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = n
	}
	return id
}
func processImplementation() Implementation {
	return Implementation{
		Binding: Binding{identity: ImplementationIdentity{ProtocolID: protocol.ProtocolID(), DescriptorID: processID(2)}, config: processID(3),
			route: credentialroute.Route{Schema: 1, ContractID: [32]byte(processID(4)), Mode: credentialroute.ModeEnvironment, Names: []string{"PRIVATE_TOKEN"}}},
		Normalize: func(_ context.Context, _ protocol.NormalizeRequest) (protocol.Intent, error) {
			return protocol.Intent{Schema: 1, ConfigContractID: processID(3), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: processID(5), Settings: []byte(`{}`)}, nil
		},
		ValidateCanonical: func(_ context.Context, intent protocol.Intent) error {
			if !bytes.Equal(intent.Settings, []byte(`{}`)) {
				return protocol.ErrProtocol
			}
			return nil
		},
		CheckRetirementCompatibility: func(context.Context, protocol.RetirementCompatibilityRequest) (bool, error) { return true, nil },
		Create: func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
			return completeFacts(inv.Command), bytes.Clone(processValue), nil
		},
		Retire: func(_ context.Context, inv Invocation) (protocol.SafeFacts, error) {
			original, err := protocol.DecodeSafeFacts(inv.Command.OriginalFacts)
			f := inv.Command.NewFacts(protocol.DispositionRetirementAcknowledged, protocol.ReasonNone)
			f.Target, f.ResourceData = bytes.Clone(original.Target), bytes.Clone(original.ResourceData)
			return f, err
		},
	}
}
func processCommand(t *testing.T, implementation Implementation) protocol.Command {
	t.Helper()
	intent, err := protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: implementation.ConfigContractID(), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: processID(5), Settings: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := protocol.IntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(implementation.CredentialRoute())
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{Schema: 1, Action: protocol.ActionCreate, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), DomainID: processID(6), OperationID: processID(7), RequestIdentityDigest: processID(8), PlanGraphID: processID(9), LineageID: processID(10), AttemptID: processID(11), TransmissionID: processID(12), ResultID: processID(13), ResultContractID: processID(14), DescriptorID: implementation.Identity().DescriptorID, ExecutorID: processID(15), RequestDigest: processID(16), IntentDigest: digest, ResourceContractID: processID(5), CredentialRouteID: protocol.ID(routeID), LifecycleMode: protocol.LifecycleManaged, Intent: intent}
}
func processInput(t *testing.T, implementation Implementation, command protocol.Command) (bytes.Buffer, bytes.Buffer, protocol.ID) {
	t.Helper()
	hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(17)})
	body, err := protocol.EncodeCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	private, err := credentialroute.EncodeInputs(implementation.CredentialRoute(), []credentialroute.Input{{Name: "PRIVATE_TOKEN", Present: true, Value: []byte(processToken)}})
	if err != nil {
		t.Fatal(err)
	}
	var control, environment bytes.Buffer
	id := processID(18)
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CommandID: id, Body: hello}, {Kind: protocol.KindCommand, CommandID: id, Body: body}} {
		if err := protocol.WriteFrame(&control, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := protocol.WriteFrame(&environment, protocol.Frame{Kind: protocol.KindEnvironment, CommandID: id, Body: private}); err != nil {
		t.Fatal(err)
	}
	clear(private)
	return control, environment, id
}
func completeFacts(command protocol.Command) protocol.SafeFacts {
	f := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	if command.LifecycleMode == protocol.LifecycleManaged {
		f.Target, f.ResourceData = []byte("local/account"), []byte("owned-resource")
	}
	return f
}
func readResult(t *testing.T, result *bytes.Buffer, id protocol.ID) protocol.Result {
	t.Helper()
	body, err := protocol.ReadExpectedFrame(result, protocol.KindResult, id, protocol.MaximumResultBody)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.DecodeResult(body)
	if err != nil || protocol.RequireEOF(result) != nil {
		t.Fatal("result exchange failed", err)
	}
	return got
}
func finalStatus(t *testing.T, status *bytes.Buffer, id protocol.ID, want protocol.Status) {
	t.Helper()
	if _, err := protocol.ReadExpectedFrame(status, protocol.KindHelloAck, id, 96); err != nil {
		t.Fatal(err)
	}
	body, err := protocol.ReadExpectedFrame(status, protocol.KindStatus, id, 3)
	if err != nil || !bytes.Equal(body, []byte{want.Stage, byte(want.Category >> 8), byte(want.Category)}) || protocol.RequireEOF(status) != nil {
		t.Fatal("closed terminal status differs", err)
	}
}
func assertCleared(t *testing.T, body []byte) {
	t.Helper()
	for _, b := range body {
		if b != 0 {
			t.Fatal("owned bytes remain after return")
		}
	}
}

// full_only: false
func TestRunCompletesGenericExchangeAndClearsPrivateInputs(t *testing.T) {
	implementation := processImplementation()
	command := processCommand(t, implementation)
	control, environment, id := processInput(t, implementation, command)
	var result, status bytes.Buffer
	calls := 0
	var capturedPrivate, capturedIntent []byte
	var callbackContext context.Context
	implementation.Create = func(ctx context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
		calls++
		callbackContext = ctx
		capturedIntent = inv.Command.Intent
		capturedPrivate = inv.Inputs[0].Value
		if !reflect.DeepEqual(inv.Command, command) || string(capturedPrivate) != processToken || cap(capturedPrivate) != len(capturedPrivate) || cap(capturedIntent) != len(capturedIntent) {
			t.Fatal("callback input differs")
		}
		return completeFacts(inv.Command), bytes.Clone(processValue), nil
	}
	if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code != 0 {
		t.Fatal("run failed", code)
	}
	if calls != 1 || callbackContext.Err() != context.Canceled {
		t.Fatal("callback lifetime differs")
	}
	assertCleared(t, capturedPrivate)
	assertCleared(t, capturedIntent)
	got := readResult(t, &result, id)
	if protocol.ValidateResult(command, got) != nil || !bytes.Equal(got.Value, processValue) {
		t.Fatal("generic result changed")
	}
	if bytes.Contains(status.Bytes(), []byte(processToken)) || bytes.Contains(status.Bytes(), processValue) {
		t.Fatal("private bytes reached public status")
	}
	finalStatus(t, &status, id, protocol.Status{Stage: protocol.StatusStageReturn})
}

// full_only: false
func TestRunRefusesEnvironmentMismatchBeforeEffect(t *testing.T) {
	for _, condition := range []string{"route", "correlation", "name", "trailing"} {
		t.Run(condition, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			if condition == "route" {
				command.CredentialRouteID = processID(91)
			}
			control, environment, _ := processInput(t, implementation, command)
			switch condition {
			case "correlation":
				environment.Bytes()[7] ^= 1
			case "name":
				environment.Bytes()[protocol.HeaderLength+4] ^= 1
			case "trailing":
				environment.WriteByte(0)
			}
			called := false
			implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
				called = true
				return protocol.SafeFacts{}, nil, nil
			}
			var result, status bytes.Buffer
			if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code == 0 || called || result.Len() != 0 {
				t.Fatal("invalid private input reached effect", code)
			}
		})
	}
}

// full_only: false
func TestRunCanonicalValidationPrecedesPrivateInput(t *testing.T) {
	implementation := processImplementation()
	command := processCommand(t, implementation)
	control, environment, _ := processInput(t, implementation, command)
	implementation.ValidateCanonical = func(context.Context, protocol.Intent) error { return errors.New("private callback detail") }
	var result, status bytes.Buffer
	before := environment.Len()
	if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code == 0 || before != environment.Len() || result.Len() != 0 || bytes.Contains(status.Bytes(), []byte("private callback detail")) {
		t.Fatal("invalid canonical input acquired credentials", code)
	}
}

// full_only: false
func TestRunPassiveNormalizationDoesNotAcquirePrivateInputs(t *testing.T) {
	for _, hasPrivate := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "private-refused"}[hasPrivate], func(t *testing.T) {
			implementation := processImplementation()
			implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
				t.Fatal("passive normalization entered Create")
				return protocol.SafeFacts{}, nil, protocol.ErrProtocol
			}
			implementation.Retire = func(context.Context, Invocation) (protocol.SafeFacts, error) {
				t.Fatal("passive normalization entered Retire")
				return protocol.SafeFacts{}, protocol.ErrProtocol
			}
			request := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), ConfigContractID: implementation.ConfigContractID(), Settings: []byte(`{"custom_default":7}`)}
			request.InputDigest, _ = protocol.NormalizeInputDigest(request)
			body, _ := protocol.EncodeNormalizeRequest(request)
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(90)})
			id := processID(91)
			var control, environment, result, status bytes.Buffer
			if err := protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindHello, CommandID: id, Body: hello}); err != nil {
				t.Fatal(err)
			}
			if err := protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindNormalize, CommandID: id, Body: body}); err != nil {
				t.Fatal(err)
			}
			if hasPrivate {
				environment.WriteByte(1)
			}
			calls := 0
			var settings []byte
			implementation.Normalize = func(_ context.Context, got protocol.NormalizeRequest) (protocol.Intent, error) {
				calls++
				if !bytes.Equal(got.Settings, request.Settings) {
					t.Fatal("passive input changed")
				}
				settings = []byte(`{}`)
				return protocol.Intent{Schema: 1, ConfigContractID: implementation.ConfigContractID(), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: processID(5), Settings: settings}, nil
			}
			code := Run(context.Background(), &control, &environment, &result, &status, implementation)
			if hasPrivate {
				if code == 0 || calls != 0 || result.Len() != 0 {
					t.Fatal("passive acquired private inputs")
				}
				return
			}
			if code != 0 || calls != 1 {
				t.Fatal("normalization failed", code)
			}
			assertCleared(t, settings)
			response, err := protocol.ReadExpectedFrame(&result, protocol.KindNormalized, id, protocol.MaximumPublicBody)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := protocol.DecodeNormalizeResponse(response)
			if err != nil || !normalized.Accepted || normalized.InputDigest != request.InputDigest {
				t.Fatal("normalization response differs", err)
			}
		})
	}
}

// full_only: false
func TestCanonicalCallbackCannotRewriteBeforePrivateInput(t *testing.T) {
	implementation := processImplementation()
	command := processCommand(t, implementation)
	control, environment, _ := processInput(t, implementation, command)
	implementation.ValidateCanonical = func(_ context.Context, intent protocol.Intent) error { copy(intent.Settings, []byte(`[]`)); return nil }
	called := false
	implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
		called = true
		return protocol.SafeFacts{}, nil, nil
	}
	var result, status bytes.Buffer
	before := environment.Len()
	if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code == 0 || called || environment.Len() != before {
		t.Fatal("rewritten canonical input reached credentials/effect", code)
	}
}

// full_only: false
func TestCanonicalAndCompatibilityResponsesPreserveExactInput(t *testing.T) {
	for _, condition := range []string{"canonical", "canonical-rewrite", "compatibility", "confirmed-refused"} {
		t.Run(condition, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			var kind, reply uint8
			var body []byte
			if condition == "canonical" || condition == "canonical-rewrite" {
				request := protocol.CanonicalRequest{Schema: 1, Purpose: protocol.CanonicalHistorical, DeadlineUnixMillis: command.DeadlineUnixMillis, Intent: command.Intent}
				request.InputDigest, _ = protocol.CanonicalInputDigest(request)
				body, _ = protocol.EncodeCanonicalRequest(request)
				kind, reply = protocol.KindValidateCanonical, protocol.KindCanonicalValidation
				if condition == "canonical-rewrite" {
					implementation.ValidateCanonical = func(_ context.Context, intent protocol.Intent) error { copy(intent.Settings, []byte(`[]`)); return nil }
				}
			} else {
				original, _ := protocol.EncodeSafeFacts(completeFacts(command))
				request := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: command.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: command.Intent, OriginalFacts: original}
				if condition == "confirmed-refused" {
					request.CompletionClass = protocol.CompletionConfirmed
				}
				request.InputDigest, _ = protocol.RetirementCompatibilityInputDigest(request)
				body, _ = protocol.EncodeRetirementCompatibilityRequest(request)
				kind, reply = protocol.KindRetirementCompatibility, protocol.KindRetirementCompatibilityResult
			}
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(99)})
			id := processID(98)
			var control, environment, result, status bytes.Buffer
			if err := protocol.WriteFrame(&control, protocol.Frame{Kind: protocol.KindHello, CommandID: id, Body: hello}); err != nil {
				t.Fatal(err)
			}
			if err := protocol.WriteFrame(&control, protocol.Frame{Kind: kind, CommandID: id, Body: body}); err != nil {
				t.Fatal(err)
			}
			if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code != 0 {
				t.Fatal("public validation exchange failed", code)
			}
			response, err := protocol.ReadExpectedFrame(&result, reply, id, protocol.MaximumPublicBody)
			if err != nil {
				t.Fatal(err)
			}
			got, err := protocol.DecodeValidationResponse(response)
			if err != nil || got.Accepted != (condition == "canonical" || condition == "compatibility") {
				t.Fatal("validation changed meaning", got.Accepted, err)
			}
		})
	}
}

// full_only: false
func TestRetirementCompatibilityRequiresUsableRetirement(t *testing.T) {
	for _, condition := range []string{"retirement-only", "no-retire", "no-check", "incompatible", "canceled", "wrong-digest"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			implementation := processImplementation()
			implementation.Create = nil
			implementation.Retire = func(context.Context, Invocation) (protocol.SafeFacts, error) {
				t.Fatal("public compatibility check entered retirement")
				return protocol.SafeFacts{}, nil
			}
			checks := 0
			implementation.CheckRetirementCompatibility = func(context.Context, protocol.RetirementCompatibilityRequest) (bool, error) {
				checks++
				if condition == "canceled" {
					cancel()
				}
				return condition != "incompatible", nil
			}
			if condition == "no-retire" {
				implementation.Retire = nil
			}
			if condition == "no-check" {
				implementation.CheckRetirementCompatibility = nil
			}
			command := processCommand(t, implementation)
			original, err := protocol.EncodeSafeFacts(completeFacts(command))
			if err != nil {
				t.Fatal(err)
			}
			request := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: command.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: command.Intent, OriginalFacts: original}
			request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := protocol.EncodeRetirementCompatibilityRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "wrong-digest" {
				body[10] ^= 1 // The digest follows the schema and deadline.
			}
			hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(99)})
			if err != nil {
				t.Fatal(err)
			}
			var control, result, status bytes.Buffer
			id := processID(98)
			for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CommandID: id, Body: hello}, {Kind: protocol.KindRetirementCompatibility, CommandID: id, Body: body}} {
				if err := protocol.WriteFrame(&control, frame); err != nil {
					t.Fatal(err)
				}
			}
			code := run(ctx, &control, bytes.NewReader(nil), &result, &status, implementation, func([]credentialroute.Input) (func() error, error) {
				t.Fatal("public compatibility check installed private input")
				return nil, nil
			})
			if condition == "wrong-digest" {
				if code != exitCommandDecode || checks != 0 || result.Len() != 0 {
					t.Fatal("invalid digest reached compatibility assessment", code, checks)
				}
				return
			}
			wantChecks := 1
			if condition == "no-retire" || condition == "no-check" {
				wantChecks = 0
			}
			if code != exitSuccess || checks != wantChecks {
				t.Fatal("unexpected compatibility exchange", code, checks)
			}
			response, err := protocol.ReadExpectedFrame(&result, protocol.KindRetirementCompatibilityResult, id, protocol.MaximumPublicBody)
			if err != nil {
				t.Fatal(err)
			}
			got, err := protocol.DecodeValidationResponse(response)
			if err != nil || got.Accepted != (condition == "retirement-only") || got.InputDigest != request.InputDigest || protocol.RequireEOF(&result) != nil {
				t.Fatal("unexpected retirement compatibility response", got, err)
			}
		})
	}
}

// full_only: false
func TestRunCallbackFailurePreservesLifecycleStatus(t *testing.T) {
	executionError := errors.New(processToken)
	for _, tc := range []struct {
		name          string
		managed       bool
		contextChange string
		callbackError error
		malformed     bool
		wantCode      int
		wantStatus    protocol.Status
	}{
		{name: "local success", wantStatus: protocol.Status{Stage: 5, Category: 0}},
		{name: "local execution error", callbackError: executionError, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 2}},
		{name: "local protocol error", callbackError: protocol.ErrProtocol, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 1}},
		{name: "local wrapped protocol error", callbackError: errors.Join(executionError, protocol.ErrProtocol), wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 1}},
		{name: "local returned cancellation", callbackError: context.Canceled, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local wrapped cancellation", callbackError: errors.Join(executionError, context.Canceled), wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local returned deadline", callbackError: context.DeadlineExceeded, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local wrapped deadline", callbackError: errors.Join(executionError, context.DeadlineExceeded), wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local cancellation after success", contextChange: "cancelled", wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local cancellation overrides execution error", contextChange: "cancelled", callbackError: executionError, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local cancellation overrides protocol error", contextChange: "cancelled", callbackError: protocol.ErrProtocol, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local deadline after success", contextChange: "expired", wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local deadline overrides execution error", contextChange: "expired", callbackError: executionError, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local deadline overrides protocol error", contextChange: "expired", callbackError: protocol.ErrProtocol, wantCode: 29, wantStatus: protocol.Status{Stage: 3, Category: 3}},
		{name: "local malformed success", malformed: true, wantCode: 30, wantStatus: protocol.Status{Stage: 4, Category: 4}},
		{name: "managed execution error", managed: true, callbackError: executionError, wantCode: 29, wantStatus: protocol.Status{Stage: 4, Category: 2}},
		{name: "managed protocol error", managed: true, callbackError: protocol.ErrProtocol, wantCode: 29, wantStatus: protocol.Status{Stage: 4, Category: 2}},
		{name: "managed returned cancellation", managed: true, callbackError: context.Canceled, wantCode: 29, wantStatus: protocol.Status{Stage: 4, Category: 3}},
		{name: "managed cancellation retains success", managed: true, contextChange: "cancelled", wantStatus: protocol.Status{Stage: 5, Category: 0}},
		{name: "managed deadline retains success", managed: true, contextChange: "expired", wantStatus: protocol.Status{Stage: 5, Category: 0}},
		{name: "managed malformed success", managed: true, malformed: true, wantCode: 30, wantStatus: protocol.Status{Stage: 4, Category: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				implementation := processImplementation()
				command := processCommand(t, implementation)
				if !tc.managed {
					command.LifecycleMode, command.ResourceContractID = protocol.LifecycleNone, protocol.ID{}
					var err error
					command.Intent, err = protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: implementation.ConfigContractID(), LifecycleMode: protocol.LifecycleNone, Settings: []byte(`{}`)})
					if err != nil {
						t.Fatal(err)
					}
					command.IntentDigest, err = protocol.IntentDigest(command.Intent)
					if err != nil {
						t.Fatal(err)
					}
				}
				control, environment, id := processInput(t, implementation, command)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				value := bytes.Repeat([]byte{'s'}, 64)
				copy(value, processValue)
				public := bytes.Repeat([]byte{'p'}, 64)
				var borrowedInput, borrowedIntent []byte
				calls := 0
				implementation.Create = func(callbackContext context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
					calls++
					borrowedInput, borrowedIntent = inv.Inputs[0].Value, inv.Command.Intent
					switch tc.contextChange {
					case "cancelled":
						cancel()
						if callbackContext.Err() != context.Canceled {
							t.Fatal("callback cancellation was not observed")
						}
					case "expired":
						<-callbackContext.Done()
						if callbackContext.Err() != context.DeadlineExceeded {
							t.Fatal("callback deadline was not observed")
						}
					}
					facts := completeFacts(inv.Command)
					facts.ProviderFacts = public[:4]
					if tc.malformed {
						facts.Schema = 99
					}
					return facts, value[:len(processValue)], tc.callbackError
				}
				var result, status bytes.Buffer
				if code := Run(ctx, &control, &environment, &result, &status, implementation); code != tc.wantCode || calls != 1 {
					t.Fatal("callback execution differs", code, tc.wantCode, calls)
				}
				assertCleared(t, value)
				assertCleared(t, public)
				assertCleared(t, borrowedInput)
				assertCleared(t, borrowedIntent)
				if tc.wantCode == 0 {
					got := readResult(t, &result, id)
					if protocol.ValidateResult(command, got) != nil || !bytes.Equal(got.Value, processValue) {
						t.Fatal("successful callback result changed")
					}
				} else if result.Len() != 0 {
					t.Fatal("failed callback emitted result bytes")
				}
				finalStatus(t, &status, id, tc.wantStatus)
			})
		})
	}
}

// full_only: false
func TestHistoricalCanonicalValidationDoesNotRequireEffectCallbacks(t *testing.T) {
	for _, missing := range []string{"normalize", "create", "retire", "compatibility", "all-effect-callbacks"} {
		t.Run(missing, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			switch missing {
			case "normalize":
				implementation.Normalize = nil
			case "create":
				implementation.Create = nil
			case "retire":
				implementation.Retire = nil
			case "compatibility":
				implementation.CheckRetirementCompatibility = nil
			case "all-effect-callbacks":
				implementation.Normalize, implementation.Create, implementation.Retire, implementation.CheckRetirementCompatibility = nil, nil, nil, nil
			}
			request := protocol.CanonicalRequest{Schema: protocol.Schema, Purpose: protocol.CanonicalHistorical, DeadlineUnixMillis: command.DeadlineUnixMillis, Intent: command.Intent}
			request.InputDigest, _ = protocol.CanonicalInputDigest(request)
			body, err := protocol.EncodeCanonicalRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(99)})
			id := processID(98)
			var control, environment, result, status bytes.Buffer
			for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CommandID: id, Body: hello}, {Kind: protocol.KindValidateCanonical, CommandID: id, Body: body}} {
				if err := protocol.WriteFrame(&control, frame); err != nil {
					t.Fatal(err)
				}
			}
			if code := Run(t.Context(), &control, &environment, &result, &status, implementation); code != 0 {
				t.Fatal("historical canonical validation required an unrelated callback", code)
			}
			response, err := protocol.ReadExpectedFrame(&result, protocol.KindCanonicalValidation, id, protocol.MaximumPublicBody)
			if err != nil {
				t.Fatal(err)
			}
			got, err := protocol.DecodeValidationResponse(response)
			if err != nil || !got.Accepted || got.InputDigest != request.InputDigest || protocol.RequireEOF(&result) != nil {
				t.Fatal("historical canonical validation lost exact acceptance", got, err)
			}
		})
	}
}

// full_only: false
func TestFreshCanonicalReadinessChecksApplicableCallbacksWithoutEffects(t *testing.T) {
	for _, mode := range []uint8{protocol.LifecycleNone, protocol.LifecycleManaged} {
		for _, missing := range []string{"none", "normalize", "create", "retire", "compatibility", "validate", "canonical-refused"} {
			t.Run(fmt.Sprintf("lifecycle=%d/%s", mode, missing), func(t *testing.T) {
				implementation := processImplementation()
				intent := protocol.Intent{Schema: protocol.Schema, ConfigContractID: implementation.ConfigContractID(), LifecycleMode: mode, Settings: []byte(`{}`)}
				if mode == protocol.LifecycleManaged {
					intent.ResourceContractID = processID(5)
				}
				encoded, err := protocol.EncodeIntent(intent)
				if err != nil {
					t.Fatal(err)
				}
				effects := 0
				implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
					effects++
					return protocol.SafeFacts{}, nil, protocol.ErrProtocol
				}
				implementation.Retire = func(context.Context, Invocation) (protocol.SafeFacts, error) {
					effects++
					return protocol.SafeFacts{}, protocol.ErrProtocol
				}
				implementation.CheckRetirementCompatibility = func(context.Context, protocol.RetirementCompatibilityRequest) (bool, error) {
					effects++
					return false, protocol.ErrProtocol
				}
				switch missing {
				case "normalize":
					implementation.Normalize = nil
				case "create":
					implementation.Create = nil
				case "retire":
					implementation.Retire = nil
				case "compatibility":
					implementation.CheckRetirementCompatibility = nil
				case "validate":
					implementation.ValidateCanonical = nil
				case "canonical-refused":
					implementation.ValidateCanonical = func(context.Context, protocol.Intent) error { return protocol.ErrProtocol }
				}
				request := protocol.CanonicalRequest{Schema: protocol.Schema, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), Purpose: protocol.CanonicalFreshCreate, Intent: encoded}
				response := processCanonicalResponse(t, implementation, request)
				want := missing != "create" && missing != "validate" && missing != "canonical-refused" && (mode != protocol.LifecycleManaged || missing != "retire" && missing != "compatibility")
				if response.Accepted != want || effects != 0 {
					t.Fatal("fresh readiness changed callback requirements or entered effects", response.Accepted, want, effects)
				}
			})
		}
	}
}

func processCanonicalResponse(t *testing.T, implementation Implementation, request protocol.CanonicalRequest) protocol.ValidationResponse {
	t.Helper()
	var err error
	request.InputDigest, err = protocol.CanonicalInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.EncodeCanonicalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: implementation.Identity().DescriptorID, ArtifactContractID: processID(99)})
	if err != nil {
		t.Fatal(err)
	}
	id := processID(98)
	var control, environment, result, status bytes.Buffer
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CommandID: id, Body: hello}, {Kind: protocol.KindValidateCanonical, CommandID: id, Body: body}} {
		if err := protocol.WriteFrame(&control, frame); err != nil {
			t.Fatal(err)
		}
	}
	if code := Run(t.Context(), &control, &environment, &result, &status, implementation); code != 0 {
		t.Fatal("canonical validation exchange failed", code)
	}
	response, err := protocol.ReadExpectedFrame(&result, protocol.KindCanonicalValidation, id, protocol.MaximumPublicBody)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.DecodeValidationResponse(response)
	if err != nil || got.InputDigest != request.InputDigest || protocol.RequireEOF(&result) != nil {
		t.Fatal("canonical validation lost exact correlation", got, err)
	}
	return got
}

// full_only: false
func TestCreateRequiresApplicableCallbacksBeforePrivateInput(t *testing.T) {
	for _, missing := range []string{"normalize", "validate", "create", "retire", "compatibility"} {
		t.Run(missing, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			control, environment, _ := processInput(t, implementation, command)
			privateLength := environment.Len()
			calls := 0
			implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
				calls++
				return completeFacts(inv.Command), bytes.Clone(processValue), nil
			}
			switch missing {
			case "normalize":
				implementation.Normalize = nil
			case "validate":
				implementation.ValidateCanonical = nil
			case "create":
				implementation.Create = nil
			case "retire":
				implementation.Retire = nil
			case "compatibility":
				implementation.CheckRetirementCompatibility = nil
			}
			var result, status bytes.Buffer
			code := Run(t.Context(), &control, &environment, &result, &status, implementation)
			if missing == "normalize" {
				if code != 0 || calls != 1 || environment.Len() != 0 {
					t.Fatal("CREATE required unrelated normalization", code, calls, environment.Len())
				}
				return
			}
			if code == 0 || calls != 0 || result.Len() != 0 || environment.Len() != privateLength {
				t.Fatal("unsupported CREATE acquired private input or entered effect", code, calls, environment.Len())
			}
		})
	}
}
