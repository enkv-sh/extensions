package output

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

type sampleImplementation struct {
	command                                   Preparation
	prepares, sends, closes, publicCalls      int
	inputs                                    []credentialroute.Input
	payload                                   []byte
	refuse, sendError, wrongResult, badBounds bool
	omitLocator                               bool
	beforeCheck                               func()
	closedWithPrivate                         bool
	normalized                                []byte
	canonical                                 protocol.Destination
	interpreted                               TargetRequest
	checked                                   ActionCheck
	checkedPolicy, preparedPolicy             protocol.Policy
	observedDeadline                          bool
	outcome                                   *Outcome
}

func (*sampleImplementation) Identity() ImplementationIdentity {
	return ImplementationIdentity{ProtocolID: protocol.ProtocolID(), DescriptorID: testID(9)}
}
func (*sampleImplementation) CredentialRoute() credentialroute.Route {
	return credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"TOKEN"}}
}
func (p *sampleImplementation) NormalizeDestination(_ context.Context, settings []byte) (protocol.Destination, error) {
	p.publicCalls++
	p.normalized = bytes.Clone(settings)
	return protocol.Destination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: bytes.Clone(settings), Capabilities: protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot}, nil
}
func (p *sampleImplementation) ValidateCanonical(_ context.Context, destination protocol.Destination) error {
	p.publicCalls++
	p.canonical = destination
	if destination.ConfigContractID != "private-config/v1" {
		return protocol.ErrProtocol
	}
	return nil
}
func (p *sampleImplementation) InterpretTarget(_ context.Context, r TargetRequest) (protocol.Target, error) {
	p.publicCalls++
	p.interpreted = r
	v := testTarget()
	v.PayloadEncoding = r.PayloadEncoding
	return v, nil
}
func (p *sampleImplementation) CheckAction(_ context.Context, r ActionCheck, policy protocol.Policy) (protocol.PayloadBounds, error) {
	p.publicCalls++
	p.checked, p.checkedPolicy = r, policy
	if p.beforeCheck != nil {
		p.beforeCheck()
	}
	if p.badBounds {
		return protocol.PayloadBounds{Maximum: 1}, nil
	}
	if valueAction(r.Action) {
		return protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, nil
	}
	return protocol.PayloadBounds{}, nil
}
func (p *sampleImplementation) Prepare(ctx context.Context, c Preparation, policy protocol.Policy, inputs []credentialroute.Input) (Prepared, error) {
	p.prepares++
	p.command = c
	p.preparedPolicy = policy
	_, p.observedDeadline = ctx.Deadline()
	p.inputs = inputs
	if p.refuse {
		return p, errors.New("private refusal")
	}
	return p, nil
}
func (p *sampleImplementation) Send(_ context.Context, payload []byte) (Outcome, error) {
	p.sends++
	p.payload = payload
	r := Outcome{}
	if p.outcome != nil {
		r = *p.outcome
		if p.sendError {
			return r, errors.New("wrapped: private send failure")
		}
		return r, nil
	}
	r.Entry, r.Class, r.NormalizedStatus = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 201
	r.SafeResourceID = "created-resource"
	if p.omitLocator {
		r.AssignedLocator = ""
	}
	if p.wrongResult {
		r.Class = protocol.OutcomeClass(99)
	}
	if p.sendError {
		return r, errors.New("private send failure")
	}
	return r, nil
}
func (p *sampleImplementation) Close() error {
	p.closes++
	p.closedWithPrivate = len(p.inputs) == 1 && bytes.Equal(p.inputs[0].Value, []byte("credential"))
	return nil
}

type forbiddenRead struct{}

func (forbiddenRead) Read([]byte) (int, error) { panic("private stream read before admission") }
func testFrame(t *testing.T, w io.Writer, kind uint8, id protocol.ID, b []byte) {
	t.Helper()
	if err := protocol.WriteFrame(w, protocol.Frame{Kind: kind, CorrelationID: id, Body: b}); err != nil {
		t.Fatal(err)
	}
}
func testEffect(t *testing.T, action protocol.Action, payload []byte) (Endpoints, *sampleImplementation, protocol.Command) {
	t.Helper()
	c, _ := testCommand(t)
	c.Action = action
	c.PolicyDigest = protocol.ID{}
	c.PolicyContractID = ""
	c.Target.Capabilities = protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot
	if createAction(action) {
		c.OwnedInstance = ""
		c.OwnedBirthAttemptID = protocol.ID{}
		c.BirthTargetRowDigest = protocol.ID{}
	}
	if !valueAction(action) {
		c.PayloadLengthMode = protocol.LengthAbsent
		c.PayloadLength = 0
		c.ValueBasisDigest = protocol.ID{}
	} else {
		c.PayloadLength = uint32(len(payload))
	}
	plugin := new(sampleImplementation)
	routeID, err := credentialroute.Identity(plugin.CredentialRoute())
	if err != nil {
		t.Fatal(err)
	}
	c.CredentialRouteID = protocol.ID(routeID)
	control, credential, value, result := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: c.DescriptorID, ArtifactContractID: testID(31)})
	if err != nil {
		t.Fatal(err)
	}
	testFrame(t, control, protocol.KindHello, c.AttemptID, hello)
	command, err := protocol.EncodeCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	testFrame(t, control, protocol.KindCommand, c.AttemptID, command)
	testFrame(t, control, protocol.KindPolicy, c.AttemptID, nil)
	private, err := credentialroute.EncodeInputs(plugin.CredentialRoute(), []credentialroute.Input{{Name: "TOKEN", Present: true, Value: []byte("credential")}})
	if err != nil {
		t.Fatal(err)
	}
	testFrame(t, credential, protocol.KindCredential, c.AttemptID, private)
	kind := uint8(protocol.KindArm)
	if valueAction(action) {
		kind = protocol.KindPayload
	}
	testFrame(t, value, kind, c.AttemptID, payload)
	return Endpoints{control, credential, value, result}, plugin, c
}
func resultFrom(t *testing.T, e Endpoints, c protocol.Command, ready bool) protocol.Result {
	t.Helper()
	r := e.Result.(*bytes.Buffer)
	if _, err := protocol.ReadExpectedFrame(r, protocol.KindHelloAck, c.AttemptID, protocol.HelloBytes); err != nil {
		t.Fatal(err)
	}
	if !ready {
		if _, err := protocol.ReadExpectedFrame(r, protocol.KindPreparationRefused, c.AttemptID, 0); err != nil {
			t.Fatal(err)
		}
		return protocol.Result{}
	}
	if _, err := protocol.ReadExpectedFrame(r, protocol.KindReadyForPayload, c.AttemptID, 0); err != nil {
		t.Fatal(err)
	}
	b, err := protocol.ReadExpectedFrame(r, protocol.KindResult, c.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	v, err := protocol.DecodeResult(b)
	if err != nil || protocol.RequireEOF(r) != nil {
		t.Fatal("invalid complete result", err)
	}
	return v
}

// full_only: false
func TestServeSingleSendOwnershipAndUncertainty(t *testing.T) {
	for _, condition := range []string{"complete", "send-error", "wrong-result", "refused", "trailing-payload", "cancelled-before-private"} {
		t.Run(condition, func(t *testing.T) {
			e, p, c := testEffect(t, protocol.ActionCreateWithValue, []byte("value"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch condition {
			case "send-error":
				p.sendError = true
			case "wrong-result":
				p.wrongResult = true
			case "refused":
				p.refuse = true
				e.Payload = forbiddenRead{}
			case "trailing-payload":
				e.Payload.(*bytes.Buffer).WriteByte(0)
			case "cancelled-before-private":
				p.beforeCheck = cancel
				e.Credential = forbiddenRead{}
				e.Payload = forbiddenRead{}
			}
			err := Serve(ctx, e, p)
			failed := condition == "trailing-payload" || condition == "cancelled-before-private"
			if (err != nil) != failed {
				t.Fatal("unexpected serving status", err)
			}
			wantSends := 1
			if failed || condition == "refused" {
				wantSends = 0
			}
			if p.sends != wantSends {
				t.Fatal("wrong physical callback count", p.sends)
			}
			if condition == "cancelled-before-private" {
				if p.prepares != 0 || p.closes != 0 {
					t.Fatal("cancelled preparation entered")
				}
				return
			}
			if p.prepares != 1 || p.closes != 1 || !p.closedWithPrivate || !bytes.Equal(p.inputs[0].Value, make([]byte, len(p.inputs[0].Value))) || !bytes.Equal(p.payload, make([]byte, len(p.payload))) {
				t.Fatal("private ownership/close/disposal changed")
			}
			if failed {
				return
			}
			r := resultFrom(t, e, c, condition != "refused")
			if condition == "send-error" || condition == "wrong-result" {
				if r.Class != protocol.ClassUnproved || r.Entry != protocol.EntryMayHaveEntered || r.ConsumerLocator != "" {
					t.Fatal("failed send was not unknown")
				}
			} else if condition == "complete" && protocol.ValidateResult(c, r) != nil {
				t.Fatal("complete result lost binding")
			}
		})
	}
}

// full_only: false
func TestServeEmptyValueAndMetadataArmAreDistinct(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionCreateWithValue} {
		t.Run(map[protocol.Action]string{protocol.ActionCreateEmpty: "metadata", protocol.ActionCreateWithValue: "empty-value"}[action], func(t *testing.T) {
			e, p, c := testEffect(t, action, nil)
			if err := Serve(context.Background(), e, p); err != nil {
				t.Fatal(err)
			}
			if (p.payload == nil) != (action == protocol.ActionCreateEmpty) {
				t.Fatal("empty value became metadata arm")
			}
			if protocol.ValidateResult(c, resultFrom(t, e, c, true)) != nil {
				t.Fatal("result invalid")
			}
		})
	}
}

// full_only: false
func TestPublicOperationsBindUnknownSemanticsWithoutPrivateEntry(t *testing.T) {
	p := new(sampleImplementation)
	id := testID(7)
	d := protocol.Destination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: []byte(`{"unknown-setting":true}`), Capabilities: protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot}
	normal := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Settings: bytes.Clone(d.CanonicalSettings)}
	canonical := protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: d}
	interpret := protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: d, EntryName: "", PayloadEncoding: protocol.EncodingBase64}
	c, _ := testCommand(t)
	check := c.ActionCheck()
	check.PolicyDigest = protocol.ID{}
	check.PolicyContractID = ""
	for _, kind := range []uint8{protocol.KindNormalizeRequest, protocol.KindCanonicalRequest, protocol.KindInterpretRequest, protocol.KindActionCheckRequest} {
		t.Run(map[uint8]string{protocol.KindNormalizeRequest: "normalize", protocol.KindCanonicalRequest: "canonical", protocol.KindInterpretRequest: "interpret", protocol.KindActionCheckRequest: "action-check"}[kind], func(t *testing.T) {
			var request []byte
			var err error
			switch kind {
			case protocol.KindNormalizeRequest:
				request, err = protocol.EncodeNormalizeRequest(normal)
			case protocol.KindCanonicalRequest:
				request, err = protocol.EncodeCanonicalRequest(canonical)
			case protocol.KindInterpretRequest:
				request, err = protocol.EncodeInterpretRequest(interpret)
			case protocol.KindActionCheckRequest:
				request, err = protocol.EncodeActionCheckRequest(check)
			}
			if err != nil {
				t.Fatal(err)
			}
			control, result := new(bytes.Buffer), new(bytes.Buffer)
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: testID(9), ArtifactContractID: testID(31)})
			testFrame(t, control, protocol.KindHello, id, hello)
			testFrame(t, control, kind, id, request)
			if kind == protocol.KindActionCheckRequest {
				testFrame(t, control, protocol.KindPolicy, id, nil)
			}
			if err := ServePublic(context.Background(), PublicEndpoints{control, result}, p); err != nil {
				t.Fatal(err)
			}
			if _, err := protocol.ReadExpectedFrame(result, protocol.KindHelloAck, id, protocol.HelloBytes); err != nil {
				t.Fatal(err)
			}
			frame, err := protocol.ReadFrame(result, protocol.MaximumPublicResultBytes)
			if err != nil || protocol.RequireEOF(result) != nil {
				t.Fatal("passive complete frame", err)
			}
			switch kind {
			case protocol.KindNormalizeRequest:
				v, err := protocol.DecodeNormalizeResult(frame.Body)
				if err != nil || !v.Accepted || protocol.ValidateNormalizeResult(id, normal, v) != nil || !bytes.Equal(v.Destination.CanonicalSettings, normal.Settings) {
					t.Fatal("normalization lost input", err)
				}
				v.RequestDigest = testID(99)
				if protocol.ValidateNormalizeResult(id, normal, v) == nil {
					t.Fatal("wrong normalization digest accepted")
				}
			case protocol.KindCanonicalRequest:
				v, err := protocol.DecodeCanonicalResult(frame.Body)
				if err != nil || !v.Accepted || protocol.ValidateCanonicalResult(id, canonical, v) != nil {
					t.Fatal("canonical result", err)
				}
			case protocol.KindInterpretRequest:
				v, err := protocol.DecodeInterpretResult(frame.Body)
				if err != nil || !v.Accepted || protocol.ValidateInterpretResponse(id, interpret, v) != nil || v.Target.PayloadEncoding != protocol.EncodingBase64 {
					t.Fatal("interpretation result", err)
				}
			case protocol.KindActionCheckRequest:
				v, err := protocol.DecodeActionCheckResult(frame.Body)
				if err != nil || !v.Accepted || protocol.ValidateActionCheckResponse(id, check, protocol.Policy{}, v) != nil {
					t.Fatal("action result", err)
				}
			}
		})
	}
	if p.prepares != 0 || p.sends != 0 || p.closes != 0 || p.publicCalls != 4 {
		t.Fatal("passive operation reached effect lifetime")
	}
	if !reflect.DeepEqual(d.CanonicalSettings, []byte(`{"unknown-setting":true}`)) {
		t.Fatal("passive mutated caller input")
	}
}

func testID(b byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = b
	}
	return id
}
func testTarget() protocol.Target {
	return protocol.Target{ServiceContractID: "private-service/v1", TargetContractID: "private-key/v1", CanonicalTarget: "local/account/key", ConsumerLocator: "local/account/key", TargetData: []byte{1, 2, 3}, PayloadEncoding: protocol.EncodingRaw, Capabilities: (protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot), CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}
}
func testCommand(t *testing.T) (protocol.Command, protocol.Policy) {
	t.Helper()
	p := protocol.Policy{ContractID: "private-policy/v1", Data: []byte("opaque\x00policy")}
	digest, err := protocol.PolicyDigest(testID(1), p)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{Schema: 1, Action: protocol.ActionWriteValue, DomainID: testID(1), OperationID: testID(2), AttemptID: testID(3), CoordinateID: testID(4), ProjectionCommitment: testID(5), DispatchContextDigest: testID(6), RequestContractDigest: testID(7), ResponseContractDigest: testID(8), DescriptorID: testID(9), CredentialRouteID: testID(10), PolicyDigest: digest, BindingIncarnationID: testID(11), EntryIncarnationID: testID(12), TargetRowDigest: testID(13), BirthTargetRowDigest: testID(14), OwnedBirthAttemptID: testID(15), ValueBasisDigest: testID(16), DeadlineUnixMillis: 4102444800000, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5, BindingDestinationID: "private", OwnedInstance: "owned", ConditionalToken: "token", PolicyContractID: p.ContractID, Target: testTarget()}, p
}

func createAction(action protocol.Action) bool {
	return action == protocol.ActionCreateEmpty || action == protocol.ActionCreateWithValue
}

func valueAction(action protocol.Action) bool {
	return action == protocol.ActionCreateWithValue || action == protocol.ActionWriteValue
}

// full_only: false
func TestPublicWrongCorrelationAndExpiredDeadlineDoNotEnterCallbacks(t *testing.T) {
	for _, condition := range []string{"correlation", "deadline", "trailing", "descriptor"} {
		t.Run(condition, func(t *testing.T) {
			p := new(sampleImplementation)
			id := testID(7)
			request := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Settings: []byte(`{}`)}
			if condition == "deadline" {
				request.DeadlineUnixMillis = 1
			}
			body, err := protocol.EncodeNormalizeRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			control, result := new(bytes.Buffer), new(bytes.Buffer)
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: testID(9), ArtifactContractID: testID(31)})
			testFrame(t, control, protocol.KindHello, id, hello)
			next := id
			if condition == "correlation" {
				next = testID(8)
			}

			if condition == "descriptor" {
				c, policy := testCommand(t)
				q := c.ActionCheck()
				q.DescriptorID = testID(99)
				body, err = protocol.EncodeActionCheckRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				testFrame(t, control, protocol.KindActionCheckRequest, next, body)
				testFrame(t, control, protocol.KindPolicy, next, policy.Data)
			} else {
				testFrame(t, control, protocol.KindNormalizeRequest, next, body)
			}
			if condition == "trailing" {
				control.WriteByte(0)
			}
			if ServePublic(context.Background(), PublicEndpoints{control, result}, p) == nil || p.publicCalls != 0 || p.prepares != 0 {
				t.Fatal("invalid public exchange reached callback")
			}
		})
	}
}

// full_only: false
func TestAuthorOutcomesValidateEvidenceAndRuntimeCorrelation(t *testing.T) {
	testOutcomeConstructors(t)
	testOutcomeAdmission(t)
	e, p, c := testEffect(t, protocol.ActionCreateWithValue, []byte("value"))
	p.omitLocator = true
	if err := Serve(context.Background(), e, p); err != nil {
		t.Fatal(err)
	}
	got := resultFrom(t, e, c, true)
	if got.Class != protocol.ClassAcknowledged || got.ConsumerLocator != c.Target.ConsumerLocator || protocol.ValidateResult(c, got) != nil {
		t.Fatal("runtime did not bind static creation locator and exact command", got)
	}
}

// full_only: false
func TestAuthorInputsKeepServiceFactsWithoutTransport(t *testing.T) {
	testExactAuthorFacts(t)
	api := reflect.TypeFor[Implementation]()
	for _, name := range []string{"NormalizeDestination", "ValidateCanonical", "InterpretTarget", "CheckAction", "Prepare"} {
		method, ok := api.MethodByName(name)
		if !ok {
			t.Fatal("missing callback", name)
		}
		input := method.Type.In(1)
		if input.Kind() != reflect.Struct {
			continue
		}
		for _, field := range []string{"Schema", "DeadlineUnixMillis", "DomainID", "DescriptorID", "CredentialRouteID", "OperationID", "CoordinateID", "RequestContractDigest", "ResponseContractDigest"} {
			if _, ok := input.FieldByName(field); ok {
				t.Errorf("callback %s exposes transport field %s", name, field)
			}
		}
	}
}

func (p *sampleImplementation) SelectPolicyAction(context.Context, PolicyActionSelection, protocol.Policy) (protocol.Action, error) {
	p.publicCalls++
	return 0, protocol.ErrProtocol
}

type selectingImplementation struct {
	sampleImplementation
	action     protocol.Action
	refusal    error
	selection  PolicyActionSelection
	policy     protocol.Policy
	selections int
}

func (p *selectingImplementation) SelectPolicyAction(ctx context.Context, r PolicyActionSelection, policy protocol.Policy) (protocol.Action, error) {
	p.selections++
	p.selection = r
	p.selection.Target.TargetData = bytes.Clone(r.Target.TargetData)
	p.policy = protocol.Policy{ContractID: policy.ContractID, Data: bytes.Clone(policy.Data)}
	_, p.observedDeadline = ctx.Deadline()
	return p.action, p.refusal
}

// full_only: false
func TestPolicyActionServingKeepsPublicSelectionClosedAndCorrelated(t *testing.T) {
	for _, condition := range []string{"write", "metadata", "refused", "invalid-action", "missing-capability", "wrong-policy-digest", "wrong-descriptor", "wrong-correlation", "trailing", "expired"} {
		t.Run(condition, func(t *testing.T) {
			p := &selectingImplementation{action: protocol.ActionWriteValue}
			policy := protocol.Policy{ContractID: "private-policy/v1", Data: []byte("public policy")}
			request := protocol.PolicyActionRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, DomainID: testID(1), DescriptorID: p.Identity().DescriptorID, PreviousPolicyDigest: testID(20), HasPreviousPolicyDigest: true, PolicyContractID: policy.ContractID, Target: testTarget()}
			request.Target.Capabilities |= protocol.CapabilityWriteSetsPolicy
			var err error
			request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "metadata":
				p.action = protocol.ActionUpdatePolicy
			case "refused":
				p.action = 0
				p.refusal = errors.New("private refusal")
			case "invalid-action":
				p.action = protocol.ActionDeleteOwned
			case "missing-capability":
				request.Target.Capabilities &^= protocol.CapabilityWriteSetsPolicy
			case "wrong-policy-digest":
				request.PolicyDigest = testID(21)
			case "wrong-descriptor":
				request.DescriptorID = testID(22)
			case "expired":
				request.DeadlineUnixMillis = 1
			}
			body, err := protocol.EncodePolicyActionRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			id := testID(7)
			hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: p.Identity().DescriptorID, ArtifactContractID: testID(31)})
			control, result := new(bytes.Buffer), new(bytes.Buffer)
			testFrame(t, control, protocol.KindHello, id, hello)
			requestID := id
			if condition == "wrong-correlation" {
				requestID = testID(23)
			}
			testFrame(t, control, protocol.KindPolicyActionRequest, requestID, body)
			testFrame(t, control, protocol.KindPolicy, id, policy.Data)
			if condition == "trailing" {
				control.WriteByte(0)
			}
			err = ServePublic(t.Context(), PublicEndpoints{Control: control, Result: result}, p)
			invalid := condition == "wrong-policy-digest" || condition == "wrong-descriptor" || condition == "wrong-correlation" || condition == "trailing" || condition == "expired"
			if (err != nil) != invalid {
				t.Fatal("public selection completion", err)
			}
			if p.prepares != 0 || p.sends != 0 || p.closes != 0 || p.selections != map[bool]int{true: 0, false: 1}[invalid] {
				t.Fatal("selection entered wrong lifetime", p.selections, p.prepares, p.sends, p.closes)
			}
			if invalid {
				return
			}
			if !p.observedDeadline || p.selection.DomainID != request.DomainID || p.selection.PreviousPolicyDigest != request.PreviousPolicyDigest || !p.selection.HasPreviousPolicyDigest || !reflect.DeepEqual(p.selection.Target, request.Target) || !reflect.DeepEqual(p.policy, policy) {
				t.Fatal("selector did not receive exact public facts")
			}
			if _, err := protocol.ReadExpectedFrame(result, protocol.KindHelloAck, id, protocol.HelloBytes); err != nil {
				t.Fatal(err)
			}
			encoded, err := protocol.ReadExpectedFrame(result, protocol.KindPolicyActionResult, id, 36)
			if err != nil || protocol.RequireEOF(result) != nil {
				t.Fatal("selection result framing", err)
			}
			got, err := protocol.DecodePolicyActionResult(encoded)
			accepted := condition == "write" || condition == "metadata"
			if err != nil || got.Accepted != accepted || protocol.ValidatePolicyActionResponse(id, request, policy, got) != nil {
				t.Fatal("selection result", got, err)
			}
			if accepted && got.Action != p.action || !accepted && got.Action != 0 {
				t.Fatal("selection escaped closed union", got)
			}
		})
	}
}
