package output

import (
	"bytes"
	"context"
	"enkv.sh/sdk/artifact/credentialroute"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

type implementation struct {
	publicCalls, credentialCalls, executeCalls, closeCalls int
	credential, payload                                    []byte
	refusal, executionError, invalidResult                 bool
	expectNativeEnvironment                                bool
	onPublic, onPrepare, onExecute                         func()
	command                                                Preparation
}

func (*implementation) Identity() ImplementationIdentity {
	return ImplementationIdentity{ProtocolID: protocol.ProtocolID(), DescriptorID: protocol.ID{9}}
}
func (*implementation) CredentialRoute() credentialroute.Route {
	return credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"TOKEN"}}
}
func (p *implementation) public() {
	p.publicCalls++
	if p.onPublic != nil {
		p.onPublic()
	}
}
func (p *implementation) NormalizeDestination(_ context.Context, settings []byte) (protocol.Destination, error) {
	p.public()
	return protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: bytes.Clone(settings), Capabilities: (protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue)}, nil
}
func (p *implementation) ValidateCanonical(context.Context, protocol.Destination) error {
	p.public()
	return nil
}
func (p *implementation) InterpretTarget(context.Context, TargetRequest) (protocol.Target, error) {
	p.public()
	return protocol.Target{}, nil
}
func (p *implementation) CheckAction(_ context.Context, r ActionCheck, _ protocol.Policy) (protocol.PayloadBounds, error) {
	p.public()
	if r.Action == protocol.ActionCreateWithValue {
		return protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, nil
	}
	return protocol.PayloadBounds{}, nil
}
func (p *implementation) Prepare(_ context.Context, c Preparation, _ protocol.Policy, inputs []credentialroute.Input) (Prepared, error) {
	p.credentialCalls++
	if p.onPrepare != nil {
		p.onPrepare()
	}
	p.command = c
	if len(inputs) != 1 {
		return nil, errors.New("missing private input")
	}
	p.credential = inputs[0].Value
	if p.expectNativeEnvironment && os.Getenv("TOKEN") != "credential" {
		return nil, errors.New("native environment missing")
	}
	if p.refusal {
		return p, errors.New("synthetic refusal")
	}
	return p, nil
}
func (p *implementation) Send(_ context.Context, payload []byte) (Outcome, error) {
	p.executeCalls++
	p.payload = payload
	if p.onExecute != nil {
		p.onExecute()
	}
	r := Outcome{}
	r.Entry, r.Class, r.NormalizedStatus = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 201
	r.SafeResourceID = "created-resource"
	if p.invalidResult {
		r.Class = protocol.OutcomeClass(99)
	}
	if p.executionError {
		return r, errors.New("private callback error")
	}
	return r, nil
}
func (p *implementation) Close() error { p.closeCalls++; return nil }
func fixture(t *testing.T, passive bool, action protocol.Action, value []byte) (Endpoints, protocol.Command) {
	t.Helper()
	p := new(implementation)
	routeID, err := credentialroute.Identity(p.CredentialRoute())
	if err != nil {
		t.Fatal(err)
	}
	c := protocol.Command{Schema: 1, Action: action, DomainID: protocol.ID{1}, OperationID: protocol.ID{2}, AttemptID: protocol.ID{3}, CoordinateID: protocol.ID{4}, ProjectionCommitment: protocol.ID{5}, DispatchContextDigest: protocol.ID{6}, RequestContractDigest: protocol.ID{7}, ResponseContractDigest: protocol.ID{8}, DescriptorID: protocol.ID{9}, CredentialRouteID: protocol.ID(routeID), BindingIncarnationID: protocol.ID{11}, EntryIncarnationID: protocol.ID{12}, TargetRowDigest: protocol.ID{13}, DeadlineUnixMillis: 4102444800000, BindingDestinationID: "destination", Target: protocol.Target{ServiceContractID: "private-service", TargetContractID: "private-target", CanonicalTarget: "account/resource", ConsumerLocator: "account/resource", TargetData: []byte("public"), PayloadEncoding: protocol.EncodingRaw, Capabilities: (protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue), CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}}
	if action == protocol.ActionCreateWithValue {
		c.PayloadLengthMode = protocol.LengthExact
		c.PayloadLength = uint32(len(value))
		c.ValueBasisDigest = protocol.ID{14}
	}
	control, credential, payload, result := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	frame := func(w io.Writer, kind uint8, body []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.WriteFrame(w, protocol.Frame{Kind: kind, CorrelationID: c.AttemptID, Body: body}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: c.DescriptorID, ArtifactContractID: protocol.ID{31}})
	frame(control, protocol.KindHello, b, err)
	if passive {
		b, err = protocol.EncodeNormalizeRequest(protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: c.DeadlineUnixMillis, Settings: []byte(`{"private":true}`)})
		frame(control, protocol.KindNormalizeRequest, b, err)
	} else {
		b, err = protocol.EncodeCommand(c)
		frame(control, protocol.KindCommand, b, err)
		frame(control, protocol.KindPolicy, nil, nil)
	}
	b, err = credentialroute.EncodeInputs(p.CredentialRoute(), []credentialroute.Input{{Name: "TOKEN", Present: true, Value: []byte("credential")}})
	frame(credential, protocol.KindCredential, b, err)
	kind := uint8(protocol.KindArm)
	if action == protocol.ActionCreateWithValue {
		kind = protocol.KindPayload
	}
	frame(payload, kind, value, nil)
	return Endpoints{Control: control, Credential: credential, Payload: payload, Result: result}, c
}
func publicEndpoints(e Endpoints) PublicEndpoints {
	return PublicEndpoints{Control: e.Control, Result: e.Result}
}
func zeroed(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

// full_only: false
func TestRunStatusOwnershipAndUncertainty(t *testing.T) {
	for _, condition := range []string{"complete", "credential refusal", "callback error", "invalid result", "cancelled after entry"} {
		t.Run(condition, func(t *testing.T) {
			e, c := fixture(t, false, protocol.ActionCreateWithValue, []byte("private payload"))
			p := new(implementation)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch condition {
			case "credential refusal":
				p.refusal = true
				e.Payload = forbiddenReader{}
			case "callback error":
				p.executionError = true
			case "invalid result":
				p.invalidResult = true
			case "cancelled after entry":
				p.onExecute = cancel
			}
			if got := Run(ctx, e, p); got != 0 {
				t.Fatalf("status=%d", got)
			}
			if !zeroed(p.credential) || !zeroed(p.payload) {
				t.Fatal("protocol-owned private bytes remain")
			}
			r := e.Result.(*bytes.Buffer)
			if _, err := protocol.ReadExpectedFrame(r, protocol.KindHelloAck, c.AttemptID, protocol.HelloBytes); err != nil {
				t.Fatal(err)
			}
			if p.refusal {
				if p.executeCalls != 0 {
					t.Fatal("refusal executed")
				}
				if _, err := protocol.ReadExpectedFrame(r, protocol.KindPreparationRefused, c.AttemptID, 0); err != nil {
					t.Fatal(err)
				}
			} else {
				if p.executeCalls != 1 {
					t.Fatalf("calls=%d", p.executeCalls)
				}
				if _, err := protocol.ReadExpectedFrame(r, protocol.KindReadyForPayload, c.AttemptID, 0); err != nil {
					t.Fatal(err)
				}
				b, err := protocol.ReadExpectedFrame(r, protocol.KindResult, c.AttemptID, protocol.MaximumResultBytes)
				if err != nil {
					t.Fatal(err)
				}
				got, err := protocol.DecodeResult(b)
				if err != nil {
					t.Fatal(err)
				}
				want := c.NewResult()
				want.Entry = protocol.EntryMayHaveEntered
				if condition == "complete" || condition == "cancelled after entry" {
					want.Class, want.NormalizedStatus = protocol.ClassAcknowledged, 201
					want.SafeResourceID = "created-resource"
					want.ConsumerLocator = c.Target.ConsumerLocator
				}
				if got != want {
					t.Fatal("result evidence changed")
				}
			}
			if protocol.RequireEOF(r) != nil {
				t.Fatal("trailing result")
			}
		})
	}
}

type forbiddenReader struct{}

func (forbiddenReader) Read([]byte) (int, error) { panic("prohibited private read") }

type closeObserved struct {
	bytes.Buffer
	closed bool
}

func (p *closeObserved) Close() error { p.closed = true; return nil }

// full_only: false
func TestRunBorrowsStreamsAndRejectsNilArguments(t *testing.T) {
	const ambientToken = "ambient-token"
	t.Setenv("TOKEN", ambientToken)
	for _, passive := range []bool{false, true} {
		t.Run(map[bool]string{false: "action", true: "passive"}[passive], func(t *testing.T) {
			e, _ := fixture(t, passive, protocol.ActionCreateWithValue, nil)
			control, credential, payload, result := new(closeObserved), new(closeObserved), new(closeObserved), new(closeObserved)
			for _, row := range []struct {
				dst *closeObserved
				src io.Reader
			}{{control, e.Control}, {credential, e.Credential}, {payload, e.Payload}} {
				if _, err := io.Copy(row.dst, row.src); err != nil {
					t.Fatal(err)
				}
			}
			e.Control, e.Credential, e.Payload, e.Result = control, credential, payload, result
			p := new(implementation)
			environmentChecks := 0
			checkAmbient := func() {
				environmentChecks++
				if value, present := os.LookupEnv("TOKEN"); !present || value != ambientToken {
					t.Fatal("in-process serving changed ambient environment")
				}
			}
			p.onPublic, p.onPrepare, p.onExecute = checkAmbient, checkAmbient, checkAmbient
			if passive {
				if got := RunPublic(context.Background(), publicEndpoints(e), p); got != 0 {
					t.Fatalf("status=%d", got)
				}
			} else {
				if got := Run(context.Background(), e, p); got != 0 {
					t.Fatalf("status=%d", got)
				}
			}
			wantChecks := 3
			if passive {
				wantChecks = 1
			}
			if environmentChecks != wantChecks {
				t.Fatal("environment callback checks missing", environmentChecks)
			}
			checkAmbient()
			if control.closed || credential.closed || payload.closed || result.closed {
				t.Fatal("borrowed stream closed")
			}
			if passive && (p.executeCalls != 0 || p.credentialCalls != 0) {
				t.Fatal("passive reached private callback")
			}
			missingArguments := []string{"context", "implementation", "typed implementation", "control", "typed control", "result", "typed result"}
			if !passive {
				missingArguments = append(missingArguments, "credential", "payload")
			}
			for _, missing := range missingArguments {
				t.Run(missing, func(t *testing.T) {
					e, _ := fixture(t, passive, protocol.ActionCreateWithValue, nil)
					p := new(implementation)
					ctx := context.Background()
					var impl Implementation = p
					switch missing {
					case "context":
						ctx = nil
					case "implementation":
						impl = nil
					case "typed implementation":
						var absent *implementation
						impl = absent
					case "control":
						e.Control = nil
					case "typed control":
						var absent *bytes.Buffer
						e.Control = absent
					case "typed result":
						var absent *bytes.Buffer
						e.Result = absent
					case "result":
						e.Result = nil
					case "credential":
						e.Credential = nil
					case "payload":
						e.Payload = nil
					}
					var got int
					if passive {
						got = RunPublic(ctx, publicEndpoints(e), impl)
					} else {
						got = Run(ctx, e, impl)
					}
					if got != 2 || p.publicCalls != 0 || p.credentialCalls != 0 || p.executeCalls != 0 {
						t.Fatalf("invalid argument status=%d", got)
					}
				})
			}
		})
	}
}

type failAfter struct {
	bytes.Buffer
	remaining int
	writes    int
}

func (w *failAfter) Write(b []byte) (int, error) {
	w.writes++
	if len(b) > w.remaining {
		n := w.remaining
		w.remaining = 0
		_, _ = w.Buffer.Write(b[:n])
		return n, errors.New("synthetic interrupted write")
	}
	w.remaining -= len(b)
	return w.Buffer.Write(b)
}

// full_only: false
func TestRunFailureDisposesPrivateBytesWithoutRetry(t *testing.T) {
	for _, condition := range []string{"cancelled before entry", "payload trailing byte", "result partial write"} {
		t.Run(condition, func(t *testing.T) {
			e, _ := fixture(t, false, protocol.ActionCreateWithValue, []byte("private payload"))
			p := new(implementation)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch condition {
			case "cancelled before entry":
				cancel()
				e.Credential = forbiddenReader{}
				e.Payload = forbiddenReader{}
			case "payload trailing byte":
				e.Payload.(*bytes.Buffer).WriteByte(0)
			case "result partial write":
				e.Result = &failAfter{remaining: protocol.HeaderLength + protocol.HelloBytes + protocol.HeaderLength + 1}
			}
			if got := Run(ctx, e, p); got != 1 {
				t.Fatalf("status=%d", got)
			}
			want := 0
			if condition == "result partial write" {
				want = 1
			}
			if p.executeCalls != want || !zeroed(p.credential) || !zeroed(p.payload) {
				t.Fatal("failure retried or retained private bytes")
			}
		})
	}
}

// full_only: false
func TestRunCancellationWaitsForCallbackBeforeDisposal(t *testing.T) {
	e, _ := fixture(t, false, protocol.ActionCreateWithValue, []byte("private payload"))
	p := new(implementation)
	entered, release := make(chan struct{}), make(chan struct{})
	p.onExecute = func() { close(entered); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- Run(ctx, e, p) }()
	released, joined := false, false
	defer func() {
		if !released {
			close(release)
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("serving did not join")
			}
		}
	}()
	select {
	case <-entered:
	case code := <-done:
		joined = true
		t.Fatalf("serving returned before callback: %d", code)
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not enter")
	}
	cancel()
	if !bytes.Equal(p.payload, []byte("private payload")) || !bytes.Equal(p.credential, []byte("credential")) {
		t.Fatal("private bytes disposed while callback owns them")
	}
	select {
	case <-done:
		joined = true
		t.Fatal("serving returned before callback joined")
	default:
	}
	close(release)
	released = true
	select {
	case got := <-done:
		joined = true
		if got != 0 {
			t.Fatalf("late original result status=%d", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serving did not join after callback release")
	}
	if !zeroed(p.payload) || !zeroed(p.credential) {
		t.Fatal("private bytes remain after callback joined")
	}
}

func (p *implementation) SelectPolicyAction(context.Context, PolicyActionSelection, protocol.Policy) (protocol.Action, error) {
	p.public()
	return 0, protocol.ErrProtocol
}
