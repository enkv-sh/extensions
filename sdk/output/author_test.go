package output

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

type outcomeRunImplementation struct {
	*implementation
	outcome Outcome
	err     error
}

func (p *outcomeRunImplementation) Prepare(ctx context.Context, c Preparation, policy protocol.Policy, inputs []credentialroute.Input) (Prepared, error) {
	_, err := p.implementation.Prepare(ctx, c, policy, inputs)
	return p, err
}

func (p *outcomeRunImplementation) Send(context.Context, []byte) (Outcome, error) {
	p.executeCalls++
	return p.outcome, p.err
}

// full_only: false
func TestRunKeepsCallbackErrorSeparateFromNoEffectEvidence(t *testing.T) {
	for _, row := range []struct {
		name    string
		outcome Outcome
		err     error
		entry   protocol.EntryState
		class   protocol.OutcomeClass
		status  uint16
	}{
		{"proved-no-effect", Outcome{Entry: protocol.EntryNotEntered, Class: protocol.ClassQualifiedNoEffect}, nil, protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect, 0},
		{"same-outcome-with-error", Outcome{Entry: protocol.EntryNotEntered, Class: protocol.ClassQualifiedNoEffect}, context.Canceled, protocol.EntryMayHaveEntered, protocol.ClassUnproved, 0},
		{"opaque-acknowledgement", Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 7, SafeResourceID: "created-resource"}, nil, protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 7},
		{"acknowledgement-without-resource", Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 7}, nil, protocol.EntryMayHaveEntered, protocol.ClassUnproved, 0},
		{"invalid-unproved-status", Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassUnproved, NormalizedStatus: 7}, nil, protocol.EntryMayHaveEntered, protocol.ClassUnproved, 0},
		{"invalid-callback-result", Outcome{Entry: protocol.EntryMayHaveEntered, Class: 99}, errors.New("private callback failure"), protocol.EntryMayHaveEntered, protocol.ClassUnproved, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			e, c := fixture(t, false, protocol.ActionCreateWithValue, []byte("value"))
			p := &outcomeRunImplementation{implementation: new(implementation), outcome: row.outcome, err: row.err}
			if code := Run(t.Context(), e, p); code != 0 {
				t.Fatal("complete serving exchange failed", code)
			}
			got := resultFrom(t, e, c, true)
			if got.Entry != row.entry || got.Class != row.class || got.NormalizedStatus != row.status || protocol.ValidateResult(c, got) != nil {
				t.Fatal("serving changed independent expected evidence", got)
			}
			if p.executeCalls != 1 || p.closeCalls != 1 || !zeroed(p.credential) {
				t.Fatal("serving did not close and dispose its single callback")
			}
		})
	}
}

func testOutcomeConstructors(t *testing.T) {
	t.Helper()
	for _, row := range []struct {
		name  string
		build func() (Outcome, error)
		valid bool
	}{
		{"ack", func() (Outcome, error) { return Acknowledged(201, "request", "resource", "") }, true},
		{"ack-zero-status", func() (Outcome, error) { return Acknowledged(0, "", "", "") }, false},
		{"safe-id-bound", func() (Outcome, error) {
			return Acknowledged(201, strings.Repeat("r", 1024), strings.Repeat("s", 1024), strings.Repeat("l", 1024))
		}, true},
		{"safe-id-over-bound", func() (Outcome, error) { return Acknowledged(201, strings.Repeat("r", 1025), "", "") }, false},
		{"resource-over-bound", func() (Outcome, error) { return Acknowledged(201, "", strings.Repeat("r", 1025), "") }, false},
		{"locator-over-bound", func() (Outcome, error) { return Acknowledged(201, "", "", strings.Repeat("l", 1025)) }, false},
		{"invalid-utf8", func() (Outcome, error) { return Acknowledged(201, "", string([]byte{255}), "") }, false},
		{"no-effect-before", func() (Outcome, error) { return QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "") }, true},
		{"no-effect-after", func() (Outcome, error) { return QualifiedNoEffect(protocol.EntryMayHaveEntered, 412, "request", "") }, true},
		{"no-effect-invalid-entry", func() (Outcome, error) { return QualifiedNoEffect(protocol.EntryState(9), 412, "", "") }, false},
		{"unknown-before", func() (Outcome, error) { return Unknown(protocol.EntryNotEntered) }, true},
		{"unknown-after", func() (Outcome, error) { return Unknown(protocol.EntryMayHaveEntered) }, true},
		{"unknown-invalid-entry", func() (Outcome, error) { return Unknown(protocol.EntryState(0)) }, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, err := row.build()
			if (err == nil) != row.valid || row.valid && !got.Valid() {
				t.Fatal("constructor evidence admission changed", err)
			}
		})
	}
}

func testOutcomeAdmission(t *testing.T) {
	t.Helper()
	for _, row := range []struct {
		name                string
		outcome             Outcome
		assigned, sendError bool
		ack                 bool
	}{
		{name: "static", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "created-resource"}, ack: true},
		{name: "assigned", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "created-resource", AssignedLocator: "service/acknowledged-reference"}, assigned: true, ack: true},
		{name: "static-missing-resource", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201}},
		{name: "assigned-missing-resource", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, AssignedLocator: "service/acknowledged-reference"}, assigned: true},
		{name: "assigned-missing", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "created-resource"}, assigned: true},
		{name: "static-unexpected-assignment", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "created-resource", AssignedLocator: "other"}},
		{name: "invalid-class", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.OutcomeClass(3)}},
		{name: "invalid-entry", outcome: Outcome{Entry: protocol.EntryState(3), Class: protocol.ClassAcknowledged, NormalizedStatus: 201}},
		{name: "ack-with-error", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201}, sendError: true},
		{name: "no-effect-with-error", outcome: Outcome{Entry: protocol.EntryNotEntered, Class: protocol.ClassQualifiedNoEffect}, sendError: true},
		{name: "unknown-with-status", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassUnproved, NormalizedStatus: 204}},
		{name: "unknown-with-resource", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassUnproved, SafeResourceID: "resource"}},
		{name: "ack-zero-status", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged}},
		{name: "no-effect-with-locator", outcome: Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassQualifiedNoEffect, AssignedLocator: "other"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			e, p, c := testEffect(t, protocol.ActionCreateWithValue, []byte("value"))
			p.outcome = &row.outcome
			p.sendError = row.sendError
			if row.assigned {
				c.Target.ConsumerLocator = ""
				c.Target.LocatorRequiresCreation = true
				replaceAuthorControl(t, &e, c, protocol.Policy{})
			}
			if err := Serve(context.Background(), e, p); err != nil {
				t.Fatal(err)
			}
			got := resultFrom(t, e, c, true)
			if protocol.ValidateResult(c, got) != nil {
				t.Fatal("runtime lost exact result correlation")
			}
			if row.ack {
				if got.Class != protocol.ClassAcknowledged {
					t.Fatal("valid acknowledgment refused")
				}
				want := c.Target.ConsumerLocator
				if row.assigned {
					want = row.outcome.AssignedLocator
				}
				if got.ConsumerLocator != want {
					t.Fatal("locator changed")
				}
			} else if got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved || got.NormalizedStatus != 0 || got.SafeRequestID != "" || got.SafeResourceID != "" || got.ConsumerLocator != "" {
				t.Fatal("invalid or errored result strengthened evidence")
			}
		})
	}
}

func replaceAuthorControl(t *testing.T, e *Endpoints, c protocol.Command, policy protocol.Policy) {
	t.Helper()
	var control bytes.Buffer
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: c.DescriptorID, ArtifactContractID: testID(31)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.EncodeCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	testFrame(t, &control, protocol.KindHello, c.AttemptID, hello)
	testFrame(t, &control, protocol.KindCommand, c.AttemptID, body)
	testFrame(t, &control, protocol.KindPolicy, c.AttemptID, policy.Data)
	e.Control = &control
}

func testExactAuthorFacts(t *testing.T) {
	t.Helper()
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionCreateWithValue, protocol.ActionWriteValue, protocol.ActionUpdatePolicy, protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		t.Run(string(rune('0'+action)), func(t *testing.T) {
			base := action
			if action == protocol.ActionUpdatePolicy || action == protocol.ActionDeleteReservedSlot {
				base = protocol.ActionCreateEmpty
			}
			payload := []byte("value")
			if base != protocol.ActionCreateWithValue && base != protocol.ActionWriteValue {
				payload = nil
			}
			e, p, c := testEffect(t, base, payload)
			c.Action = action
			policy := protocol.Policy{}
			if action == protocol.ActionUpdatePolicy {
				policy = protocol.Policy{ContractID: "policy/facts", Data: []byte("exact policy")}
				c.PolicyContractID = policy.ContractID
				var err error
				c.PolicyDigest, err = protocol.PolicyDigest(c.DomainID, policy)
				if err != nil {
					t.Fatal(err)
				}
				c.OwnedInstance = "exact-owned"
				c.OwnedBirthAttemptID = testID(15)
				c.BirthTargetRowDigest = testID(14)
			}
			if action == protocol.ActionDeleteReservedSlot {
				c.UncertainCreateAttemptID = testID(23)
				c.ExclusiveNamespaceDigest = testID(24)
			}
			c.ConditionalToken = "actual conditional token"
			replaceAuthorControl(t, &e, c, policy)
			if err := Serve(context.Background(), e, p); err != nil {
				t.Fatal(err)
			}
			want := Preparation{Action: action, Target: c.Target, AttemptID: c.AttemptID, OwnedInstance: c.OwnedInstance, ConditionalToken: "actual conditional token", PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
			if !reflect.DeepEqual(p.command, want) || p.preparedPolicy.ContractID != policy.ContractID || !bytes.Equal(p.preparedPolicy.Data, policy.Data) || !p.observedDeadline {
				t.Fatal("prepare dropped admitted service facts")
			}
			if p.checked.Action != action || !reflect.DeepEqual(p.checked.Target, c.Target) || p.checked.ConditionalTokenLength != uint16(len(c.ConditionalToken)) || p.checked.PayloadLengthMode != c.PayloadLengthMode || p.checked.PayloadLength != c.PayloadLength || p.checked.OwnedInstance != c.OwnedInstance || p.checkedPolicy.ContractID != policy.ContractID || !bytes.Equal(p.checkedPolicy.Data, policy.Data) {
				t.Fatal("action callback lost service facts")
			}
			mode := protocol.OwnershipQualified
			if action == protocol.ActionCreateEmpty || action == protocol.ActionCreateWithValue {
				mode = protocol.OwnershipNone
			}
			if action == protocol.ActionDeleteReservedSlot {
				mode = protocol.OwnershipUncertain
			}
			if p.checked.OwnershipMode != mode || p.checked.UncertainCreateAttemptID != c.UncertainCreateAttemptID || p.checked.ExclusiveNamespaceDigest != c.ExclusiveNamespaceDigest {
				t.Fatal("ownership facts changed")
			}
		})
	}
	// Passive action facts use distinct caller-supplied ownership bytes.
	p := new(sampleImplementation)
	c, policy := testCommand(t)
	q := c.ActionCheck()
	q.OwnedInstanceDigest = testID(42)
	q.ConditionalTokenLength = 37
	body, err := protocol.EncodeActionCheckRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	var control, result bytes.Buffer
	id := testID(79)
	hello, _ := protocol.EncodeHello(protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: p.Identity().DescriptorID, ArtifactContractID: testID(31)})
	testFrame(t, &control, protocol.KindHello, id, hello)
	testFrame(t, &control, protocol.KindActionCheckRequest, id, body)
	testFrame(t, &control, protocol.KindPolicy, id, policy.Data)
	if err := ServePublic(context.Background(), PublicEndpoints{Control: &control, Result: &result}, p); err != nil {
		t.Fatal(err)
	}
	if p.checked.OwnedInstanceDigest != testID(42) || p.checked.ConditionalTokenLength != 37 || p.prepares != 0 || p.sends != 0 || !bytes.Equal(p.checkedPolicy.Data, []byte("opaque\x00policy")) {
		t.Fatal("passive ownership facts changed or private stage entered")
	}

	settings := []byte(`{"public":"settings"}`)
	destination := protocol.Destination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: settings, Policy: policy, Capabilities: protocol.CapabilityWriteValue}
	targetRequest := protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: destination, EntryName: "", PayloadEncoding: protocol.EncodingBase64}
	for _, kind := range []uint8{protocol.KindNormalizeRequest, protocol.KindCanonicalRequest, protocol.KindInterpretRequest} {
		p = new(sampleImplementation)
		var body []byte
		var err error
		switch kind {
		case protocol.KindNormalizeRequest:
			body, err = protocol.EncodeNormalizeRequest(protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Settings: settings})
		case protocol.KindCanonicalRequest:
			body, err = protocol.EncodeCanonicalRequest(protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: destination})
		case protocol.KindInterpretRequest:
			body, err = protocol.EncodeInterpretRequest(targetRequest)
		}
		if err != nil {
			t.Fatal(err)
		}
		var control, result bytes.Buffer
		testFrame(t, &control, protocol.KindHello, id, hello)
		testFrame(t, &control, kind, id, body)
		if err := ServePublic(context.Background(), PublicEndpoints{Control: &control, Result: &result}, p); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case protocol.KindNormalizeRequest:
			if !bytes.Equal(p.normalized, settings) {
				t.Fatal("settings changed")
			}
		case protocol.KindCanonicalRequest:
			if !reflect.DeepEqual(p.canonical, destination) {
				t.Fatal("canonical facts changed")
			}
		case protocol.KindInterpretRequest:
			want := TargetRequest{Destination: destination, EntryName: "", PayloadEncoding: protocol.EncodingBase64}
			if !reflect.DeepEqual(p.interpreted, want) {
				t.Fatal("target facts changed")
			}
		}
		if p.prepares != 0 || p.sends != 0 || p.publicCalls != 1 {
			t.Fatal("passive callback reached private stage")
		}
	}
}
