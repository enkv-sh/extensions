package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/examples/testservice"
	"enkv.sh/sdk/output"
	"enkv.sh/sdk/output/conformance"
	protocol "enkv.sh/sdk/protocols/output"
)

const testToken = "local-author-test"

func serviceFixture(t *testing.T) (*testservice.Service, *httptest.Server) {
	t.Helper()
	service, err := testservice.New(testservice.Config{Token: testToken, Namespace: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	t.Cleanup(func() {
		server.Close()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("ENKV_EXAMPLE_TOKEN", testToken)
	return service, server
}
func authorCommand(t *testing.T, p *implementation, endpoint, name string, action protocol.Action, payload []byte, owned string) protocol.Command {
	t.Helper()
	settings, _ := json.Marshal(settings{Endpoint: endpoint, Namespace: "dev"})
	d, err := p.NormalizeDestination(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	target, err := p.InterpretTarget(t.Context(), output.TargetRequest{Destination: d, EntryName: name, PayloadEncoding: protocol.EncodingRaw})
	if err != nil {
		t.Fatal(err)
	}
	pRequest := output.Preparation{Action: action, Target: target, OwnedInstance: owned}
	if action == protocol.ActionCreateWithValue || action == protocol.ActionWriteValue {
		pRequest.PayloadLengthMode = protocol.LengthExact
		pRequest.PayloadLength = uint32(len(payload))
	}
	f, err := conformance.NewFixture(p, conformance.Request{Preparation: pRequest, Payload: payload, Inputs: []credentialroute.Input{{Name: "ENKV_EXAMPLE_TOKEN", Present: false}}}, output.Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassUnproved})
	if err != nil {
		t.Fatal(err)
	}
	c := f.Command
	return c
}
func execute(t *testing.T, p *implementation, c protocol.Command, payload []byte) (protocol.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var control, credentials, values, result bytes.Buffer
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: p.Identity().ProtocolID, DescriptorID: c.DescriptorID, ArtifactContractID: protocol.ID{31}})
	if err != nil {
		return protocol.Result{}, err
	}
	command, err := protocol.EncodeCommand(c)
	if err != nil {
		return protocol.Result{}, err
	}
	private, err := credentialroute.EncodeInputs(p.CredentialRoute(), []credentialroute.Input{{Name: "ENKV_EXAMPLE_TOKEN", Present: true, Value: []byte(testToken)}})
	if err != nil {
		return protocol.Result{}, err
	}
	var credentialFrame, payloadFrame []byte
	defer func() {
		clear(private[:cap(private)])
		clear(credentialFrame[:cap(credentialFrame)])
		clear(payloadFrame[:cap(payloadFrame)])
	}()
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CorrelationID: c.AttemptID, Body: hello}, {Kind: protocol.KindCommand, CorrelationID: c.AttemptID, Body: command}, {Kind: protocol.KindPolicy, CorrelationID: c.AttemptID}} {
		if err := protocol.WriteFrame(&control, frame); err != nil {
			return protocol.Result{}, err
		}
	}
	if err := protocol.WriteFrame(&credentials, protocol.Frame{Kind: protocol.KindCredential, CorrelationID: c.AttemptID, Body: private}); err != nil {
		return protocol.Result{}, err
	}
	credentialFrame = credentials.Bytes()
	kind := uint8(protocol.KindArm)
	if c.Action == protocol.ActionCreateWithValue || c.Action == protocol.ActionWriteValue {
		kind = protocol.KindPayload
	}
	if err := protocol.WriteFrame(&values, protocol.Frame{Kind: kind, CorrelationID: c.AttemptID, Body: payload}); err != nil {
		return protocol.Result{}, err
	}
	payloadFrame = values.Bytes()
	if code := output.Run(ctx, output.Endpoints{Control: &control, Credential: &credentials, Payload: &values, Result: &result}, p); code != 0 {
		return protocol.Result{}, protocol.ErrProtocol
	}
	ack, err := protocol.ReadExpectedFrame(&result, protocol.KindHelloAck, c.AttemptID, protocol.HelloBytes)
	if err != nil || !bytes.Equal(ack, hello) {
		return protocol.Result{}, protocol.ErrProtocol
	}
	if _, err := protocol.ReadExpectedFrame(&result, protocol.KindReadyForPayload, c.AttemptID, 0); err != nil {
		return protocol.Result{}, err
	}
	body, err := protocol.ReadExpectedFrame(&result, protocol.KindResult, c.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		return protocol.Result{}, err
	}
	decoded, err := protocol.DecodeResult(body)
	if err != nil {
		return protocol.Result{}, err
	}
	if err := protocol.ValidateResult(c, decoded); err != nil {
		return protocol.Result{}, err
	}
	if err := protocol.RequireEOF(&result); err != nil {
		return protocol.Result{}, err
	}
	return decoded, nil
}

func readValue(t *testing.T, locator string) ([]byte, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, locator, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatal("consumer read", err, closeErr)
	}
	return body, response.StatusCode
}

// full_only: false
func TestLocalOutputOwnsCanonicalSettingsAndPhysicalIdentity(t *testing.T) {
	_, server := serviceFixture(t)
	p, err := newImplementation()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"namespace":"dev","endpoint":"` + server.URL + `/"}`)
	d, err := p.NormalizeDestination(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte(`{"endpoint":"` + server.URL + `","namespace":"dev"}`)
	if !bytes.Equal(d.CanonicalSettings, expected) || d.ConfigContractID != configContract || d.ServiceContractID != serviceContract {
		t.Fatal("plugin defaults/normalization changed")
	}
	if p.ValidateCanonical(t.Context(), d) != nil {
		t.Fatal("canonical validation failed")
	}
	expectedDestination := protocol.Destination{ConfigContractID: configContract, ServiceContractID: serviceContract, CanonicalSettings: expected, Capabilities: actions}
	locator := server.URL + "/values/dev/c2VjcmV0"
	expectedTarget := protocol.Target{ServiceContractID: serviceContract, TargetContractID: targetContract, CanonicalTarget: locator, ConsumerLocator: locator, TargetData: []byte(`{"endpoint":"` + server.URL + `","namespace":"dev","key":"c2VjcmV0"}`), PayloadEncoding: protocol.EncodingRaw, Capabilities: actions, CreateValueBounds: protocol.PayloadBounds{Maximum: 65536}, WriteValueBounds: protocol.PayloadBounds{Maximum: 65536}}
	passive := conformance.PublicFixture{PolicyAction: output.PolicyActionSelection{DomainID: protocol.ID{1}, Target: expectedTarget}, PolicyActionPolicy: protocol.Policy{ContractID: "unsupported-policy", Data: []byte("policy")}, Settings: raw, ExpectedDestination: expectedDestination, TargetRequest: output.TargetRequest{Destination: expectedDestination, EntryName: "secret", PayloadEncoding: protocol.EncodingRaw}, ExpectedTarget: expectedTarget, ActionCheck: output.ActionCheck{Action: protocol.ActionCreateWithValue, Target: expectedTarget, PayloadLengthMode: protocol.LengthExact, PayloadLength: 1}, ExpectedBounds: protocol.PayloadBounds{Maximum: 65536}, NormalizeAccepted: true, CanonicalAccepted: true, TargetAccepted: true, ActionAccepted: true}
	if err := conformance.CheckPublicImplementation(t.Context(), output.RunPublic, p, passive); err != nil {
		t.Fatal(err)
	}
	changed := d
	changed.CanonicalSettings = raw
	if p.ValidateCanonical(t.Context(), changed) == nil {
		t.Fatal("canonical validation reapplied normalization")
	}
	c := authorCommand(t, p, server.URL, "secret", protocol.ActionCreateWithValue, []byte("x"), "")
	if c.Target.CanonicalTarget != server.URL+"/values/dev/c2VjcmV0" || c.Target.ConsumerLocator != c.Target.CanonicalTarget || c.Target.TargetContractID != targetContract || c.Target.LocatorRequiresCreation || c.Target.CreateValueBounds != (protocol.PayloadBounds{Maximum: 65536}) || c.Target.WriteValueBounds != (protocol.PayloadBounds{Maximum: 65536}) {
		t.Fatal("target/reference derivation changed")
	}
	changedTarget := c.Target
	changedTarget.WriteValueBounds.Maximum--
	if !changedTarget.Valid() {
		t.Fatal("changed bounds fixture violates the family contract")
	}
	if _, err := readTarget(changedTarget); err == nil {
		t.Fatal("plugin accepted changed declared value bounds")
	}
}

// full_only: false
func TestLocalOutputCreatesWritesAndDeletesExactOwnedValue(t *testing.T) {
	service, server := serviceFixture(t)
	p, err := newImplementation()
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{0, 255, 'a'}
	c := authorCommand(t, p, server.URL, "secret", protocol.ActionCreateWithValue, first, "")
	result, err := execute(t, p, c, first)
	if err != nil || protocol.ValidateResult(c, result) != nil || result.Class != protocol.ClassAcknowledged || result.SafeResourceID != "v1" || result.ConsumerLocator != c.Target.CanonicalTarget {
		t.Fatal("create result", err, result.Class)
	}
	if actual, status := readValue(t, c.Target.ConsumerLocator); status != 200 || !bytes.Equal(actual, first) {
		t.Fatal("created consumer bytes differ")
	}
	c = authorCommand(t, p, server.URL, "secret", protocol.ActionWriteValue, []byte{}, "v1")
	result, err = execute(t, p, c, []byte{})
	if err != nil || result.Class != protocol.ClassAcknowledged || result.ConsumerLocator != "" {
		t.Fatal("write result", err)
	}
	if actual, status := readValue(t, c.Target.ConsumerLocator); status != 200 || len(actual) != 0 {
		t.Fatal("empty owned value changed")
	}
	maximum := bytes.Repeat([]byte{0, 255}, 32768)
	c = authorCommand(t, p, server.URL, "secret", protocol.ActionWriteValue, maximum, "v1")
	result, err = execute(t, p, c, maximum)
	if err != nil || protocol.ValidateResult(c, result) != nil || result.Class != protocol.ClassAcknowledged || result.SafeResourceID != "v1" {
		t.Fatal("maximum owned write result", err)
	}
	if actual, status := readValue(t, c.Target.ConsumerLocator); status != 200 || !bytes.Equal(actual, maximum) {
		t.Fatal("maximum owned consumer bytes differ")
	}
	wrong := authorCommand(t, p, server.URL, "secret", protocol.ActionDeleteOwned, nil, "v99")
	result, err = execute(t, p, wrong, nil)
	if err != nil || result.Class != protocol.ClassQualifiedNoEffect {
		t.Fatal("wrong owner was not refused", err)
	}
	c = authorCommand(t, p, server.URL, "secret", protocol.ActionDeleteOwned, nil, "v1")
	c.Target.Capabilities = protocol.CapabilityDeleteOwned
	c.Target.CreateValueBounds = protocol.PayloadBounds{}
	c.Target.WriteValueBounds = protocol.PayloadBounds{}
	if !c.Valid() {
		t.Fatal("retained deletion-only target refused")
	}
	result, err = execute(t, p, c, nil)
	if err != nil || result.Class != protocol.ClassAcknowledged {
		t.Fatal("owned deletion", err)
	}
	if _, status := readValue(t, c.Target.ConsumerLocator); status != 404 {
		t.Fatal("owned value remains")
	}
	counts := service.Counts()
	if counts.ValueCreates != 1 || counts.ValueWrites != 2 || counts.ValueDeletes != 1 {
		t.Fatal("unexpected physical mutation counts", counts)
	}
}

// full_only: false
func TestAuthorConformanceAndConsumerDetectWrongRequestPayload(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "correct", true: "defective-request"}[bad], func(t *testing.T) {
			_, server := serviceFixture(t)
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte{0, 255, 'x'}
			c := authorCommand(t, p, server.URL, "secret", protocol.ActionCreateWithValue, payload, "")
			input := []byte(testToken)
			defer clear(input[:cap(input)])
			fixture, err := conformance.NewFixture(p, conformance.Request{Preparation: preparationForTest(c), Inputs: []credentialroute.Input{{Name: "ENKV_EXAMPLE_TOKEN", Present: true, Value: input}}, Payload: payload}, output.Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "v1"})
			if err != nil {
				t.Fatal(err)
			}
			impl := output.Implementation(p)
			if bad {
				impl = wrongRequest{Implementation: p}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = conformance.CheckImplementation(ctx, output.Run, impl, fixture)
			if err != nil {
				t.Fatal("common serving contract", err)
			}
			actual, status := readValue(t, c.Target.ConsumerLocator)
			meaningPassed := status == 200 && bytes.Equal(actual, payload)
			if meaningPassed == bad {
				t.Fatal("consumer did not distinguish the defective author request")
			}
		})
	}
}

type wrongRequest struct{ output.Implementation }

func (p wrongRequest) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	prepared, err := p.Implementation.Prepare(ctx, c, policy, inputs)
	if err != nil {
		return nil, err
	}
	return wrongPayload{prepared}, nil
}

type wrongPayload struct{ output.Prepared }

func (p wrongPayload) Send(ctx context.Context, _ []byte) (output.Outcome, error) {
	return p.Prepared.Send(ctx, []byte{'B', 'A', 'D'})
}

// full_only: false
func TestLocalOutputLostAcknowledgementDoesNotResend(t *testing.T) {
	service, server := serviceFixture(t)
	p, err := newImplementation()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("once")
	c := authorCommand(t, p, server.URL, "secret", protocol.ActionCreateWithValue, payload, "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	prepared, err := p.Prepare(ctx, preparationForTest(c), protocol.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := prepared.Close(); err != nil {
			t.Error(err)
		}
	}()
	service.LoseNextValueReply()
	result, err := prepared.Send(ctx, payload)
	if err == nil || result.Class != protocol.ClassUnproved || result.Entry != protocol.EntryMayHaveEntered {
		t.Fatal("lost reply was not unknown")
	}
	if _, err := prepared.Send(ctx, payload); err == nil {
		t.Fatal("original prepared invocation resent")
	}
	if counts := service.Counts(); counts.ValueCreates != 1 {
		t.Fatal("lost reply caused multiple sends", counts)
	}
	if actual, status := readValue(t, c.Target.ConsumerLocator); status != 200 || !bytes.Equal(actual, payload) {
		t.Fatal("controlled effect absent")
	}
}

// full_only: false
func TestLocalOutputChecksCredentialNamespaceBeforePayload(t *testing.T) {
	for _, condition := range []string{"wrong-token", "wrong-namespace"} {
		t.Run(condition, func(t *testing.T) {
			service, server := serviceFixture(t)
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			c := authorCommand(t, p, server.URL, "secret", protocol.ActionCreateWithValue, []byte("secret"), "")
			if condition == "wrong-token" {
				t.Setenv("ENKV_EXAMPLE_TOKEN", "wrong")
			} else {
				c.Target.TargetData = []byte(`{"endpoint":"` + server.URL + `","namespace":"other","key":"c2VjcmV0"}`)
				c.Target.CanonicalTarget = server.URL + "/values/other/c2VjcmV0"
				c.Target.ConsumerLocator = c.Target.CanonicalTarget
			}
			if _, err := p.CheckAction(t.Context(), actionForTest(c.ActionCheck()), protocol.Policy{}); err != nil {
				t.Fatal("credential refusal fixture has an invalid public target", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			prepared, err := p.Prepare(ctx, preparationForTest(c), protocol.Policy{}, nil)
			if prepared != nil {
				t.Cleanup(func() {
					if err := prepared.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if err == nil || prepared != nil {
				t.Fatal("wrong credentials or namespace reached preparation")
			}
			if counts := service.Counts(); counts.ValueCreates != 0 || counts.ValueWrites != 0 || counts.ValueDeletes != 0 {
				t.Fatal("refused preparation changed a service value", counts)
			}
		})
	}
}

// full_only: false
func TestOutputStartupRefusesWrongFamilyBeforeCallbacks(t *testing.T) {
	original := descriptorBytes
	t.Cleanup(func() { descriptorBytes = original })
	descriptor, err := artifact.DecodeDescriptor(original)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Role = "manifest-generator"
	descriptor.Output = nil
	descriptor.Manifest = &artifact.ManifestDeclaration{ConfigContractID: "other/config", FormatContractID: "other/format"}
	descriptorBytes, err = artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newImplementation(); err == nil {
		t.Fatal("wrong family accepted")
	}
}

func preparationForTest(c protocol.Command) output.Preparation {
	return output.Preparation{Action: c.Action, Target: c.Target, AttemptID: c.AttemptID, OwnedInstance: c.OwnedInstance, ConditionalToken: c.ConditionalToken, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
func actionForTest(c protocol.ActionCheckRequest) output.ActionCheck {
	return output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, OwnershipMode: c.OwnershipMode, OwnedInstanceDigest: c.OwnedInstanceDigest, UncertainCreateAttemptID: c.UncertainCreateAttemptID, ExclusiveNamespaceDigest: c.ExclusiveNamespaceDigest, ConditionalTokenLength: c.ConditionalTokenLength, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
