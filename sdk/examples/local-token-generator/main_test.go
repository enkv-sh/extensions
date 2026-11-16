package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/examples/testservice"
	"enkv.sh/sdk/generator"
	"enkv.sh/sdk/generator/conformance"
	protocol "enkv.sh/sdk/protocols/generator"
)

const testToken = "example-test-credential"

func id(n byte) protocol.ID {
	var v protocol.ID
	for i := range v {
		v[i] = n
	}
	return v
}
func localService(t *testing.T) (*testservice.Service, *httptest.Server) {
	t.Helper()
	service, err := testservice.New(testservice.Config{Token: testToken, Namespace: "demo"})
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
	return service, server
}
func authorImplementation(t *testing.T) generator.Implementation {
	t.Helper()
	v, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func authorFixture(t *testing.T, impl generator.Implementation, endpoint, namespace, subject string) conformance.Fixture {
	t.Helper()
	raw, err := json.Marshal(settings{Endpoint: endpoint, Namespace: namespace, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := impl.Normalize(t.Context(), protocol.NormalizeRequest{Schema: 1, ConfigContractID: impl.ConfigContractID(), Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := conformance.NewFixture(impl, conformance.Request{Action: protocol.ActionCreate, Intent: intent, Inputs: []credentialroute.Input{{Name: tokenVariable, Present: true, Value: []byte(testToken)}}}, conformance.Expectation{Disposition: protocol.DispositionCompleteCreate, Target: []byte(`{"endpoint":"` + endpoint + `","namespace":"demo"}`), ResourceData: []byte(`{"id":"t1"}`), Value: expectedValue()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, input := range fixture.Inputs {
			clear(input.Value[:cap(input.Value)])
		}
		clear(fixture.ExpectedValue[:cap(fixture.ExpectedValue)])
	})
	return fixture
}
func authorCommand(t *testing.T, impl generator.Implementation, endpoint, namespace, subject string) protocol.Command {
	t.Helper()
	return authorFixture(t, impl, endpoint, namespace, subject).Command
}
func expectedValue() []byte { return append([]byte{0, 255}, []byte("demo/api/t1")...) }

// full_only: false
func TestImplementationPreservesBindingErrorCauses(t *testing.T) {
	if _, err := implementation(); err != nil {
		t.Fatal(err)
	}
	declaration, err := artifact.DecodeDescriptor(descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	declaration.Generator = nil
	missing, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name, body, field string
	}{
		{"syntax", `{"schema":`, "descriptor"},
		{"field-case", `{"SCHEMA":"private-supplied-value"}`, "record.schema"},
		{"missing-declaration", string(missing), "descriptor"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			original := descriptorBytes
			t.Cleanup(func() { descriptorBytes = original })
			descriptorBytes = []byte(invalid.body)
			_, err := implementation()
			if !errors.Is(err, errSettings) || !errors.Is(err, artifact.ErrRecord) {
				t.Fatal("constructor lost settings or record cause")
			}
			if !strings.Contains(err.Error(), invalid.field) || strings.Contains(err.Error(), "private-supplied-value") || strings.Contains(err.Error(), "SCHEMA") {
				t.Fatal("constructor diagnostic lost safe field context")
			}
		})
	}
}

// full_only: false
func TestNormalizerOwnsDefaultsAndCanonicalSettings(t *testing.T) {
	_, server := localService(t)
	impl := authorImplementation(t)
	raw := []byte(`{"subject":"api","namespace":" DEMO ","endpoint":"` + server.URL + `/"}`)
	intent, err := impl.Normalize(t.Context(), protocol.NormalizeRequest{Schema: 1, ConfigContractID: impl.ConfigContractID(), Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"endpoint":"` + server.URL + `","namespace":"demo","subject":"api"}`)
	if !bytes.Equal(intent.Settings, want) || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID != resourceContractID() {
		t.Fatal("canonical settings/defaults differ")
	}
	if impl.ValidateCanonical(t.Context(), intent) != nil {
		t.Fatal("canonical settings refused")
	}
	defaulted, err := impl.Normalize(t.Context(), protocol.NormalizeRequest{Schema: 1, ConfigContractID: impl.ConfigContractID(), Settings: []byte(`{"endpoint":"` + server.URL + `"}`)})
	if err != nil || !bytes.Equal(defaulted.Settings, []byte(`{"endpoint":"`+server.URL+`","namespace":"example","subject":"token"}`)) {
		t.Fatal("omitted settings did not receive the author's exact defaults", err)
	}
	intent.Settings = raw
	if impl.ValidateCanonical(t.Context(), intent) == nil {
		t.Fatal("canonical validation reapplied defaults")
	}
	for _, bad := range []string{`{"endpoint":"https://127.0.0.1:1234"}`, `{"endpoint":"http://example.com:1234"}`, `{"endpoint":"` + server.URL + `","unknown":1}`} {
		if _, err := impl.Normalize(t.Context(), protocol.NormalizeRequest{Schema: 1, ConfigContractID: impl.ConfigContractID(), Settings: []byte(bad)}); err == nil {
			t.Fatal("invalid implementation settings admitted")
		}
	}
}

// full_only: false
func TestManagedTokenAuthorCheckUsesOwnHTTPBehavior(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	service, err := testservice.New(testservice.Config{Token: testToken, Namespace: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var method, contentType string
	var sent []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokens" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			method, contentType, sent = r.Method, r.Header.Get("Content-Type"), bytes.Clone(body)
			mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		service.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		server.Close()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	impl := authorImplementation(t)
	fixture := authorFixture(t, impl, server.URL, "demo", "api")
	if err := conformance.CheckImplementation(t.Context(), generator.Run, impl, fixture); err != nil {
		t.Fatal(err)
	}
	if count := service.Counts(); count.TokenCreates != 1 || count.Tokens != 1 {
		t.Fatal("author callback did not create exactly one resource", count)
	}
	mu.Lock()
	requestCorrect := method == http.MethodPost && contentType == "application/json" && bytes.Equal(sent, []byte(`{"namespace":"demo","subject":"api"}`))
	mu.Unlock()
	if !requestCorrect {
		t.Fatal("author's exact HTTP request differs")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/tokens/t1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatal("independent consumer failed")
	}
	var content struct {
		ID    string `json:"id"`
		Value string `json:"value_base64"`
	}
	if json.Unmarshal(body, &content) != nil || content.ID != "t1" {
		t.Fatal("consumer resource differs")
	}
	value, err := base64.StdEncoding.Strict().DecodeString(content.Value)
	if err != nil || !bytes.Equal(value, expectedValue()) {
		t.Fatal("consumer bytes differ")
	}
	clear(value)
	clear(body)
}

// full_only: false
func TestManagedTokenRetiresExactOriginalResource(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	service, server := localService(t)
	impl := authorImplementation(t)
	create := authorCommand(t, impl, server.URL, "demo", "api")
	facts, value, err := impl.Create(t.Context(), generator.Invocation{Command: create})
	if err != nil || !bytes.Equal(value, expectedValue()) {
		t.Fatal("create failed", err)
	}
	clear(value)
	original, err := protocol.EncodeSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	compat := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: create.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: create.Intent, OriginalFacts: original}
	compat.InputDigest, _ = protocol.RetirementCompatibilityInputDigest(compat)
	if accept, err := impl.CheckRetirementCompatibility(t.Context(), compat); err != nil || !accept {
		t.Fatal("compatible original refused", err)
	}
	retire := create
	retire.Action, retire.OriginalFacts, retire.RequestDigest = protocol.ActionRetire, original, id(31)
	retire.AttemptID, retire.TransmissionID, retire.ResultID = id(32), id(33), id(34)
	ack, err := impl.Retire(t.Context(), generator.Invocation{Command: retire})
	if err != nil || protocol.ValidateResult(retire, retire.NewResult(ack, nil)) != nil || ack.Disposition != protocol.DispositionRetirementAcknowledged {
		t.Fatal("exact retirement failed", err)
	}
	if count := service.Counts(); count.Tokens != 0 || count.TokenCreates != 1 || count.TokenRetires != 1 {
		t.Fatal("retirement changed wrong resource", count)
	}
	compat.CompletionClass = protocol.CompletionConfirmed
	if accept, err := impl.CheckRetirementCompatibility(t.Context(), compat); err != nil || accept {
		t.Fatal("native author claimed confirmed invalidation")
	}
}

// full_only: false
func TestCreateChecksResolvedNamespaceBeforeEffect(t *testing.T) {
	for _, condition := range []string{"namespace", "credential"} {
		t.Run(condition, func(t *testing.T) {
			t.Setenv(tokenVariable, testToken)
			service, server := localService(t)
			impl := authorImplementation(t)
			namespace := "demo"
			if condition == "namespace" {
				namespace = "other"
			} else {
				t.Setenv(tokenVariable, "incorrect")
			}
			command := authorCommand(t, impl, server.URL, namespace, "api")
			facts, value, err := impl.Create(t.Context(), generator.Invocation{Command: command})
			if err != nil || len(value) != 0 || facts.Disposition != protocol.DispositionConfirmedNoEffect || service.Counts().TokenCreates != 0 {
				t.Fatal("account/credential refusal entered create", err)
			}
		})
	}
}

// full_only: false
func TestLostCreateReplyRemainsUnknownWithoutRetry(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	service, server := localService(t)
	service.LoseNextTokenReply()
	impl := authorImplementation(t)
	command := authorCommand(t, impl, server.URL, "demo", "api")
	facts, value, err := impl.Create(t.Context(), generator.Invocation{Command: command})
	if err != nil || len(value) != 0 || facts.Disposition != protocol.DispositionUnknown || facts.Reason != protocol.ReasonTransport {
		t.Fatal("lost reply fabricated ownership/no-effect", err)
	}
	if count := service.Counts(); count.TokenCreates != 1 || count.Tokens != 1 {
		t.Fatal("unknown create retried", count)
	}
}

// full_only: false
func TestCancelledCreateHasNoServiceEffect(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	service, server := localService(t)
	impl := authorImplementation(t)
	command := authorCommand(t, impl, server.URL, "demo", "api")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	facts, value, err := impl.Create(ctx, generator.Invocation{Command: command})
	if err != nil || len(value) != 0 || facts.Disposition != protocol.DispositionConfirmedNoEffect || service.Counts().TokenCreates != 0 || service.Counts().Tokens != 0 {
		t.Fatal("cancelled create created a resource or claimed a value", err)
	}
}

// full_only: false
func TestMalformedReturnedValueRetainsOwnedResource(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/session" {
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.WriteString(w, `{"namespace":"demo"}`); err != nil {
				t.Errorf("write session reply: %v", err)
			}
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/tokens" {
			t.Error("request method/path differs")
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, `{"id":"t9","value_base64":"***"}`); err != nil {
			t.Errorf("write token reply: %v", err)
		}
	}))
	defer server.Close()
	impl := authorImplementation(t)
	command := authorCommand(t, impl, server.URL, "demo", "api")
	facts, value, err := impl.Create(t.Context(), generator.Invocation{Command: command})
	if err != nil || len(value) != 0 || facts.Disposition != protocol.DispositionOwnedUnusableCreate || string(facts.ResourceData) != `{"id":"t9"}` {
		t.Fatal("unusable owned resource lost", err)
	}
}

// full_only: false
func TestAuthorCheckDetectsChangedSubjectRequest(t *testing.T) {
	t.Setenv(tokenVariable, testToken)
	_, server := localService(t)
	impl := authorImplementation(t)
	fixture := authorFixture(t, impl, server.URL, "demo", "api")
	actual := impl.Create
	impl.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
		intent, err := protocol.DecodeIntent(inv.Command.Intent)
		if err != nil {
			return protocol.SafeFacts{}, nil, err
		}
		intent.Settings = bytes.Replace(intent.Settings, []byte(`"subject":"api"`), []byte(`"subject":"wrong"`), 1)
		inv.Command.Intent, err = protocol.EncodeIntent(intent)
		if err != nil {
			return protocol.SafeFacts{}, nil, err
		}
		return actual(ctx, inv)
	}
	if err := conformance.CheckImplementation(t.Context(), generator.Run, impl, fixture); err == nil {
		t.Fatal("changed request subject passed independent author expectations")
	}
}
