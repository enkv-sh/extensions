package gcpsm

import (
	"bytes"
	"context"
	"encoding/json"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	outputcredential "enkv.sh/plugins/outputs/gcp-secret-manager/credential"
)

func gcpCredentialEnvironment(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	body := []byte(`{"type":"authorized_user","client_id":"synthetic-client","client_secret":"synthetic-secret","refresh_token":"synthetic-refresh","quota_project_id":"quota-project","universe_domain":"googleapis.com"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

// full_only: false
func TestDefaultOutputCapturesADCBearerExpiryAndQuota(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("subject_token") != "synthetic-subject" {
			t.Error("standard token exchange differs")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"captured-token","token_type":"Bearer","expires_in":3600,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`)
	}))
	defer server.Close()
	root := t.TempDir()
	subject := filepath.Join(root, "subject-token")
	if err := os.WriteFile(subject, []byte("synthetic-subject"), 0600); err != nil {
		t.Fatal(err)
	}
	adc := map[string]any{"type": "external_account", "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/test/providers/test",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": server.URL, "credential_source": map[string]string{"file": subject}, "quota_project_id": "quota-project", "universe_domain": "googleapis.com"}
	body, err := json.Marshal(adc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adc.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")
	source, err := loadCredentialSource(context.Background())
	if err != nil || source.credentials == nil || requests.Load() != 0 {
		t.Fatal("standard output route was not lazy", err)
	}
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "replacement-project")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wire, expiry, err := captureCredentialSource(ctx, source)
	defer clear(wire)
	if err != nil || requests.Load() != 1 || !time.Now().Before(expiry) {
		t.Fatal("standard output capture failed", err)
	}
	value, err := outputcredential.Decode(wire, time.Now())
	if err != nil || string(value.Token) != "captured-token" || value.QuotaProject != "quota-project" || value.Expiry.UnixMilli() != expiry.UnixMilli() {
		t.Fatal("captured output context changed", err)
	}
}

// full_only: false
func TestDefaultOutputSelectsADCWithoutCredentialFileArgument(t *testing.T) {
	gcpCredentialEnvironment(t)
	source, err := loadCredentialSource(context.Background())
	if err != nil || source.credentials == nil {
		t.Fatal("standard output requires a credential file", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if body, _, err := captureCredentialSource(ctx, source); err == nil || body != nil {
		t.Fatal("canceled ADC capture returned credentials")
	}
}

// full_only: false
func TestStandardDiscoveryInputsMatchAmbientWithoutMutation(t *testing.T) {
	t.Setenv("SELECTED_INPUT", "")
	i := Implementation{Binding: fixtureBinding(t, credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeSDK, Names: []string{"SELECTED_INPUT"}})}
	matching := []credentialroute.Input{{Name: "SELECTED_INPUT", Present: true, Value: []byte{}}}
	if err := i.checkEnvironment(matching); err != nil {
		t.Fatal("present empty input refused", err)
	}
	for _, input := range []credentialroute.Input{{Name: "SELECTED_INPUT"}, {Name: "SELECTED_INPUT", Present: true, Value: []byte("other")}} {
		if err := i.checkEnvironment([]credentialroute.Input{input}); err == nil {
			t.Fatal("mismatched route input accepted")
		}
		if value, present := os.LookupEnv("SELECTED_INPUT"); !present || value != "" {
			t.Fatal("global environment changed")
		}
	}
	if err := os.Unsetenv("SELECTED_INPUT"); err != nil {
		t.Fatal(err)
	}
	if err := i.checkEnvironment([]credentialroute.Input{{Name: "SELECTED_INPUT"}}); err != nil {
		t.Fatal("absent input refused", err)
	}
	if err := i.checkEnvironment(matching); err == nil {
		t.Fatal("empty input substituted for absent input")
	}
}

// full_only: false
func TestPrepareCapturesADCUntilOwnedSendCloses(t *testing.T) {
	exchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"captured-token","token_type":"Bearer","expires_in":3600,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`)
	}))
	defer server.Close()
	root := t.TempDir()
	subject := filepath.Join(root, "subject")
	if err := os.WriteFile(subject, []byte("synthetic-subject"), 0600); err != nil {
		t.Fatal(err)
	}
	adc := map[string]any{"type": "external_account", "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/test/providers/test", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": server.URL, "credential_source": map[string]string{"file": subject}, "quota_project_id": "quota-project", "universe_domain": "googleapis.com"}
	raw, err := json.Marshal(adc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adc.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")
	descriptor, err := os.ReadFile("../../cmd/enkv-output-gcp-secret-manager/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := NewImplementation(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	implementation.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
		writes++
		if req.Header.Get("Authorization") != "Bearer captured-token" || req.Header.Get("X-Goog-User-Project") != "quota-project" {
			t.Error("ADC capture changed")
		}
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			t.Error(err)
		}
		if err := req.Body.Close(); err != nil {
			t.Error(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(`{"name":"` + testParent + `/versions/42","clientSpecifiedPayloadChecksum":true}`))}, nil
	})
	payload := []byte("captured publication value")
	command, policy := testCommand(t, payload)
	command.DescriptorID = implementation.Identity().DescriptorID
	routeID, err := credentialroute.Identity(implementation.CredentialRoute())
	if err != nil {
		t.Fatal(err)
	}
	command.CredentialRouteID = protocol.ID(routeID)
	inputs := make([]credentialroute.Input, len(implementation.CredentialRoute().Names))
	for at, name := range implementation.CredentialRoute().Names {
		value, present := os.LookupEnv(name)
		inputs[at] = credentialroute.Input{Name: name, Present: present, Value: []byte(value)}
	}
	preparedValue, err := implementation.Prepare(t.Context(), preparationForTest(command), policy, inputs)
	if err != nil || preparedValue == nil || exchanges != 1 || writes != 0 {
		t.Fatal("ADC preparation", err, exchanges, writes)
	}
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "replacement-project")
	command.Target.TargetData[0] = 'X'
	got, err := preparedValue.Send(t.Context(), payload)
	if err != nil || got.Class != protocol.ClassAcknowledged || exchanges != 1 || writes != 1 {
		t.Fatal("captured send", got.Class, err, exchanges, writes)
	}
	if _, err := preparedValue.Send(t.Context(), payload); err == nil || writes != 1 {
		t.Fatal("prepared action resent")
	}
	owned := preparedValue.(*prepared)
	credential := owned.credential
	target := owned.command.Target.TargetData
	if err := preparedValue.Close(); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{credential, target} {
		if !bytes.Equal(body, make([]byte, len(body))) {
			t.Fatal("private owner not cleared")
		}
	}
}
