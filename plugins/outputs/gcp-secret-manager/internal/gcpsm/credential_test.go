package gcpsm

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestCapturedQuotaProjectReachesAdmittedServiceRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer token-1" || r.Header.Get("X-Goog-User-Project") != "quota-project" {
			t.Error("snapshot token/quota changed")
		}
		_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
	}))
	defer server.Close()
	body := testCredential("token-1")
	body = body[:len(body)-2]
	body = binary.BigEndian.AppendUint16(body, uint16(len("quota-project")))
	body = append(body, "quota-project"...)
	defer clear(body)
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	result, err := testImplementation(server).execute(context.Background(), command, policy, payload, body)
	if err != nil || requests != 1 || result.Class != protocol.ClassAcknowledged {
		t.Fatalf("quota snapshot dispatch differs: requests=%d result=%v err=%v", requests, result.Class, err)
	}
}

// full_only: false
func TestQuotaProjectAndHeadersComeOnlyFromCapturedMetadata(t *testing.T) {
	payload := []byte("{}")
	command, _ := testCommand(t, payload)
	requests := 0
	guard := &operationTransport{endpoint: endpoint, bearer: "Bearer token-1", quotaProject: "quota-project", rules: actionRules(preparationForTest(command), "123456789012", "Enkv_output-1"),
		base: headerCheckTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			if err := r.Body.Close(); err != nil {
				return nil, err
			}
			if r.Header.Get("X-Goog-User-Project") != "quota-project" || r.Header.Get("X-Goog-Api-Key") != "" || r.Header.Get("X-Unreviewed") != "" {
				t.Error("caller metadata survived admission")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})}
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint+"/v1/"+testParent+":addVersion?alt=json&prettyPrint=false", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer token-1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goog-User-Project", "attacker")
	req.Header.Set("X-Goog-Api-Key", "private")
	req.Header.Set("X-Unreviewed", "private")
	response, err := guard.RoundTrip(req)
	if err != nil || requests != 1 {
		t.Fatal("admitted request failed", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

type headerCheckTransport func(*http.Request) (*http.Response, error)

func (f headerCheckTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
