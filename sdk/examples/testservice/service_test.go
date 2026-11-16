package testservice

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fixture struct {
	service *Service
	server  *httptest.Server
	client  *http.Client
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	service, err := New(Config{Token: "example-token", Namespace: "workshop"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		server.Close()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return fixture{service, server, &http.Client{Transport: transport, Timeout: 2 * time.Second}}
}

func (f fixture) request(t *testing.T, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer example-token")
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response: %v", err)
		}
	}()
	result, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(result) > 65536 {
		t.Fatal("response read failed", err, len(result))
	}
	return response.StatusCode, result, response.Header
}

// full_only: false
func TestTokenLifecycleUsesBinaryValueAndExactNamespace(t *testing.T) {
	f := newFixture(t)
	status, body, _ := f.request(t, "GET", "/session", nil, nil)
	if status != 200 || string(body) != "{\"namespace\":\"workshop\"}\n" {
		t.Fatal("session namespace differs", status)
	}
	status, _, _ = f.request(t, "POST", "/tokens", []byte(`{"namespace":"other","subject":"api"}`), nil)
	if status != 400 || f.service.Counts().TokenCreates != 0 {
		t.Fatal("wrong namespace created a token")
	}
	status, body, _ = f.request(t, "POST", "/tokens", []byte(`{"namespace":"workshop","subject":"api"}`), nil)
	var token struct {
		ID          string `json:"id"`
		ValueBase64 string `json:"value_base64"`
	}
	if status != 201 || json.Unmarshal(body, &token) != nil || token.ID != "t1" {
		t.Fatal("token creation response differs", status)
	}
	value, err := base64.StdEncoding.DecodeString(token.ValueBase64)
	if err != nil || !bytes.Equal(value, []byte("\x00\xffworkshop/api/t1")) {
		t.Fatal("token did not contain independent expected binary bytes")
	}
	status, read, _ := f.request(t, "GET", "/tokens/t1", nil, nil)
	if status != 200 || !bytes.Equal(read, body) {
		t.Fatal("created token was not stored")
	}
	status, _, _ = f.request(t, "DELETE", "/tokens/t1", nil, nil)
	if status != 204 {
		t.Fatal("retirement failed", status)
	}
	status, _, _ = f.request(t, "GET", "/tokens/t1", nil, nil)
	if status != 404 || f.service.Counts() != (Counts{TokenCreates: 1, TokenRetires: 1}) {
		t.Fatal("retirement left a token", status, f.service.Counts())
	}
}

// full_only: false
func TestValueOwnershipRejectsReplacementAndPreservesEmptyValues(t *testing.T) {
	f := newFixture(t)
	const path = "/values/workshop/YXBp" // Unpadded base64url of "api".
	create := map[string]string{"If-None-Match": "*"}
	first := map[string]string{"If-Match": `"v1"`}
	second := map[string]string{"If-Match": `"v2"`}
	status, _, headers := f.request(t, "POST", path, []byte{}, create)
	if status != 201 || headers.Get("X-Resource-ID") != "v1" || headers.Get("ETag") != `"v1"` {
		t.Fatal("empty creation did not return exact ownership", status)
	}
	status, body, _ := f.request(t, "GET", path, nil, nil)
	if status != 200 || len(body) != 0 {
		t.Fatal("empty value changed", status)
	}
	status, _, _ = f.request(t, "POST", path, []byte("replacement"), create)
	if status != 412 {
		t.Fatal("occupied creation replaced a value", status)
	}
	status, _, _ = f.request(t, "PUT", path, []byte("unowned"), second)
	if status != 412 {
		t.Fatal("wrong owner wrote a value", status)
	}
	want := []byte{0, 1, 255}
	status, _, headers = f.request(t, "PUT", path, want, first)
	if status != 204 || headers.Get("X-Resource-ID") != "v1" {
		t.Fatal("owned write changed resource identity", status)
	}
	status, body, _ = f.request(t, "GET", path, nil, nil)
	if status != 200 || !bytes.Equal(body, want) {
		t.Fatal("owned write did not retain exact bytes", status)
	}
	status, _, _ = f.request(t, "DELETE", path, nil, first)
	if status != 204 {
		t.Fatal("owned delete failed", status)
	}
	status, _, headers = f.request(t, "POST", path, []byte("second"), create)
	if status != 201 || headers.Get("X-Resource-ID") != "v2" {
		t.Fatal("recreation reused the old resource identity", status)
	}
	status, _, _ = f.request(t, "DELETE", path, nil, first)
	if status != 412 {
		t.Fatal("old owner deleted a new resource", status)
	}
	status, _, _ = f.request(t, "DELETE", path, nil, second)
	if status != 204 || f.service.Counts() != (Counts{ValueCreates: 2, ValueWrites: 1, ValueDeletes: 2}) {
		t.Fatal("final value ownership or mutation counts differ", status, f.service.Counts())
	}
}

// full_only: false
func TestValueLimitRejectsFirstExcessBeforeMutation(t *testing.T) {
	f := newFixture(t)
	const path = "/values/workshop/eA"
	want := bytes.Repeat([]byte{0x81}, 65536)
	status, _, _ := f.request(t, "POST", path, want, map[string]string{"If-None-Match": "*"})
	if status != 201 {
		t.Fatal("maximum value refused", status)
	}
	status, _, _ = f.request(t, "PUT", path, bytes.Repeat([]byte{0x82}, 65537), map[string]string{"If-Match": `"v1"`})
	if status != 413 || f.service.Counts().ValueWrites != 0 {
		t.Fatal("first excess value reached mutation", status)
	}
	status, body, _ := f.request(t, "GET", path, nil, nil)
	if status != 200 || !bytes.Equal(body, want) {
		t.Fatal("oversized write changed the previous value", status)
	}
}

// full_only: false
func TestLostRepliesLeaveOneEffect(t *testing.T) {
	for _, family := range []string{"token", "value"} {
		t.Run(family, func(t *testing.T) {
			f := newFixture(t)
			path, body := "/tokens", []byte(`{"namespace":"workshop","subject":"api"}`)
			if family == "token" {
				f.service.LoseNextTokenReply()
			} else {
				path, body = "/values/workshop/YXBp", []byte("original")
				f.service.LoseNextValueReply()
			}
			r, err := http.NewRequestWithContext(t.Context(), "POST", f.server.URL+path, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer example-token")
			r.Header.Set("If-None-Match", "*")
			response, err := f.client.Do(r)
			if err == nil {
				if err := response.Body.Close(); err != nil {
					t.Errorf("close unexpected response: %v", err)
				}
				t.Fatal("lost acknowledgement returned a response")
			}
			want := Counts{Tokens: 1, TokenCreates: 1}
			if family == "value" {
				want = Counts{Values: 1, ValueCreates: 1}
			}
			if got := f.service.Counts(); got != want {
				t.Fatal("lost response lost or repeated the effect", got)
			}
		})
	}
}

// full_only: false
func TestUnauthorizedRequestCannotCreate(t *testing.T) {
	f := newFixture(t)
	status, _, _ := f.request(t, "POST", "/tokens", []byte(`{"namespace":"workshop","subject":"api"}`), map[string]string{"Authorization": "Bearer wrong"})
	if status != 401 || f.service.Counts() != (Counts{}) {
		t.Fatal("unauthorized request reached effect", status)
	}
}
