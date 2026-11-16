package gcpsm

import (
	"context"
	"crypto/tls"
	protocol "enkv.sh/sdk/protocols/output"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestProductionTransportDoesNotOfferHTTP2(t *testing.T) {
	hello := make(chan []string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted TLS server was reached")
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		hello <- append([]string(nil), info.SupportedProtos...)
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	transport, ok := New().transport.(*http.Transport)
	if !ok || transport.TLSClientConfig != nil || transport.DialContext != nil {
		t.Fatal("production transport no longer uses the default TLS path")
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(req)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("test server certificate was unexpectedly trusted")
	}
	select {
	case protocols := <-hello:
		if slices.Contains(protocols, "h2") {
			t.Fatalf("unqualified TLS ALPN offered: %v", protocols)
		}
	case <-ctx.Done():
		t.Fatal("TLS ClientHello was not observed")
	}
}

// full_only: false
func TestDeletionMetadataGuardRequiresExactProjection(t *testing.T) {
	command, _, _ := actionCommand(t, protocol.ActionDeleteOwned)
	for _, query := range []string{
		"alt=json&fields=name%2Cetag&prettyPrint=false",
		"alt=json&prettyPrint=false",
		"alt=json&fields=%2A&prettyPrint=false",
		"alt=json&fields=name%2Cetag%2Cannotations&prettyPrint=false",
		"alt=json&fields=name%2Cetag&fields=%2A&prettyPrint=false",
		"alt=json&fields=name%2Cetag&prettyPrint=false&other=1",
	} {
		t.Run(query, func(t *testing.T) {
			calls := 0
			guard := &operationTransport{endpoint: "https://secretmanager.test", bearer: "Bearer token-1", rules: actionRules(preparationForTest(command), "123456789012", "Enkv_output-1"), base: bodyTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"name":"` + testParent + `","etag":"etag-1"}`))}, nil
			})}
			request, err := http.NewRequest("GET", "https://secretmanager.test/v1/"+testParent+"?"+query, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer token-1")
			reply, err := guard.RoundTrip(request)
			expected := query == "alt=json&fields=name%2Cetag&prettyPrint=false"
			if (err == nil) != expected || calls != map[bool]int{false: 0, true: 1}[expected] || guard.didEnter() {
				t.Fatalf("admitted=%v calls=%d mutation=%v", err == nil, calls, guard.didEnter())
			}
			if reply != nil {
				_ = reply.Body.Close()
			}
		})
	}
}
