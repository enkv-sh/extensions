package github

import (
	"context"
	"crypto/tls"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"net/http"
	"net/http/httptest"
	"slices"
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
	transport, ok := testImplementation(profile.Repository).transport.(*http.Transport)
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
