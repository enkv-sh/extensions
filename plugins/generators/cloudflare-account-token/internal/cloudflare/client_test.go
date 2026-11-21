package cloudflare

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

func testClient(origin string) *Client {
	return &Client{origin: origin, unqualifiedTestOrigin: true, requestTimeout: requestTimeout, transport: func() ownedTransport {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		return &http.Transport{
			TLSClientConfig:        &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, // test server only
			Protocols:              protocols,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 << 10,
			ResponseHeaderTimeout:  20 * time.Second,
		}
	}}
}

type testOwnedTransport struct {
	requests  atomic.Int32
	roundTrip func(*http.Request) (*http.Response, error)
}

func (t *testOwnedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.requests.Add(1)
	return t.roundTrip(request)
}

func (*testOwnedTransport) CloseIdleConnections() {}

type closeErrorBody struct {
	io.Reader
}

func (*closeErrorBody) Close() error { return errors.New("injected close failure") }

func createCommand(t *testing.T, responseValue string) (provider.Command, []byte, []byte) {
	t.Helper()
	intentBody, account, _ := testIntent(t)
	intent, err := profile.ParseIntent(intentBody, account)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := intent.RequestJSON()
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := profile.HTTPRequestDigest(1, account, [32]byte{}, requestBody)
	command := provider.Command{Action: 1, CreateAttemptID: provider.ID{1}, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()),
		HTTPRequestDigest: provider.ID(requestDigest), IntentDigest: provider.ID(intent.Digest), Account: provider.ID(account), Intent: intentBody}
	response, _, _ := createEnvelope(t, responseValue)
	return command, []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"), response
}

// full_only: false
func TestProductionTransportIsOwnedHTTP1Only(t *testing.T) {
	transport := newProductionTransport()
	if transport.Proxy != nil || !transport.DisableKeepAlives || !transport.DisableCompression || transport.ForceAttemptHTTP2 ||
		transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() || transport.Protocols.UnencryptedHTTP2() ||
		transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "api.cloudflare.com" ||
		transport.MaxResponseHeaderBytes != 16<<10 || transport.DialContext == nil {
		t.Fatalf("transport is not closed: %+v", transport)
	}
}

// full_only: false
func TestProductionCreateUserAgentBindsAttempt(t *testing.T) {
	command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	client := NewProduction()
	var agents []string
	client.transport = func() ownedTransport {
		return &testOwnedTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
			agents = append(agents, r.UserAgent())
			r.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}}
	}
	// Python hashlib.sha256 over the NUL-terminated v1 prefix and 32 raw
	// bytes, first byte 01 or 02 followed by 31 zero bytes.
	for i, digest := range []string{
		"2822afe9d00715da82ad1c6bca0cc7f29be5ef86ae21dd74e9bee9bedcf79333",
		"4b250dc941ace32888849d638947a9007a31d98854fdbdabcbe949d7c0b7aaf7",
	} {
		command.CreateAttemptID = provider.ID{byte(i + 1)}
		facts, value, err := client.Execute(t.Context(), command, bearer)
		if err != nil || value != nil || facts.Disposition != provider.DispositionUnknown || facts.TokenPresent != 0 ||
			len(agents) != i+1 || agents[i] != "enkv-generator-cloudflare/0.1.0 audit/"+digest {
			t.Errorf("CREATE %d did not send its exact marker once and retain an unknown outcome", i+1)
		}
	}
	command.CreateAttemptID = provider.ID{}
	if _, _, err := client.Execute(t.Context(), command, bearer); !errors.Is(err, ErrClient) || len(agents) != 2 {
		t.Fatal("CREATE with no Attempt ID reached the transport or was accepted")
	}
}

// full_only: false
func TestExecuteCreateUsesOnePhysicalHTTP1RequestAgainstHTTP2Server(t *testing.T) {
	command, bearer, response := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	var requests, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens" || r.GetBody != nil || !r.Close ||
			r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer "+string(bearer) || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: method=%s url=%s getbody=%v close=%v proto=%s headers=%v", r.Method, r.URL, r.GetBody != nil, r.Close, r.Proto, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	if !slices.Contains(server.TLS.NextProtos, "h2") {
		t.Fatal("test server did not offer HTTP/2")
	}
	facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, bearer)
	defer clear(value)
	if err != nil || facts.Disposition != 1 || requests.Load() != 1 || connections.Load() != 1 {
		t.Fatalf("execute = facts=%+v value=%q err=%v requests=%d connections=%d", facts, value, err, requests.Load(), connections.Load())
	}
}

// full_only: false
func TestRedirectsNeverReachTargetAndNeverRetry(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
			var targetRequests, originRequests atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetRequests.Add(1) }))
			defer target.Close()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				originRequests.Add(1)
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer origin.Close()
			facts, value, err := testClient(origin.URL+"/client/v4").Execute(context.Background(), command, bearer)
			if err != nil || facts.Disposition != 4 || facts.Reason != 7 || len(value) != 0 || originRequests.Load() != 1 || targetRequests.Load() != 0 {
				t.Fatalf("redirect escaped: facts=%+v err=%v origin=%d target=%d", facts, err, originRequests.Load(), targetRequests.Load())
			}
		})
	}
}

// full_only: false
func TestTransportFailuresAndOverflowDoNotRetry(t *testing.T) {
	tests := map[string]http.Handler{
		"429": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"rate"}],"messages":[],"result":null}`)
		}),
		"500": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"success":false,"errors":[],"messages":[],"result":null}`)
		}),
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, bearer)
			if err != nil || facts.Disposition != 4 || len(value) != 0 || requests.Load() != 1 {
				t.Fatalf("failure escaped: facts=%+v err=%v requests=%d", facts, err, requests.Load())
			}
			if facts.Reason != 7 {
				t.Fatalf("reason = %d", facts.Reason)
			}
		})
	}
}

// full_only: false
func TestResponseBodyOverflowIsDetectedAtLimitPlusOne(t *testing.T) {
	body, overflow, err := readBoundedResponseBody(bytes.NewReader(make([]byte, provider.CloudflareMaxResponseBytes+1)))
	defer clear(body)
	if err != nil || !overflow || len(body) != provider.CloudflareMaxResponseBytes+1 {
		t.Fatalf("body=%d overflow=%v err=%v", len(body), overflow, err)
	}
}

// full_only: false
func TestEveryCommandOwnsAFreshConnection(t *testing.T) {
	command, bearer, response := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	var requests, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(response)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	client := testClient(server.URL + "/client/v4")
	for i := 0; i < 2; i++ {
		facts, value, err := client.Execute(context.Background(), command, bearer)
		clear(value)
		if err != nil || facts.Disposition != 1 {
			t.Fatalf("execute %d = facts=%+v err=%v", i, facts, err)
		}
	}
	if requests.Load() != 2 || connections.Load() != 2 {
		t.Fatalf("requests=%d connections=%d", requests.Load(), connections.Load())
	}
}

// full_only: false
func TestEarlyEOFAndDeadlineDoNotRetry(t *testing.T) {
	t.Run("early EOF", func(t *testing.T) {
		command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("server cannot hijack")
			}
			connection, buffer, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
			_ = buffer.Flush()
			_ = connection.Close()
		}))
		defer server.Close()
		facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, bearer)
		if err != nil || facts.Disposition != 4 || facts.Reason != 8 || len(value) != 0 || requests.Load() != 1 {
			t.Fatalf("early EOF escaped: facts=%+v err=%v requests=%d", facts, err, requests.Load())
		}
	})
	t.Run("deadline", func(t *testing.T) {
		command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
		command.DeadlineUnixMillis = uint64(time.Now().Add(150 * time.Millisecond).UnixMilli())
		var requests atomic.Int32
		release := make(chan struct{})
		server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		defer server.Close()
		started := time.Now()
		facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, bearer)
		close(release)
		if elapsed := time.Since(started); err != nil || facts.Disposition != 4 || facts.Reason != 9 || len(value) != 0 || requests.Load() != 1 || elapsed > 2*time.Second {
			t.Fatalf("deadline escaped: facts=%+v err=%v requests=%d elapsed=%s", facts, err, requests.Load(), elapsed)
		}
	})
}

// full_only: false
func TestCallerCancellationDoesNotRetry(t *testing.T) {
	command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	started := make(chan struct{})
	transport := &testOwnedTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	}}
	client := &Client{origin: "https://fixture.invalid/client/v4", unqualifiedTestOrigin: true, requestTimeout: requestTimeout,
		transport: func() ownedTransport { return transport }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var facts provider.SafeFacts
	var value []byte
	var err error
	go func() {
		facts, value, err = client.Execute(ctx, command, bearer)
		close(done)
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not join")
	}
	if err != nil || facts.Disposition != 4 || facts.Reason != 8 || len(value) != 0 || transport.requests.Load() != 1 {
		t.Fatalf("cancellation escaped: facts=%+v value=%d err=%v requests=%d", facts, len(value), err, transport.requests.Load())
	}
}

// full_only: false
func TestCancelledCallerDoesNotConstructTransport(t *testing.T) {
	command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	created := 0
	client := &Client{origin: "https://fixture.invalid/client/v4", unqualifiedTestOrigin: true, requestTimeout: requestTimeout,
		transport: func() ownedTransport { created++; return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	facts, value, err := client.Execute(ctx, command, bearer)
	if err != nil || facts.Disposition != 4 || facts.Reason != 8 || len(value) != 0 || created != 0 {
		t.Fatalf("cancelled input: disposition=%d reason=%d transport=%d err=%v", facts.Disposition, facts.Reason, created, err)
	}
}

// full_only: false
func TestResponseCloseFailureDoesNotRetry(t *testing.T) {
	command, bearer, responseBody := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	transport := &testOwnedTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        make(http.Header),
			Body:          &closeErrorBody{Reader: bytes.NewReader(responseBody)},
			ContentLength: int64(len(responseBody)),
			Request:       request,
		}, nil
	}}
	client := &Client{origin: "https://fixture.invalid/client/v4", unqualifiedTestOrigin: true, requestTimeout: requestTimeout,
		transport: func() ownedTransport { return transport }}
	facts, value, err := client.Execute(context.Background(), command, bearer)
	if err != nil || facts.Disposition != 4 || facts.Reason != 8 || facts.HTTPStatus != http.StatusOK || len(value) != 0 || transport.requests.Load() != 1 {
		t.Fatalf("close failure escaped: facts=%+v value=%d err=%v requests=%d", facts, len(value), err, transport.requests.Load())
	}
}

// full_only: false
func TestExpiredCommandDoesNotSend(t *testing.T) {
	command, bearer, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	command.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, bearer)
	if err != nil || facts.Disposition != 4 || facts.Reason != 9 || len(value) != 0 || requests.Load() != 0 {
		t.Fatalf("expired command sent: facts=%+v err=%v requests=%d", facts, err, requests.Load())
	}
}

// full_only: false
func TestProviderCredentialRejectionRemainsUnknownAndSendsOnce(t *testing.T) {
	for _, test := range []struct {
		name, bearer string
		status       int
	}{
		{"legacy denied", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", http.StatusForbidden},
		{"account token expired", "cfat_0123456789abcdefghijklmnopqrstuvwxyzABCD_012345", http.StatusUnauthorized},
		{"user token denied", "cfut_0123456789abcdefghijklmnopqrstuvwxyzABCD_012345", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, _, _ := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+test.bearer {
					t.Error("credential bytes changed before provider authentication")
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"credential rejected"}],"messages":[],"result":null}`)
			}))
			defer server.Close()
			facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, []byte(test.bearer))
			defer clear(value)
			if err != nil || facts.Disposition != provider.DispositionUnknown || facts.Reason != provider.ReasonRejected || facts.HTTPStatus != uint16(test.status) ||
				len(value) != 0 || requests.Load() != 1 || !slices.Equal(facts.ErrorCodes, []uint32{9109}) {
				t.Fatal("provider credential rejection changed uncertainty or send count", err, facts, requests.Load())
			}
		})
	}
}

// full_only: false
func TestDeleteUsesExplicitRetainedIntentDigest(t *testing.T) {
	account, target, intentDigest := testTag(0), testTag(3), testTag(7)
	requestDigest := profile.HTTPRequestDigest(2, account, target, nil)
	command := provider.Command{Action: 2, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), HTTPRequestDigest: provider.ID(requestDigest),
		IntentDigest: provider.ID(intentDigest), Account: provider.ID(account), TargetPresent: 1, Target: provider.ID(target)}
	response := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, target))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "enkv-generator-cloudflare/0.1.0" || r.Method != http.MethodDelete || r.URL.Path != "/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/3456789abcdef0123456789abcdef012" || r.ContentLength > 0 || r.GetBody != nil {
			t.Errorf("unexpected delete request: %+v", r)
		}
		_, _ = w.Write(response)
	}))
	defer server.Close()
	facts, value, err := testClient(server.URL+"/client/v4").Execute(context.Background(), command, []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"))
	if err != nil || facts.Disposition != 3 || facts.IntentDigest != provider.ID(intentDigest) || len(value) != 0 {
		t.Fatalf("delete = facts=%+v err=%v", facts, err)
	}
}
