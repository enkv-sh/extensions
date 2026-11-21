// Package cloudflare sends and classifies one fixed Cloudflare token request.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

const requestTimeout = provider.CloudflareRequestTimeoutSeconds * time.Second

// ErrClient reports a local command or client configuration refusal.
var ErrClient = errors.New("cloudflare command refused")

// Client owns one fresh transport per command. NewProduction is the only
// production constructor and has no endpoint or transport option.
type Client struct {
	origin                string
	unqualifiedTestOrigin bool
	requestTimeout        time.Duration
	transport             func() ownedTransport
}

type ownedTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}

// NewProduction returns a client for the fixed production origin with a fresh
// transport per Execute call. The zero Client is invalid.
func NewProduction() *Client {
	return &Client{origin: profile.ProductionOrigin, requestTimeout: requestTimeout, transport: func() ownedTransport { return newProductionTransport() }}
}

func newProductionTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: provider.CloudflareDialTimeoutSeconds * time.Second, KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2:      false,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.cloudflare.com", NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout:    provider.CloudflareTLSTimeoutSeconds * time.Second,
		ResponseHeaderTimeout:  provider.CloudflareHeaderTimeoutSeconds * time.Second,
		MaxResponseHeaderBytes: provider.CloudflareMaxHeaderBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		Protocols:              protocols,
	}
}

// Execute performs at most one physical provider request. Provider failures
// return closed unknown facts; local command mismatches return ErrClient and
// do not open a connection. Inputs are borrowed only until return. A returned
// bearer is independently owned and must be cleared by the caller. No response
// or transport failure permits replay.
func (c *Client) Execute(ctx context.Context, command provider.Command, bearer []byte) (provider.SafeFacts, []byte, error) {
	if c == nil || ctx == nil || c.transport == nil || c.origin == "" || c.requestTimeout <= 0 ||
		!c.unqualifiedTestOrigin && c.requestTimeout != requestTimeout || !provider.ValidBearer(bearer) ||
		!c.unqualifiedTestOrigin && c.origin != profile.ProductionOrigin {
		return provider.SafeFacts{}, nil, ErrClient
	}
	account := [32]byte(command.Account)
	target := [32]byte(command.Target)
	intentDigest := [32]byte(command.IntentDigest)
	requestDigest := [32]byte(command.HTTPRequestDigest)
	if !profile.ValidTag(account) || intentDigest == [32]byte{} || requestDigest == [32]byte{} {
		return provider.SafeFacts{}, nil, ErrClient
	}
	userAgent := "enkv-generator-cloudflare/0.1.0"
	var httpBody []byte
	switch command.Action {
	case provider.ActionCreate:
		if command.CreateAttemptID == (provider.ID{}) || command.TargetPresent != 0 || command.Target != (provider.ID{}) {
			return provider.SafeFacts{}, nil, ErrClient
		}
		intent, parseErr := profile.ParseIntent(command.Intent, account)
		if parseErr != nil || intent.Digest != intentDigest {
			return provider.SafeFacts{}, nil, ErrClient
		}
		httpBody, parseErr = intent.RequestJSON()
		if parseErr != nil {
			return provider.SafeFacts{}, nil, ErrClient
		}
		defer clear(httpBody)
		marker := sha256.Sum256(append([]byte("ENKV/Cloudflare/audit-marker/v1\x00"), command.CreateAttemptID[:]...))
		userAgent += " audit/" + hex.EncodeToString(marker[:])
	case provider.ActionDelete:
		if command.TargetPresent != 1 || !profile.ValidTag(target) || len(command.Intent) != 0 {
			return provider.SafeFacts{}, nil, ErrClient
		}
	default:
		return provider.SafeFacts{}, nil, ErrClient
	}
	method, relativePath, contentType, ok := profile.HTTPRequestParts(command.Action, account, target)
	if !ok || profile.HTTPRequestDigest(command.Action, account, target, httpBody) != requestDigest {
		return provider.SafeFacts{}, nil, ErrClient
	}
	facts := baseFacts(provider.HTTPStatusAbsent, account, intentDigest, requestDigest)
	deadline := time.UnixMilli(int64(command.DeadlineUnixMillis))
	if command.DeadlineUnixMillis > uint64(^uint64(0)>>1) || !deadline.After(time.Now()) {
		facts.Reason = provider.ReasonDeadline
		return facts, nil, nil
	}
	requestDeadline := time.Now().Add(c.requestTimeout)
	if deadline.Before(requestDeadline) {
		requestDeadline = deadline
	}
	if ctx.Err() != nil {
		facts.Reason = provider.ReasonTransport
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			facts.Reason = provider.ReasonDeadline
		}
		return facts, nil, nil
	}
	requestContext, cancel := context.WithDeadline(ctx, requestDeadline)
	defer cancel()
	endpoint, err := url.Parse(c.origin + relativePath)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		!c.unqualifiedTestOrigin && (endpoint.Scheme != "https" || endpoint.Host != "api.cloudflare.com") {
		return provider.SafeFacts{}, nil, ErrClient
	}
	request := &http.Request{
		Method: method, URL: endpoint, Header: make(http.Header), Host: endpoint.Host,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Close: true, GetBody: nil,
	}
	request = request.WithContext(requestContext)
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", userAgent)
	if len(httpBody) > 0 {
		request.Header.Set("Content-Type", contentType)
		request.ContentLength = int64(len(httpBody))
		request.Body = newRequestBody(httpBody)
	}
	if requestContext.Err() != nil {
		facts.Reason = provider.ReasonTransport
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			facts.Reason = provider.ReasonDeadline
		}
		return facts, nil, nil
	}
	transport := c.transport()
	if transport == nil {
		return provider.SafeFacts{}, nil, ErrClient
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, requestErr := client.Do(request)
	if request.Body != nil {
		_ = request.Body.Close()
		if body, ok := request.Body.(*requestBody); ok && !body.wait(requestContext) {
			requestErr = ErrClient
		}
	}
	if requestErr != nil {
		if response != nil && response.Body != nil {
			cancel()
			_ = response.Body.Close()
		}
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			facts.Reason = provider.ReasonDeadline
		} else {
			facts.Reason = provider.ReasonTransport
		}
		return facts, nil, nil
	}
	if response == nil || response.Body == nil {
		facts.Reason = provider.ReasonTransport
		return facts, nil, nil
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" || response.Uncompressed {
		cancel()
		_ = response.Body.Close()
		facts.HTTPStatus = admittedHTTPStatus(response.StatusCode)
		facts.Reason = provider.ReasonTransport
		return facts, nil, nil
	}
	responseBody, overflow, readErr := readBoundedResponseBody(response.Body)
	if overflow {
		cancel()
		transport.CloseIdleConnections()
		_ = response.Body.Close()
		clear(responseBody)
		facts.HTTPStatus = admittedHTTPStatus(response.StatusCode)
		facts.Reason = provider.ReasonOverflow
		return facts, nil, nil
	}
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.ContentLength >= 0 && response.ContentLength != int64(len(responseBody)) {
		clear(responseBody)
		facts.HTTPStatus = admittedHTTPStatus(response.StatusCode)
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			facts.Reason = provider.ReasonDeadline
		} else {
			facts.Reason = provider.ReasonTransport
		}
		return facts, nil, nil
	}
	defer clear(responseBody)
	if command.Action == provider.ActionCreate {
		intent, _ := profile.ParseIntent(command.Intent, account)
		normalized, value := NormalizeCreate(response.StatusCode, responseBody, intent, requestDigest)
		return normalized, value, nil
	}
	return NormalizeDelete(response.StatusCode, responseBody, account, target, intentDigest, requestDigest), nil, nil
}

func readBoundedResponseBody(body io.Reader) ([]byte, bool, error) {
	value, err := io.ReadAll(io.LimitReader(body, provider.CloudflareMaxResponseBytes+1))
	return value, len(value) > provider.CloudflareMaxResponseBytes, err
}

func admittedHTTPStatus(status int) uint16 {
	if status < http.StatusContinue || status > provider.HTTPStatusMaximum {
		return 0
	}
	return uint16(status)
}

// The HTTP transport can finish body handling after Do returns. Serialize reads
// with Close before Execute clears its borrowed request allocation.
type requestBody struct {
	reader    *bytes.Reader
	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	closeOnce sync.Once
}

func newRequestBody(body []byte) *requestBody {
	return &requestBody{reader: bytes.NewReader(body), done: make(chan struct{})}
}

// Read serializes transport reads with Close while borrowing Execute's body.
func (b *requestBody) Read(out []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(out)
}

// Close prevents further reads before Execute clears its borrowed allocation.
// It is idempotent and signals the transport-body join.
func (b *requestBody) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		close(b.done)
		b.mu.Unlock()
	})
	return nil
}

func (b *requestBody) wait(ctx context.Context) bool {
	select {
	case <-b.done:
		return true
	case <-ctx.Done():
		return false
	}
}
