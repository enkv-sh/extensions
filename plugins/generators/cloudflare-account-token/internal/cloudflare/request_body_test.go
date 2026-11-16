package cloudflare

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

// full_only: false
func TestExecuteClosesBorrowedRequestBeforeReturn(t *testing.T) {
	command, bearer, response := createCommand(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	var borrowed io.ReadCloser
	transport := &testOwnedTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		borrowed = request.Body
		if borrowed == nil {
			t.Fatal("create request has no body")
		}
		if _, err := io.ReadAll(borrowed); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(response)), ContentLength: int64(len(response))}, nil
	}}
	client := &Client{origin: "https://fixture.invalid/client/v4", unqualifiedTestOrigin: true, requestTimeout: requestTimeout,
		transport: func() ownedTransport { return transport }}
	facts, value, err := client.Execute(t.Context(), command, bearer)
	defer clear(value)
	if err != nil || facts.Disposition != 1 || transport.requests.Load() != 1 {
		t.Fatal("complete create did not retain its one request", facts, err, transport.requests.Load())
	}
	if n, err := borrowed.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("returned transport can still read borrowed body", n, err)
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal("repeated close failed", err)
	}
	body := borrowed.(*requestBody)
	if !body.wait(context.Background()) {
		t.Fatal("closed body did not retain its positive join")
	}
}
