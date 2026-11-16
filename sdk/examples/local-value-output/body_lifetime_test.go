package main

import (
	"bytes"
	"context"
	protocol "enkv.sh/sdk/protocols/output"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type bodyTestTransport func(*http.Request) (*http.Response, error)

func (f bodyTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// full_only: false
func TestLocalOutputDelayedBodyReadAfterSend(t *testing.T) {
	for _, outcome := range []string{"response", "error", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			implementation, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("borrowed private bytes")
			command := authorCommand(t, implementation, "http://127.0.0.1:12345", "value", protocol.ActionCreateWithValue, payload, "")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			readGate, closeGate, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			read := make(chan []byte, 1)
			calls := 0
			var body io.ReadCloser
			p := &prepared{command: preparationForTest(command), token: []byte("local-token"), transport: &http.Transport{}}
			p.client = &http.Client{Transport: bodyTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body = req.Body
				if req.ContentLength != int64(len(payload)) || req.GetBody != nil {
					t.Error("request length or replay contract changed")
				}
				go func() {
					defer close(joined)
					<-readGate
					data, readErr := io.ReadAll(req.Body)
					if readErr != nil {
						t.Error(readErr)
					}
					read <- data
					<-closeGate
					if err := req.Body.Close(); err != nil {
						t.Error(err)
					}
				}()
				if outcome == "error" {
					return nil, errors.New("controlled transport error")
				}
				if outcome == "cancel" {
					cancel()
					return nil, context.Canceled
				}
				return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"X-Resource-Id": {"v1"}, "Etag": {`"v1"`}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})}
			defer func() {
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			}()
			result, err := p.Send(ctx, payload)
			if body == nil {
				t.Fatal("request did not enter transport", err)
			}
			defer func() {
				select {
				case <-readGate:
				default:
					close(readGate)
				}
				select {
				case <-closeGate:
				default:
					close(closeGate)
				}
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("transport user did not join")
				}
			}()
			if result.Entry != protocol.EntryMayHaveEntered || calls != 1 || (outcome == "response" && (err != nil || result.Class != protocol.ClassAcknowledged)) || (outcome != "response" && (err == nil || result.Class != protocol.ClassUnproved)) {
				t.Fatal("effect evidence changed", result, err, calls)
			}
			clear(payload)
			close(readGate)
			select {
			case got := <-read:
				if !bytes.Equal(got, []byte("borrowed private bytes")) {
					t.Error("late Read used borrowed or disposed bytes")
				}
			case <-time.After(time.Second):
				t.Fatal("late Read did not settle")
			}
			close(closeGate)
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("Close did not join")
			}
			if n, err := body.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Error("closed transport body remained readable")
			}
			if _, err := p.Send(ctx, payload); err == nil || calls != 1 {
				t.Error("prepared send replayed")
			}
		})
	}
}

// full_only: false
func TestLocalOutputEmptyValueAndMetadataRequestBodies(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateWithValue, protocol.ActionWriteValue, protocol.ActionDeleteOwned} {
		implementation, err := newImplementation()
		if err != nil {
			t.Fatal(err)
		}
		payload, owned := []byte{}, "v1"
		if action == protocol.ActionCreateWithValue {
			owned = ""
		}
		if action == protocol.ActionDeleteOwned {
			payload = nil
		}
		command := authorCommand(t, implementation, "http://127.0.0.1:12345", "value", action, payload, owned)
		calls := 0
		p := &prepared{command: preparationForTest(command), token: []byte("local-token"), transport: &http.Transport{}}
		p.client = &http.Client{Transport: bodyTestTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.ContentLength != 0 || req.Body != http.NoBody || req.GetBody != nil {
				t.Error("empty request body semantics changed")
			}
			status := http.StatusNoContent
			if action == protocol.ActionCreateWithValue {
				status = http.StatusCreated
			}
			return &http.Response{StatusCode: status, Header: http.Header{"X-Resource-Id": {"v1"}, "Etag": {`"v1"`}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})}
		result, err := p.Send(t.Context(), payload)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if err != nil || result.Class != protocol.ClassAcknowledged || calls != 1 {
			t.Fatal("empty action changed", action, result, err, calls)
		}
	}
}
