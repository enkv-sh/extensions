package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/plugins/outputs/github-actions/profile"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/crypto/nacl/box"
)

// full_only: false
func TestGitHubDelayedEffectBodyReadAfterExecute(t *testing.T) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0, 1, 2, 255}
	policy := testPolicy(profile.Organization)
	command := testCommand(t, profile.Organization, protocol.ActionCreateWithValue, policy, payload)
	var effectBody io.ReadCloser
	i := testImplementation(profile.Organization)
	i.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
				Body: io.NopCloser(strings.NewReader(`{"key_id":"test-key","key":"` + base64.StdEncoding.EncodeToString(public[:]) + `"}`))}, nil
		}
		effectBody = req.Body
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	got, err := i.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
	if effectBody == nil {
		t.Fatalf("effect did not reach transport: result=%#v err=%v", got, err)
	}
	defer func() {
		if err := effectBody.Close(); err != nil {
			t.Error("close delayed effect body", err)
		}
	}()
	if err != nil || got.Class != protocol.ClassAcknowledged {
		t.Fatalf("effect result=%#v err=%v", got, err)
	}
	body, readErr := io.ReadAll(effectBody)
	var fields struct {
		EncryptedValue string   `json:"encrypted_value"`
		Visibility     string   `json:"visibility"`
		Selected       []uint64 `json:"selected_repository_ids"`
	}
	if readErr != nil || json.Unmarshal(body, &fields) != nil {
		t.Fatalf("delayed body changed: read=%v bytes=%d", readErr, len(body))
	}
	sealed, decodeErr := base64.StdEncoding.Strict().DecodeString(fields.EncryptedValue)
	opened, ok := box.OpenAnonymous(nil, sealed, public, private)
	defer clear(opened)
	if decodeErr != nil || !ok || !bytes.Equal(opened, payload) || fields.Visibility != "selected" || len(fields.Selected) != 2 || fields.Selected[0] != 7 || fields.Selected[1] != 11 {
		t.Fatal("delayed sealed payload or admitted visibility changed")
	}
}

// full_only: false
func TestGitHubOutputWireBodyCustodyOnResponseErrorAndCancellation(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateWithValue, protocol.ActionWriteValue, protocol.ActionUpdatePolicy} {
		for _, encoding := range []string{"raw", "base64"} {
			for _, outcome := range []string{"response", "error", "cancel"} {
				t.Run(strconv.Itoa(int(action))+"/"+encoding+"/"+outcome, func(t *testing.T) {
					public, private, keyErr := box.GenerateKey(rand.Reader)
					if keyErr != nil {
						t.Fatal(keyErr)
					}
					payload := []byte{0, 1, 2, 255}
					if encoding == "base64" {
						payload = []byte("AAEC/w==")
					}
					if action == protocol.ActionUpdatePolicy {
						payload = nil
					}
					expectedPayload := bytes.Clone(payload)
					defer clear(expectedPayload)
					policy := testPolicy(profile.Organization)
					command := testCommand(t, profile.Organization, action, policy, payload)
					command.Target.PayloadEncoding = map[string]uint8{"raw": protocol.EncodingRaw, "base64": protocol.EncodingBase64}[encoding]
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					var owner io.ReadCloser
					reads, effects := 0, 0
					readGate, closeGate, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
					readResult := make(chan struct {
						body []byte
						err  error
					}, 1)
					implementation := testImplementation(profile.Organization)
					implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
						if req.Method == http.MethodGet {
							reads++
							response := `{"key_id":"test-key","key":"` + base64.StdEncoding.EncodeToString(public[:]) + `"}`
							if action == protocol.ActionUpdatePolicy {
								response = `{"name":"TOKEN","visibility":"selected"}`
							}
							return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(response))}, nil
						}
						effects++
						owner = req.Body
						if owner == nil {
							t.Error("effect body did not own wire storage")
							return nil, errors.New("missing wire owner")
						}
						if req.GetBody != nil || req.Method != http.MethodPut {
							t.Error("effect body changed exact request contract")
						}
						go func() {
							<-readGate
							body, err := io.ReadAll(owner)
							readResult <- struct {
								body []byte
								err  error
							}{body, err}
							<-closeGate
							if err := owner.Close(); err != nil {
								t.Error(err)
							}
							close(joined)
						}()
						if outcome == "error" {
							return nil, errors.New("controlled transport failure")
						}
						if outcome == "cancel" {
							cancel()
							return nil, context.Canceled
						}
						status := http.StatusNoContent
						if action == protocol.ActionCreateWithValue {
							status = http.StatusCreated
						}
						return &http.Response{StatusCode: status, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(""))}, nil
					})
					got, err := implementation.executeForTest(ctx, command, policy, payload, []byte("github_pat_TEST"))
					if owner == nil {
						t.Fatalf("effect did not reach owned transport: result=%#v err=%v reads=%d effects=%d", got, err, reads, effects)
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
							t.Error("transport cleanup did not join")
						}
					}()
					wantClass := protocol.OutcomeClass(protocol.ClassAcknowledged)
					if outcome != "response" {
						wantClass = protocol.ClassUnproved
					}
					if err != nil || got.Class != wantClass || got.Entry != protocol.EntryMayHaveEntered || reads != 1 || effects != 1 {
						t.Fatalf("result=%#v err=%v reads=%d effects=%d", got, err, reads, effects)
					}
					clear(payload)
					close(readGate)
					var wire []byte
					select {
					case read := <-readResult:
						if read.err != nil {
							t.Fatal("delayed transport read", read.err)
						}
						wire = read.body
					case <-time.After(time.Second):
						t.Fatal("delayed transport reader did not settle")
					}
					defer clear(wire)
					if action == protocol.ActionUpdatePolicy {
						if string(wire) != `{"selected_repository_ids":[7,11]}` {
							t.Fatal("delayed organization policy body changed")
						}
					} else {
						var fields map[string]json.RawMessage
						if json.Unmarshal(wire, &fields) != nil || len(fields) != 4 || string(fields["key_id"]) != `"test-key"` || string(fields["visibility"]) != `"selected"` || string(fields["selected_repository_ids"]) != `[7,11]` {
							t.Fatal("delayed encrypted body or visibility changed")
						}
						var encrypted string
						if json.Unmarshal(fields["encrypted_value"], &encrypted) != nil {
							t.Fatal("delayed ciphertext is not JSON")
						}
						sealed, decodeErr := base64.StdEncoding.Strict().DecodeString(encrypted)
						opened, ok := box.OpenAnonymous(nil, sealed, public, private)
						if decodeErr != nil || !ok || !bytes.Equal(opened, expectedPayload) {
							clear(opened)
							clear(sealed)
							t.Fatal("delayed ciphertext changed application bytes")
						}
						clear(opened)
						clear(sealed)
					}
					close(closeGate)
					select {
					case <-joined:
					case <-time.After(time.Second):
						t.Fatal("delayed transport closer did not join")
					}
					if owner.Close() != nil {
						t.Fatal("repeated body Close failed")
					}
					if n, err := owner.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatal("closed body remained readable")
					}
				})
			}
		}
	}
}
