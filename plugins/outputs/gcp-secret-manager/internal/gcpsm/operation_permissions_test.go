package gcpsm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestGCPOutputWireBodyCustodyOnResponseErrorAndCancellation(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		for _, outcome := range []string{"response", "error", "cancel"} {
			t.Run(encoding+"/"+outcome, func(t *testing.T) {
				payload, wirePayload, checksum := []byte("123456789"), "MTIzNDU2Nzg5", "3808858755"
				// The Base64 checksum literal was derived independently with the
				// reflected Castagnoli polynomial 0x82f63b78 and initial/final XOR.
				if encoding == "base64" {
					payload, wirePayload, checksum = []byte("MTIzNDU2Nzg5"), "TVRJek5EVTJOemc1", "3793270396"
				}
				command, policy := testCommand(t, payload)
				command.Target.PayloadEncoding = testEncoding(encoding)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var owner io.ReadCloser
				readGate, closeGate, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
				readResult := make(chan struct {
					body []byte
					err  error
				}, 1)
				i := New()
				i.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
					owner = req.Body
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
					if req.Header.Get("Authorization") != "Bearer token-1" || req.Header.Get("Content-Type") != "application/json" ||
						req.URL.EscapedPath() != "/v1/"+testParent+":addVersion" || req.URL.RawQuery != "alt=json&prettyPrint=false" || req.GetBody != nil || !req.Close {
						t.Error("admitted request fields changed")
					}
					if outcome == "error" {
						return nil, errors.New("controlled transport failure")
					}
					if outcome == "cancel" {
						cancel()
						return nil, context.Canceled
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
						Body: io.NopCloser(strings.NewReader(`{"name":"` + testParent + `/versions/42","clientSpecifiedPayloadChecksum":true}`))}, nil
				})
				got, err := i.execute(ctx, command, policy, payload, testCredential("token-1"))
				if owner == nil {
					t.Fatalf("request did not reach transport: result=%#v err=%v", got, err)
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
				if err != nil || got.Class != wantClass || got.Entry != protocol.EntryMayHaveEntered {
					t.Fatalf("result=%#v err=%v", got, err)
				}
				clear(payload)
				close(readGate)
				var body []byte
				var readErr error
				select {
				case read := <-readResult:
					body, readErr = read.body, read.err
				case <-time.After(time.Second):
					t.Fatal("delayed transport reader did not settle")
				}
				want := `{"payload":{"data":"` + wirePayload + `","dataCrc32c":"` + checksum + `"}}`
				if readErr != nil || string(body) != want {
					t.Fatalf("delayed body differs: read=%v bytes=%d", readErr, len(body))
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

// full_only: false
func TestGCPCloudPolicyActionRefusesBeforeTransport(t *testing.T) {
	command, _, _ := actionCommand(t, protocol.ActionWriteValue)
	command.Action = protocol.ActionUpdatePolicy
	command.PayloadLengthMode, command.PayloadLength, command.ValueBasisDigest = protocol.LengthAbsent, 0, protocol.ID{}
	policy := protocol.Policy{ContractID: "gcp-secret-manager/secret-accessor", Data: testPolicyData([]string{"serviceAccount:reader@example.iam.gserviceaccount.com"})}
	var digestErr error
	command.PolicyDigest, digestErr = protocol.PolicyDigest(command.DomainID, policy)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	command.PolicyContractID = policy.ContractID
	var payload []byte
	gets, sets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			_, _ = io.WriteString(w, `{"etag":"etag-1","version":1}`)
			return
		}
		sets++
		_, _ = io.WriteString(w, `{"etag":"etag-2","version":1,"bindings":[{"role":"roles/secretmanager.secretAccessor","members":["serviceAccount:reader@example.iam.gserviceaccount.com"]}]}`)
	}))
	defer server.Close()
	got, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
	if err != nil || gets != 0 || sets != 0 || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
		t.Fatalf("cloud policy refusal: result=%#v err=%v policy-reads=%d policy-writes=%d", got, err, gets, sets)
	}
}

// full_only: false
func TestGCPLegacyCloudPolicyInputsRefuseValueRequests(t *testing.T) {
	for _, subjects := range [][]string{nil, {"serviceAccount:reader@example.iam.gserviceaccount.com"}} {
		name := "empty"
		if len(subjects) != 0 {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			command, _, payload := actionCommand(t, protocol.ActionWriteValue)
			policy := protocol.Policy{ContractID: "gcp-secret-manager/secret-accessor", Data: testPolicyData(subjects)}
			var err error
			command.PolicyDigest, err = protocol.PolicyDigest(command.DomainID, policy)
			if err != nil {
				t.Fatal(err)
			}
			command.PolicyContractID = policy.ContractID
			calls := 0
			implementation := New()
			implementation.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				_ = req.Body.Close()
				return nil, errors.New("cloud policy must refuse before provider request")
			})
			got, err := implementation.execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || calls != 0 || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
				t.Fatalf("legacy policy admitted: result=%#v err=%v calls=%d", got, err, calls)
			}
		})
	}
}

// full_only: false
func TestGCPExecutionAccessDeniedNeverRepairsPermissions(t *testing.T) {
	for _, action := range []struct {
		name         string
		code         protocol.Action
		method, path string
		metadata     bool
	}{
		{"create", protocol.ActionCreateEmpty, http.MethodPost, "/v1/projects/123456789012/secrets", false},
		{"write", protocol.ActionWriteValue, http.MethodPost, "/v1/" + testParent + ":addVersion", false},
		{"owned-delete", protocol.ActionDeleteOwned, http.MethodDelete, "/v1/" + testParent, true},
		{"reserved-delete", protocol.ActionDeleteReservedSlot, http.MethodDelete, "/v1/" + testParent, true},
	} {
		for _, encoding := range []string{"raw", "base64"} {
			t.Run(action.name+"/"+encoding, func(t *testing.T) {
				command, policy, payload := actionCommand(t, action.code)
				command.Target.PayloadEncoding = testEncoding(encoding)
				if encoding == "base64" && action.code == protocol.ActionWriteValue {
					payload = []byte("b25lIGVudHJ5IHZhbHVl")
					command.PayloadLength = uint32(len(payload))
				}
				metadata, effects, other := 0, 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.Method == http.MethodGet && req.URL.EscapedPath() == "/v1/"+testParent && action.metadata && metadata == 0 && effects == 0 {
						metadata++
						_, _ = io.WriteString(w, `{"name":"`+testParent+`","etag":"etag-1"}`)
						return
					}
					if req.Method != action.method || req.URL.EscapedPath() != action.path {
						other++
					}
					effects++
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Execution access denied","status":"PERMISSION_DENIED"}}`)
				}))
				defer server.Close()
				got, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
				wantMetadata := 0
				if action.metadata {
					wantMetadata = 1
				}
				if err != nil || metadata != wantMetadata || effects != 1 || other != 0 || got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved || got.SafeResourceID != "" {
					t.Fatalf("access denial changed execution or repaired permissions: result=%#v err=%v metadata=%d effects=%d other=%d", got, err, metadata, effects, other)
				}
			})
		}
	}
}
