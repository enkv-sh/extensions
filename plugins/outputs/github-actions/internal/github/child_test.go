package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/crypto/nacl/box"
)

// The child uses the production constructor. Only this test's private route
// changes. Production commands have no endpoint override.
// full_only: false
func TestGitHubChildProtocolOneSend(t *testing.T) {
	if os.Getenv("ENKV_GITHUB_OUTPUT_CHILD") == "1" {
		number, err := strconv.Atoi(os.Getenv("ENKV_GITHUB_OUTPUT_SCOPE"))
		if err != nil {
			os.Exit(2)
		}
		implementation := testImplementation(profile.Scope(number))
		implementation.endpoint = os.Getenv("ENKV_GITHUB_OUTPUT_ENDPOINT")
		control, credential, payload, result := os.NewFile(3, "control"), os.NewFile(4, "credential"),
			os.NewFile(5, "payload"), os.NewFile(6, "result")
		status := output.Run(context.Background(), output.Endpoints{Control: control,
			Credential: credential, Payload: payload, Result: result}, implementation)
		for _, file := range []*os.File{control, credential, payload, result} {
			if file.Close() != nil {
				os.Exit(2)
			}
		}
		if status != 0 {
			os.Exit(status)
		}
		return
	}
	for _, tc := range []struct {
		name    string
		scope   profile.Scope
		action  protocol.Action
		variant string
	}{
		{"repository-create-201", profile.Repository, protocol.ActionCreateWithValue, "ack"},
		{"repository-create-204", profile.Repository, protocol.ActionCreateWithValue, "create-204"},
		{"repository-write-204", profile.Repository, protocol.ActionWriteValue, "ack"},
		{"repository-key-reject", profile.Repository, protocol.ActionCreateWithValue, "key-reject"},
		{"repository-get-401", profile.Repository, protocol.ActionCreateWithValue, "get-401"},
		{"repository-get-redirect", profile.Repository, protocol.ActionCreateWithValue, "get-redirect"},
		{"repository-put-403", profile.Repository, protocol.ActionCreateWithValue, "effect-403"},
		{"repository-response-lost", profile.Repository, protocol.ActionCreateWithValue, "response-lost"},
		{"repository-tls-failure", profile.Repository, protocol.ActionCreateWithValue, "tls-failure"},
		{"organization-create-201", profile.Organization, protocol.ActionCreateWithValue, "ack"},
		{"organization-policy-204", profile.Organization, protocol.ActionUpdatePolicy, "ack"},
		{"organization-policy-metadata-reject", profile.Organization, protocol.ActionUpdatePolicy, "metadata-reject"},
		{"organization-policy-429", profile.Organization, protocol.ActionUpdatePolicy, "effect-429"},
		{"environment-create-201", profile.Environment, protocol.ActionCreateWithValue, "ack"},
		{"environment-delete-204", profile.Environment, protocol.ActionDeleteOwned, "ack"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := box.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			policy := testPolicy(tc.scope)
			if tc.action >= protocol.ActionDeleteOwned {
				policy = profile.Policy{}
			}
			var payload []byte
			if tc.action == protocol.ActionCreateWithValue || tc.action == protocol.ActionWriteValue {
				payload = []byte("private child output")
			}
			command := testCommand(t, tc.scope, tc.action, policy, payload)
			target, err := parseCanonicalTarget(tc.scope, command.Target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			var reads, effects, bad atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 1 || r.GetBody != nil || !r.Close ||
					r.Header.Get("Authorization") != "Bearer github_pat_TEST" ||
					r.Header.Get("X-GitHub-Api-Version") != apiVersion || r.URL.RawQuery != "" {
					bad.Add(1)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch {
				case r.Method == http.MethodGet && r.URL.EscapedPath() == target.KeyPath &&
					(tc.action == protocol.ActionCreateWithValue || tc.action == protocol.ActionWriteValue):
					reads.Add(1)
					switch tc.variant {
					case "key-reject":
						_, _ = io.WriteString(w, `{"key_id":"test-key","key":"invalid"}`)
					case "get-401":
						w.WriteHeader(http.StatusUnauthorized)
					case "get-redirect":
						http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
					default:
						_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "test-key",
							"key": base64.StdEncoding.EncodeToString(public[:])})
					}
				case r.Method == http.MethodGet && r.URL.EscapedPath() == target.SecretPath &&
					tc.action == protocol.ActionUpdatePolicy:
					reads.Add(1)
					if tc.variant == "metadata-reject" {
						_, _ = io.WriteString(w, `{"name":"TOKEN","visibility":"all"}`)
					} else {
						_, _ = io.WriteString(w, `{"name":"TOKEN","visibility":"selected"}`)
					}
				case r.Method == http.MethodPut && (r.URL.EscapedPath() == target.SecretPath ||
					r.URL.EscapedPath() == target.PolicyPath):
					effects.Add(1)
					wire, readErr := io.ReadAll(io.LimitReader(r.Body, maximumPutBodyBytes+1))
					if readErr != nil || len(wire) > maximumPutBodyBytes {
						bad.Add(1)
						w.WriteHeader(400)
						return
					}
					if tc.action == protocol.ActionUpdatePolicy {
						if string(wire) != `{"selected_repository_ids":[7,11]}` {
							bad.Add(1)
						}
					} else {
						var body struct {
							EncryptedValue string   `json:"encrypted_value"`
							KeyID          string   `json:"key_id"`
							Visibility     string   `json:"visibility"`
							Selected       []uint64 `json:"selected_repository_ids"`
						}
						if json.Unmarshal(wire, &body) != nil || body.KeyID != "test-key" {
							bad.Add(1)
						} else {
							sealed, decodeErr := base64.StdEncoding.Strict().DecodeString(body.EncryptedValue)
							plain, ok := box.OpenAnonymous(nil, sealed, public, private)
							if decodeErr != nil || !ok || !bytes.Equal(plain, payload) {
								bad.Add(1)
							}
							if tc.scope == profile.Organization && (body.Visibility != "selected" ||
								len(body.Selected) != 2 || body.Selected[0] != 7 || body.Selected[1] != 11) {
								bad.Add(1)
							}
						}
					}
					switch tc.variant {
					case "create-204":
						w.WriteHeader(http.StatusNoContent)
					case "effect-403":
						w.WriteHeader(http.StatusForbidden)
					case "effect-429":
						w.WriteHeader(http.StatusTooManyRequests)
					case "response-lost":
						if connection, _, err := w.(http.Hijacker).Hijack(); err == nil {
							_ = connection.Close()
						}
					default:
						if tc.action == protocol.ActionCreateWithValue {
							w.WriteHeader(http.StatusCreated)
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
					}
				case r.Method == http.MethodDelete && r.URL.EscapedPath() == target.SecretPath:
					effects.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					bad.Add(1)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			var server *httptest.Server
			if tc.variant == "tls-failure" {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			result := runGitHubChildWire(t, server.URL, tc.scope, command, policy, payload, []byte("github_pat_TEST"))
			wantRead, wantEffect := int32(1), int32(1)
			if tc.action == protocol.ActionDeleteOwned {
				wantRead = 0
			}
			if tc.variant == "tls-failure" {
				wantRead, wantEffect = 0, 0
			}
			if tc.variant == "key-reject" || tc.variant == "get-401" ||
				tc.variant == "get-redirect" || tc.variant == "metadata-reject" {
				wantEffect = 0
			}
			if reads.Load() != wantRead || effects.Load() != wantEffect || bad.Load() != 0 {
				t.Fatalf("request count/shape: reads=%d effects=%d bad=%d",
					reads.Load(), effects.Load(), bad.Load())
			}
			if wantEffect == 0 {
				if result.Entry != protocol.EntryNotEntered || result.Class != protocol.ClassQualifiedNoEffect {
					t.Fatalf("pre-entry result=%#v", result)
				}
			} else if tc.variant == "ack" {
				status := uint16(http.StatusNoContent)
				if tc.action == protocol.ActionCreateWithValue {
					status = http.StatusCreated
				}
				if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged ||
					result.NormalizedStatus != status {
					t.Fatalf("ACK result=%#v", result)
				}
			} else if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved {
				t.Fatalf("possible-entry result=%#v", result)
			}
		})
	}
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionDeleteOwned} {
		name := "retained-old-write-after-create"
		if action == protocol.ActionDeleteOwned {
			name = "retained-old-delete-after-create"
		}
		t.Run(name, func(t *testing.T) { githubChildRetainedOldRequest(t, action) })
	}

}

func runGitHubChildWire(t *testing.T, endpoint string, scope profile.Scope, command protocol.Command, policy profile.Policy, payload, credential []byte) protocol.Result {
	t.Helper()
	controlR, controlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	credentialR, credentialW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	payloadR, payloadW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	resultR, resultW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{controlR, controlW, credentialR, credentialW, payloadR, payloadW, resultR, resultW} {
		defer func(f *os.File) { _ = f.Close() }(file)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGitHubChildProtocolOneSend$")
	child.Env = append(os.Environ(), "ENKV_GITHUB_OUTPUT_CHILD=1", "ENKV_GITHUB_OUTPUT_ENDPOINT="+endpoint, "ENKV_GITHUB_OUTPUT_SCOPE="+strconv.Itoa(int(scope)))
	child.ExtraFiles = []*os.File{controlR, credentialR, payloadR, resultW}
	child.Stdout, child.Stderr = io.Discard, io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	_ = controlR.Close()
	_ = credentialR.Close()
	_ = payloadR.Close()
	_ = resultW.Close()
	hello := protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: command.DescriptorID, ArtifactContractID: sha256.Sum256([]byte("artifact contract"))}
	helloBody, err := protocol.EncodeHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindHello, CorrelationID: command.AttemptID, Body: helloBody}); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ReadExpectedFrame(resultR, protocol.KindHelloAck, command.AttemptID, protocol.HelloBytes); err != nil {
		t.Fatal(err)
	}
	commandBody, err := protocol.EncodeCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	policyBody, err := protocol.EncodePolicy(publicPolicyForTest(policy))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindCommand, CorrelationID: command.AttemptID, Body: commandBody}); err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindPolicy, CorrelationID: command.AttemptID, Body: policyBody}); err != nil {
		t.Fatal(err)
	}
	if err := controlW.Close(); err != nil {
		t.Fatal(err)
	}
	credentialBody, err := credentialroute.EncodeInputs(profile.CredentialRoute(), []credentialroute.Input{{Name: "GITHUB_TOKEN", Present: true, Value: credential}})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(credentialW, protocol.Frame{Kind: protocol.KindCredential, CorrelationID: command.AttemptID, Body: credentialBody}); err != nil {
		t.Fatal(err)
	}
	if err := credentialW.Close(); err != nil {
		t.Fatal(err)
	}
	ready, err := protocol.ReadFrame(resultR, 0)
	if err != nil || ready.CorrelationID != command.AttemptID {
		t.Fatal("preparation frame", err)
	}
	if ready.Kind == protocol.KindPreparationRefused {
		if err := protocol.RequireEOF(resultR); err != nil {
			t.Fatal(err)
		}
		_ = payloadW.Close()
		waitErr := child.Wait()
		joined = true
		if waitErr != nil || ctx.Err() != nil {
			t.Fatal("refused child did not join", waitErr, ctx.Err())
		}
		result := command.NewResult()
		result.Entry, result.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
		return result
	}
	if ready.Kind != protocol.KindReadyForPayload {
		t.Fatal("unexpected readiness kind", ready.Kind)
	}
	kind := protocol.KindArm
	if command.Action == protocol.ActionCreateWithValue || command.Action == protocol.ActionWriteValue {
		kind = protocol.KindPayload
	}
	if err := protocol.WriteFrame(payloadW, protocol.Frame{Kind: kind, CorrelationID: command.AttemptID, Body: payload}); err != nil {
		t.Fatal(err)
	}
	if err := payloadW.Close(); err != nil {
		t.Fatal(err)
	}
	resultBody, err := protocol.ReadExpectedFrame(resultR, protocol.KindResult, command.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := protocol.DecodeResult(resultBody)
	if err != nil || protocol.ValidateResult(command, result) != nil {
		t.Fatalf("child result=%#v err=%v", result, err)
	}
	if err := protocol.RequireEOF(resultR); err != nil {
		t.Fatal(err)
	}
	waitErr := child.Wait()
	joined = true
	if waitErr != nil || ctx.Err() != nil {
		t.Fatalf("child was not joined successfully: wait=%v context=%v", waitErr, ctx.Err())
	}
	return result
}

func githubChildRetainedOldRequest(t *testing.T, action protocol.Action) {
	t.Helper()
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(profile.Repository)
	bPayload := []byte("fresh B literal value")
	aPayload := []byte("retained A literal value")
	aPolicy := policy
	if action == protocol.ActionDeleteOwned {
		aPayload, aPolicy = nil, profile.Policy{}
	}
	b := testCommand(t, profile.Repository, protocol.ActionCreateWithValue, policy, bPayload)
	a := testCommand(t, profile.Repository, action, aPolicy, aPayload)
	b.OperationID, b.AttemptID, b.BindingIncarnationID = testID("fresh B operation"), testID("fresh B attempt"), testID("fresh B binding")
	a.OperationID, a.AttemptID, a.BindingIncarnationID = testID("retained A operation"), testID("retained A attempt"), testID("retained A binding")
	a.OwnedBirthAttemptID, a.BirthTargetRowDigest = testID("retained A birth"), testID("retained A birth target")
	a.TargetRowDigest, a.EntryIncarnationID, a.ProjectionCommitment, a.DispatchContextDigest = testID("retained A target"), testID("retained A entry"), testID("retained A projection"), testID("retained A dispatch")
	b.TargetRowDigest, b.EntryIncarnationID, b.ProjectionCommitment, b.DispatchContextDigest = testID("fresh B target"), testID("fresh B entry"), testID("fresh B projection"), testID("fresh B dispatch")
	const slot = "repos/owner/repo/actions/secrets/TOKEN"
	const keyPath = "/repos/owner/repo/actions/secrets/public-key"
	const secretPath = "/repos/owner/repo/actions/secrets/TOKEN"
	if a.Target.CanonicalTarget != slot || b.Target.CanonicalTarget != slot || a.Target.ConsumerLocator != slot || b.Target.ConsumerLocator != slot || a.OwnedInstance != slot {
		t.Fatal("fixed name-addressed profile.Repository slot changed")
	}
	var mu sync.Mutex
	var effects []string
	var reads, bad atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.GetBody != nil || !r.Close || r.Header.Get("Authorization") != "Bearer github_pat_TEST" || r.Header.Get("X-GitHub-Api-Version") != apiVersion || r.Header.Get("Accept") != "application/vnd.github+json" || r.URL.RawQuery != "" {
			bad.Add(1)
			w.WriteHeader(400)
			return
		}
		if r.Method == http.MethodGet && r.URL.EscapedPath() == keyPath {
			if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
				bad.Add(1)
				w.WriteHeader(400)
				return
			}
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "test-key", "key": base64.StdEncoding.EncodeToString(public[:])})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.EscapedPath() != secretPath || len(effects) > 1 {
			bad.Add(1)
			w.WriteHeader(400)
			return
		}
		first := len(effects) == 0
		wantMethod := http.MethodPut
		wantPayload := bPayload
		label := "B PUT"
		if !first {
			label, wantPayload = "A PUT", aPayload
			if action == protocol.ActionDeleteOwned {
				wantMethod, label = http.MethodDelete, "A DELETE"
			}
		}
		if r.Method != wantMethod {
			bad.Add(1)
			w.WriteHeader(400)
			return
		}
		wire, readErr := io.ReadAll(io.LimitReader(r.Body, maximumPutBodyBytes+1))
		if readErr != nil || len(wire) > maximumPutBodyBytes {
			bad.Add(1)
			w.WriteHeader(400)
			return
		}
		if wantMethod == http.MethodPut {
			if r.Header.Get("Content-Type") != "application/json" || r.ContentLength != int64(len(wire)) {
				bad.Add(1)
				w.WriteHeader(400)
				return
			}
			var body struct {
				EncryptedValue string `json:"encrypted_value"`
				KeyID          string `json:"key_id"`
			}
			decoder := json.NewDecoder(bytes.NewReader(wire))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.KeyID != "test-key" {
				bad.Add(1)
				w.WriteHeader(400)
				return
			}
			sealed, err := base64.StdEncoding.Strict().DecodeString(body.EncryptedValue)
			plain, ok := box.OpenAnonymous(nil, sealed, public, private)
			if err != nil || !ok || !bytes.Equal(plain, wantPayload) {
				bad.Add(1)
				w.WriteHeader(400)
				return
			}
		} else if len(wire) != 0 || r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
			bad.Add(1)
			w.WriteHeader(400)
			return
		}
		effects = append(effects, label)
		if first {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	bResult := runGitHubChildWire(t, server.URL, profile.Repository, b, policy, bPayload, []byte("github_pat_TEST"))
	aResult := runGitHubChildWire(t, server.URL, profile.Repository, a, aPolicy, aPayload, []byte("github_pat_TEST"))
	for _, pair := range []struct {
		command protocol.Command
		result  protocol.Result
		status  uint16
	}{{b, bResult, 201}, {a, aResult, 204}} {
		if pair.result.DomainID != pair.command.DomainID || pair.result.OperationID != pair.command.OperationID || pair.result.AttemptID != pair.command.AttemptID || pair.result.CoordinateID != pair.command.CoordinateID || pair.result.ProjectionCommitment != pair.command.ProjectionCommitment || pair.result.Entry != protocol.EntryMayHaveEntered || pair.result.Class != protocol.ClassAcknowledged || pair.result.NormalizedStatus != pair.status || pair.result.SafeResourceID != slot {
			t.Fatal("exact native result identities or ACK", pair.result)
		}
	}
	wantReads := int32(2)
	want := []string{"B PUT", "A PUT"}
	if action == protocol.ActionDeleteOwned {
		wantReads, want = 1, []string{"B PUT", "A DELETE"}
	}
	mu.Lock()
	got := append([]string(nil), effects...)
	mu.Unlock()
	if reads.Load() != wantReads || bad.Load() != 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("native name-addressed order: reads=%d bad=%d effects=%v", reads.Load(), bad.Load(), got)
	}
}
