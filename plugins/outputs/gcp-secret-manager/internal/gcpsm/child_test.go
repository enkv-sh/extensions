package gcpsm

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// The child uses New's production transport with only a private local route.
// full_only: false
func TestGCPChildProtocolOneSend(t *testing.T) {
	if os.Getenv("ENKV_GCP_OUTPUT_CHILD") == "1" {
		implementation := testPublicImplementation(t)
		implementation.endpoint = os.Getenv("ENKV_GCP_OUTPUT_ENDPOINT")
		control, credential, payload, result := os.NewFile(3, "control"), os.NewFile(4, "credential"), os.NewFile(5, "payload"), os.NewFile(6, "result")
		status := output.Run(context.Background(), output.Endpoints{Control: control, Credential: credential, Payload: payload, Result: result}, capturedImplementation{implementation})
		for _, file := range []*os.File{control, credential, payload, result} {
			if closeErr := file.Close(); closeErr != nil {
				os.Exit(2)
			}
		}
		if status != 0 {
			os.Exit(status)
		}
		return
	}
	for _, variant := range []string{"ack", "redirect", "rate-limit", "response-lost", "tls-failure"} {
		t.Run(variant, func(t *testing.T) {
			payload := []byte("private child output")
			command, policy := testCommand(t, payload)
			var posts, bad atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/"+testParent+":addVersion" ||
					r.URL.RawQuery != "alt=json&prettyPrint=false" || r.ProtoMajor != 1 || r.GetBody != nil ||
					r.Header.Get("Authorization") != "Bearer token-1" {
					bad.Add(1)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch variant {
				case "ack":
					_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
				case "rate-limit":
					w.WriteHeader(http.StatusTooManyRequests)
				case "response-lost":
					if connection, _, err := w.(http.Hijacker).Hijack(); err == nil {
						_ = connection.Close()
					}
				}
			})
			var server *httptest.Server
			if variant == "tls-failure" {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			result := runGCPChildWire(t, server.URL, command, policy, payload, testCredential("token-1"))
			expectedPosts := int32(1)
			if variant == "tls-failure" {
				expectedPosts = 0
			}
			if posts.Load() != expectedPosts || bad.Load() != 0 {
				t.Fatalf("request count/shape: POST=%d bad=%d", posts.Load(), bad.Load())
			}
			if variant == "ack" {
				if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged ||
					result.SafeResourceID != testParent+"/versions/42" {
					t.Fatalf("GCP child ACK=%#v", result)
				}
			} else if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved {
				t.Fatalf("GCP child uncertainty=%#v", result)
			}
		})
	}
}

// full_only: false
func TestGCPChildProtocolMetadataActions(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty,
		protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		t.Run(strconv.Itoa(int(action)), func(t *testing.T) {
			command, policy, payload := actionCommand(t, action)
			var methods []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method+" "+r.URL.EscapedPath())
				switch {
				case action == protocol.ActionCreateEmpty:
					_, _ = io.WriteString(w, `{"name":"`+testParent+`","replication":{"automatic":{}}}`)
				case r.Method == "GET":
					_, _ = io.WriteString(w, `{"name":"`+testParent+`","etag":"etag-1"}`)
				case r.Method == "DELETE":
					_, _ = io.WriteString(w, "{}")
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			result := runGCPChildWire(t, server.URL, command, policy, payload, testCredential("token-1"))
			want := 2
			if action == protocol.ActionCreateEmpty {
				want = 1
			}
			if result.Class != protocol.ClassAcknowledged || result.Entry != protocol.EntryMayHaveEntered ||
				len(methods) != want {
				t.Fatalf("metadata child result=%#v methods=%v", result, methods)
			}
		})
	}
}

func runGCPChildWire(t *testing.T, endpoint string, command protocol.Command, policy protocol.Policy, payload, credential []byte) protocol.Result {
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
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGCPChildProtocolOneSend$")
	child.Env = append(os.Environ(), "ENKV_GCP_OUTPUT_CHILD=1", "ENKV_GCP_OUTPUT_ENDPOINT="+endpoint)
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
	hello := protocol.Hello{ProtocolID: protocol.ProtocolID(), DescriptorID: fixtureBinding(t, fixtureRoute()).Identity().DescriptorID, ArtifactContractID: testID("artifact contract")}
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
	policyBody, err := protocol.EncodePolicy(policy)
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
	encodedCredential := make([]byte, base64.StdEncoding.EncodedLen(len(credential)))
	defer clear(encodedCredential)
	base64.StdEncoding.Encode(encodedCredential, credential)
	credentialBody, err := credentialroute.EncodeInputs(fixtureRoute(), []credentialroute.Input{{Name: "TEST_CREDENTIAL", Present: true, Value: encodedCredential}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentialBody)
	if err := protocol.WriteFrame(credentialW, protocol.Frame{Kind: protocol.KindCredential, CorrelationID: command.AttemptID, Body: credentialBody}); err != nil {
		t.Fatal(err)
	}
	if err := credentialW.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ReadExpectedFrame(resultR, protocol.KindReadyForPayload, command.AttemptID, 0); err != nil {
		t.Fatal(err)
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
