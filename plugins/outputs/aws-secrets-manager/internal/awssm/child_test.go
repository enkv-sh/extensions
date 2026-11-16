package awssm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// The child uses New's production HTTP/1-only transport. The private route
// points only at the test server; the production command has no such option.
// full_only: false
func TestAWSChildProtocolOneSend(t *testing.T) {
	if os.Getenv("ENKV_AWS_OUTPUT_CHILD") == "1" {
		implementation := testPublicImplementation(t)
		implementation.endpoint = os.Getenv("ENKV_AWS_OUTPUT_ENDPOINT")
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
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/" || r.ProtoMajor != 1 || r.GetBody != nil ||
					r.Header.Get("X-Amz-Target") != "secretsmanager.PutSecretValue" || r.Header.Get("Authorization") == "" {
					bad.Add(1)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch variant {
				case "ack":
					_ = json.NewEncoder(w).Encode(map[string]any{"ARN": testARN, "Name": "enkv-output",
						"VersionId": hex.EncodeToString(command.AttemptID[:]), "VersionStages": []string{"AWSCURRENT"}})
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
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
			result := runAWSChildWire(t, server.URL, command, policy, payload, testCredential(""))
			if bad.Load() != 0 || posts.Load() != map[bool]int32{true: 0, false: 1}[variant == "tls-failure"] {
				t.Fatalf("request count/shape: POST=%d bad=%d", posts.Load(), bad.Load())
			}
			if variant == "ack" {
				if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged ||
					result.SafeResourceID != hex.EncodeToString(command.AttemptID[:]) {
					t.Fatalf("AWS child ACK=%#v", result)
				}
			} else if result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved {
				t.Fatalf("AWS child uncertainty=%#v", result)
			}
		})
	}
}

func runAWSChildWire(t *testing.T, endpoint string, command protocol.Command, policy protocol.Policy, payload, credential []byte) protocol.Result {
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
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAWSChildProtocolOneSend$")
	child.Env = append(os.Environ(), "ENKV_AWS_OUTPUT_CHILD=1", "ENKV_AWS_OUTPUT_ENDPOINT="+endpoint)
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
	kind := uint8(protocol.KindPayload)
	if command.Action != protocol.ActionWriteValue && command.Action != protocol.ActionCreateWithValue {
		kind = protocol.KindArm
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
