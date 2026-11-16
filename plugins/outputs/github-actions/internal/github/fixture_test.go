package github

import (
	"bytes"
	"context"
	"encoding/json"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func testImplementation(scope profile.Scope) Implementation {
	name := map[profile.Scope]string{profile.Repository: "repository", profile.Organization: "organization", profile.Environment: "environment"}[scope]
	if name == "" {
		return Implementation{scope: scope}
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "cmd", "enkv-output-github-"+name, "plugin.json"))
	if err != nil {
		panic(err)
	}
	i, err := New(scope, body)
	if err != nil {
		panic(err)
	}
	return i
}
func publicPolicyForTest(p profile.Policy) protocol.Policy {
	wire, err := profile.PublicPolicy(p)
	if err == nil {
		return wire
	}
	return protocol.Policy{ContractID: profile.PolicyContractID, Data: []byte{0, 1, p.Mode, 0, 0}}
}
func (i Implementation) executeForTest(ctx context.Context, c protocol.Command, p profile.Policy, payload, token []byte) (protocol.Result, error) {
	return runForTest(ctx, i, c, publicPolicyForTest(p), payload, token)
}
func runForTest(ctx context.Context, implementation output.Implementation, c protocol.Command, policy protocol.Policy, payload, token []byte) (protocol.Result, error) {
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(c.DeadlineUnixMillis)))
	defer cancel()
	var control, credentials, values, result bytes.Buffer
	hello, err := protocol.EncodeHello(protocol.Hello{ProtocolID: implementation.Identity().ProtocolID, DescriptorID: c.DescriptorID, ArtifactContractID: testID("artifact")})
	if err != nil {
		return protocol.Result{}, err
	}
	command, err := protocol.EncodeCommand(c)
	if err != nil {
		return protocol.Result{}, err
	}
	private, err := credentialroute.EncodeInputs(implementation.CredentialRoute(), []credentialroute.Input{{Name: "GITHUB_TOKEN", Present: true, Value: token}})
	if err != nil {
		return protocol.Result{}, err
	}
	var credentialFrame, payloadFrame []byte
	defer func() {
		clear(private[:cap(private)])
		clear(credentialFrame[:cap(credentialFrame)])
		clear(payloadFrame[:cap(payloadFrame)])
	}()
	for _, frame := range []protocol.Frame{{Kind: protocol.KindHello, CorrelationID: c.AttemptID, Body: hello}, {Kind: protocol.KindCommand, CorrelationID: c.AttemptID, Body: command}, {Kind: protocol.KindPolicy, CorrelationID: c.AttemptID, Body: policy.Data}} {
		if err := protocol.WriteFrame(&control, frame); err != nil {
			return protocol.Result{}, err
		}
	}
	if err := protocol.WriteFrame(&credentials, protocol.Frame{Kind: protocol.KindCredential, CorrelationID: c.AttemptID, Body: private}); err != nil {
		return protocol.Result{}, err
	}
	credentialFrame = credentials.Bytes()
	kind := uint8(protocol.KindArm)
	if c.Action == protocol.ActionCreateWithValue || c.Action == protocol.ActionWriteValue {
		kind = protocol.KindPayload
	}
	if err := protocol.WriteFrame(&values, protocol.Frame{Kind: kind, CorrelationID: c.AttemptID, Body: payload}); err != nil {
		return protocol.Result{}, err
	}
	payloadFrame = values.Bytes()
	code := output.Run(ctx, output.Endpoints{Control: &control, Credential: &credentials, Payload: &values, Result: &result}, implementation)
	if code != 0 {
		return protocol.Result{}, fmt.Errorf("output serving failed: %d", code)
	}
	ack, err := protocol.ReadExpectedFrame(&result, protocol.KindHelloAck, c.AttemptID, protocol.HelloBytes)
	if err != nil || !bytes.Equal(ack, hello) {
		return protocol.Result{}, protocol.ErrProtocol
	}
	ready, err := protocol.ReadFrame(&result, 0)
	if err != nil || ready.CorrelationID != c.AttemptID {
		return protocol.Result{}, protocol.ErrProtocol
	}
	if ready.Kind == protocol.KindPreparationRefused {
		if err := protocol.RequireEOF(&result); err != nil {
			return protocol.Result{}, err
		}
		r := c.NewResult()
		r.Entry, r.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
		return r, nil
	}
	if ready.Kind != protocol.KindReadyForPayload {
		return protocol.Result{}, protocol.ErrProtocol
	}
	body, err := protocol.ReadExpectedFrame(&result, protocol.KindResult, c.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		return protocol.Result{}, err
	}
	decoded, err := protocol.DecodeResult(body)
	if err != nil {
		return protocol.Result{}, err
	}
	if err := protocol.ValidateResult(c, decoded); err != nil {
		return protocol.Result{}, err
	}
	if err := protocol.RequireEOF(&result); err != nil {
		return protocol.Result{}, err
	}
	return decoded, nil
}

func targetDataForTest(scope profile.Scope, coordinate string) []byte {
	body, _ := json.Marshal(struct {
		Scope      profile.Scope `json:"scope"`
		Coordinate string        `json:"coordinate"`
	}{scope, coordinate})
	return body
}
func testTransportImplementation(scope profile.Scope, endpoint string, transport http.RoundTripper) Implementation {
	i := testImplementation(scope)
	i.endpoint = endpoint
	i.transport = transport
	return i
}

func preparationForTest(c protocol.Command) output.Preparation {
	return output.Preparation{Action: c.Action, Target: c.Target, AttemptID: c.AttemptID, OwnedInstance: c.OwnedInstance, ConditionalToken: c.ConditionalToken, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
func actionForTest(c protocol.ActionCheckRequest) output.ActionCheck {
	return output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, OwnershipMode: c.OwnershipMode, OwnedInstanceDigest: c.OwnedInstanceDigest, UncertainCreateAttemptID: c.UncertainCreateAttemptID, ExclusiveNamespaceDigest: c.ExclusiveNamespaceDigest, ConditionalTokenLength: c.ConditionalTokenLength, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
