package gcpsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"testing"
	"time"
)

func testEncoding(s string) uint8 {
	if s == "raw" {
		return protocol.EncodingRaw
	}
	if s == "base64" {
		return protocol.EncodingBase64
	}
	return 0
}
func testPolicyData(subjects []string) []byte { b, _ := json.Marshal(subjects); return b }
func fixtureRoute() credentialroute.Route {
	return credentialroute.Route{Schema: 1, ContractID: [32]byte(testID("test-captured-credential")), Mode: credentialroute.ModeEnvironment, Names: []string{"TEST_CREDENTIAL"}}
}
func fixtureRouteID(t testing.TB) protocol.ID {
	t.Helper()
	id, err := credentialroute.Identity(fixtureRoute())
	if err != nil {
		t.Fatal(err)
	}
	return protocol.ID(id)
}
func fixtureBinding(t testing.TB, route credentialroute.Route) output.Binding {
	t.Helper()
	routeBytes, err := credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	body, err := artifact.EncodeDescriptor(artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "controlled-output", Role: "output", Version: "1.0.0", Wire: output.DescriptorWire(), Output: &artifact.OutputDeclaration{ConfigContractID: "controlled-config", CredentialRoute: routeBytes}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := output.Bind(body, "controlled-config")
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
func testPublicImplementation(t testing.TB) Implementation {
	i := New()
	i.Binding = fixtureBinding(t, fixtureRoute())
	return i
}

// This child fixture isolates the production HTTP engine. Discovery has separate
// tests against the real standard SDK chain and ADC.
type capturedImplementation struct{ Implementation }

func (c capturedImplementation) CredentialRoute() credentialroute.Route { return fixtureRoute() }
func (c capturedImplementation) Prepare(ctx context.Context, command output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	if _, err := c.CheckAction(ctx, output.ActionCheck{Action: command.Action, Target: command.Target, OwnedInstance: command.OwnedInstance, ConditionalTokenLength: uint16(len(command.ConditionalToken)), PayloadLengthMode: command.PayloadLengthMode, PayloadLength: command.PayloadLength}, policy); err != nil {
		return nil, err
	}
	if len(inputs) != 1 || !inputs[0].Present {
		return nil, protocol.ErrProtocol
	}
	credential, err := base64.StdEncoding.Strict().AppendDecode(nil, inputs[0].Value)
	if err != nil {
		clear(credential)
		return nil, protocol.ErrProtocol
	}
	return &capturedPrepared{implementation: c.Implementation, command: command, policy: policy, credential: credential}, nil
}

type capturedPrepared struct {
	implementation Implementation
	command        output.Preparation
	policy         protocol.Policy
	credential     []byte
}

func (p *capturedPrepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	return p.implementation.send(ctx, p.command, p.policy, payload, p.credential)
}
func (p *capturedPrepared) Close() error { clear(p.credential); p.credential = nil; return nil }

func (i Implementation) execute(ctx context.Context, command protocol.Command, policy protocol.Policy, payload, credential []byte) (protocol.Result, error) {
	if protocol.ValidatePolicy(command, policy) != nil {
		r := command.NewResult()
		r.Entry, r.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
		return r, nil
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(command.DeadlineUnixMillis)))
	defer cancel()
	outcome, err := i.send(ctx, preparationForTest(command), policy, payload, credential)
	return wireForTest(command, outcome), err
}

func preparationForTest(c protocol.Command) output.Preparation {
	return output.Preparation{Action: c.Action, Target: c.Target, AttemptID: c.AttemptID, OwnedInstance: c.OwnedInstance, ConditionalToken: c.ConditionalToken, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
func actionForTest(c protocol.ActionCheckRequest) output.ActionCheck {
	return output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, OwnershipMode: c.OwnershipMode, OwnedInstanceDigest: c.OwnedInstanceDigest, UncertainCreateAttemptID: c.UncertainCreateAttemptID, ExclusiveNamespaceDigest: c.ExclusiveNamespaceDigest, ConditionalTokenLength: c.ConditionalTokenLength, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
}
func wireForTest(c protocol.Command, o output.Outcome) protocol.Result {
	r := c.NewResult()
	r.Entry, r.Class, r.NormalizedStatus, r.SafeRequestID, r.SafeResourceID = o.Entry, o.Class, o.NormalizedStatus, o.SafeRequestID, o.SafeResourceID
	if o.Class == protocol.ClassAcknowledged && (c.Action == protocol.ActionCreateEmpty || c.Action == protocol.ActionCreateWithValue) {
		r.ConsumerLocator = c.Target.ConsumerLocator
		if c.Target.LocatorRequiresCreation {
			r.ConsumerLocator = o.AssignedLocator
		}
	}
	return r
}
