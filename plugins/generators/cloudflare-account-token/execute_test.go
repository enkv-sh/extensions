package cloudflare_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/sdk/generator/conformance"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	cloudflare "enkv.sh/plugins/generators/cloudflare-account-token"
	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

const ordinarySettings = `{"account":"0123456789abcdef0123456789abcdef","name":"root","policies":[{"effect":"allow","permission_groups":["123456789abcdef0123456789abcdef0"],"resources":[{"kind":"account","id":"0123456789abcdef0123456789abcdef"}]}]}`

func commandFixture(t *testing.T) protocol.Command {
	t.Helper()
	intent, err := profile.Normalize([]byte(ordinarySettings), profile.ProductionOrigin)
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.EncodeIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := protocol.IntentDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	route, err := credentialroute.Identity(profile.CredentialRoute())
	if err != nil {
		t.Fatal(err)
	}
	command := protocol.Command{Schema: 1, Action: protocol.ActionCreate, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), DomainID: protocol.ID{1}, OperationID: protocol.ID{2}, RequestIdentityDigest: protocol.ID{3}, PlanGraphID: protocol.ID{4}, LineageID: protocol.ID{5}, AttemptID: protocol.ID{6}, TransmissionID: protocol.ID{7}, ResultID: protocol.ID{8}, ResultContractID: protocol.ID{9}, DescriptorID: protocol.ID{10}, ExecutorID: protocol.ID{11}, RequestDigest: protocol.ID{12}, IntentDigest: digest, ResourceContractID: intent.ResourceContractID, CredentialRouteID: protocol.ID(route), LifecycleMode: protocol.LifecycleManaged, Intent: body}
	if _, err := protocol.EncodeCommand(command); err != nil {
		t.Fatal(err)
	}
	return command
}
func invocation(command protocol.Command, bearer []byte) generator.Invocation {
	return generator.Invocation{Command: command, Inputs: []credentialroute.Input{{Name: profile.CredentialEnvironment, Present: true, Value: bearer}}}
}

// full_only: false
func TestExecuteRefusesInvalidCommandAndPreservesBorrowedInputs(t *testing.T) {
	intent := []byte("invalid intent")
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	wantIntent, wantBearer := bytes.Clone(intent), bytes.Clone(bearer)
	facts, value, err := cloudflare.Execute(context.Background(), invocation(protocol.Command{Intent: intent}, bearer))
	if err == nil || !reflect.DeepEqual(facts, protocol.SafeFacts{}) || value != nil {
		t.Fatal("invalid command did not refuse without a result")
	}
	if !bytes.Equal(intent, wantIntent) || !bytes.Equal(bearer, wantBearer) {
		t.Fatal("public adapter changed borrowed input")
	}
}

// full_only: false
func TestExecuteCancelledValidCommandReturnsClosedUnknownFacts(t *testing.T) {
	command := commandFixture(t)
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	wantIntent, wantBearer := bytes.Clone(command.Intent), bytes.Clone(bearer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	facts, value, err := cloudflare.Execute(ctx, invocation(command, bearer))
	want := command.NewFacts(protocol.DispositionUnknown, protocol.ReasonTransport)
	opaque, decodeErr := provider.DecodeFacts(facts.ProviderFacts)
	if err != nil || value != nil || decodeErr != nil || opaque.Disposition != provider.DispositionUnknown || opaque.Reason != provider.ReasonTransport || opaque.Account != provider.ID([32]byte([]byte("0123456789abcdef0123456789abcdef"))) || facts.RequestDigest != command.RequestDigest {
		t.Fatal("cancelled command lost closed unknown facts")
	}
	facts.ProviderFacts = nil
	if !reflect.DeepEqual(facts, want) {
		t.Fatal("generic facts changed admitted identities")
	}
	if !bytes.Equal(command.Intent, wantIntent) || !bytes.Equal(bearer, wantBearer) {
		t.Fatal("public adapter changed borrowed input")
	}
}

// full_only: false
func TestImplementationBindsDescriptorAndDeclaredCredential(t *testing.T) {
	descriptor, err := os.ReadFile("cmd/enkv-generator-cloudflare/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := cloudflare.NewImplementation(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if implementation.ConfigContractID() != profile.ConfigContractID(profile.ProductionOrigin) || len(implementation.CredentialRoute().Names) != 1 || implementation.CredentialRoute().Names[0] != "CLOUDFLARE_API_TOKEN" {
		t.Fatal("wrong declared credential route")
	}
	declaration, err := artifact.DecodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	declaration.Generator = nil
	missing, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name, body, field string
	}{
		{"syntax", `{"schema":`, "descriptor"},
		{"field-case", `{"SCHEMA":"private-supplied-value"}`, "record.schema"},
		{"missing-declaration", string(missing), "descriptor"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			_, err := cloudflare.NewImplementation([]byte(invalid.body))
			if !errors.Is(err, protocol.ErrProtocol) || !errors.Is(err, artifact.ErrRecord) {
				t.Fatal("constructor lost protocol or record cause")
			}
			if !strings.Contains(err.Error(), invalid.field) || strings.Contains(err.Error(), "private-supplied-value") || strings.Contains(err.Error(), "SCHEMA") {
				t.Fatal("constructor diagnostic lost safe field context")
			}
		})
	}
	for _, condition := range []string{"config", "route-name"} {
		t.Run(condition, func(t *testing.T) {
			declaration, err := artifact.DecodeDescriptor(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "config" {
				declaration.Generator.ConfigContractID = artifact.Digest{9}
			} else {
				route, err := credentialroute.Decode(declaration.Generator.CredentialRoute)
				if err != nil {
					t.Fatal(err)
				}
				route.Names[0] = "OTHER_TOKEN"
				declaration.Generator.CredentialRoute, err = credentialroute.Encode(route)
				if err != nil {
					t.Fatal(err)
				}
			}
			body, err := artifact.EncodeDescriptor(declaration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cloudflare.NewImplementation(body); err == nil {
				t.Fatal("unsupported plugin semantics accepted")
			}
		})
	}
	command := commandFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []credentialroute.Input{{Name: profile.CredentialEnvironment, Present: false}, {Name: profile.CredentialEnvironment, Present: true, Value: []byte("short")}, {Name: profile.CredentialEnvironment, Present: true, Value: []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN\n")}, {Name: "OTHER_TOKEN", Present: true, Value: bytes.Repeat([]byte{'a'}, 40)}} {
		if _, _, err := cloudflare.Execute(ctx, generator.Invocation{Command: command, Inputs: []credentialroute.Input{input}}); err == nil {
			t.Fatal("unusable credential was accepted")
		}
	}
	for _, token := range [][]byte{bytes.Repeat([]byte{'a'}, 40), bytes.Repeat([]byte{'b'}, 80)} {
		if _, _, err := cloudflare.Execute(ctx, invocation(command, token)); err != nil {
			t.Fatal("rotated valid credential refused", err)
		}
	}
}

func originalFacts(t *testing.T, command protocol.Command) protocol.SafeFacts {
	t.Helper()
	intent, err := protocol.DecodeIntent(command.Intent)
	if err != nil {
		t.Fatal(err)
	}
	controls, err := profile.ParseCanonical(intent, profile.ProductionOrigin)
	if err != nil {
		t.Fatal(err)
	}
	token := provider.ID([32]byte([]byte("abcdef0123456789abcdef0123456789")))
	opaque, err := provider.EncodeFacts(provider.SafeFacts{Schema: 1, Disposition: provider.DispositionCompleteCreate, Reason: provider.ReasonNone, HTTPStatus: 200, Account: provider.ID(controls.Account), TokenPresent: 1, TokenID: token, TokenStatus: provider.TokenStatusActive, EchoPresence: provider.EchoName | provider.EchoPolicies, RequestDigest: provider.ID{99}, IntentDigest: provider.ID(controls.Digest), MatchedControlsDigest: provider.ID(controls.Digest)})
	if err != nil {
		t.Fatal(err)
	}
	facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	facts.Target = bytes.Clone(controls.Account[:])
	facts.ResourceData = bytes.Clone(token[:])
	facts.ProviderFacts = opaque
	return facts
}

// full_only: false
func TestRetirementCompatibilityChecksExactOriginalResource(t *testing.T) {
	descriptor, err := os.ReadFile("cmd/enkv-generator-cloudflare/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := cloudflare.NewImplementation(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	command := commandFixture(t)
	original := originalFacts(t, command)
	body, err := protocol.EncodeSafeFacts(original)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: command.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: command.Intent, OriginalFacts: body}
	request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := implementation.CheckRetirementCompatibility(context.Background(), request); err != nil || !accepted {
		t.Fatal("exact original resource refused", err)
	}
	for _, change := range []func(*protocol.SafeFacts){func(v *protocol.SafeFacts) { v.Target = bytes.Repeat([]byte{'f'}, 32) }, func(v *protocol.SafeFacts) { v.ResourceData = bytes.Repeat([]byte{'e'}, 32) }, func(v *protocol.SafeFacts) { v.ResourceContractID = protocol.ID{44} }, func(v *protocol.SafeFacts) { v.ProviderFacts = append(bytes.Clone(v.ProviderFacts), 0) }} {
		changed := original
		change(&changed)
		request.OriginalFacts, err = protocol.EncodeSafeFacts(changed)
		if err != nil {
			t.Fatal(err)
		}
		if accepted, err := implementation.CheckRetirementCompatibility(context.Background(), request); err != nil || accepted {
			t.Fatal("changed original resource accepted")
		}
	}
	request.OriginalFacts = body
	request.CompletionClass = protocol.CompletionConfirmed
	if accepted, err := implementation.CheckRetirementCompatibility(context.Background(), request); err != nil || accepted {
		t.Fatal("acknowledgement claimed confirmed invalidation")
	}
	command.Action = protocol.ActionRetire
	command.OriginalFacts = body
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	facts, value, err := cloudflare.Execute(ctx, invocation(command, bytes.Repeat([]byte{'a'}, 40)))
	if err != nil || value != nil || facts.Disposition != protocol.DispositionUnknown || !bytes.Equal(facts.Target, original.Target) || !bytes.Equal(facts.ResourceData, original.ResourceData) {
		t.Fatal("retirement uncertainty lost exact original target", err)
	}
}

// full_only: false
func TestAuthorConformanceUsesSemanticCancelledFixture(t *testing.T) {
	descriptor, err := os.ReadFile("cmd/enkv-generator-cloudflare/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	impl, err := cloudflare.NewImplementation(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed field-order derivation: schema, unknown/transport, absent status/token,
	// account, request/control digest literals, zero match, no errors or times.
	expected, err := hex.DecodeString("0001040800003031323334353637383961626364656630313233343536373839616263646566000000009259ec5818471f96534511fe9472e6deb42d1ff0f135c850cba68288affbb46471239c0bc19edc1e3672a631909d686ffeba5f280bc7f6fbe9d748cdd1cdc3c9000000000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expected[:cap(expected)])
	intent := protocol.Intent{Schema: 1, ConfigContractID: profile.ConfigContractID(profile.ProductionOrigin), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: profile.ResourceContractID(profile.ProductionOrigin), Settings: []byte(ordinarySettings)}
	input := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	defer clear(input[:cap(input)])
	fixture, err := conformance.NewFixture(impl, conformance.Request{Action: protocol.ActionCreate, Intent: intent, Inputs: []credentialroute.Input{{Name: profile.CredentialEnvironment, Present: true, Value: input}}}, conformance.Expectation{Disposition: protocol.DispositionUnknown, Reason: protocol.ReasonTransport, ProviderFacts: expected})
	if err != nil {
		t.Fatal(err)
	}
	actual := impl.Create
	calls := 0
	impl.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
		calls++
		child, cancel := context.WithCancel(ctx)
		cancel()
		return actual(child, inv)
	}
	if err := conformance.CheckImplementation(t.Context(), generator.Run, impl, fixture); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("actual cancellation callback count", calls)
	}
}
