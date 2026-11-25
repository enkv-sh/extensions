package execution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"enkv.sh/plugins/outputs/aws-secrets-manager/execution"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"os"
	"testing"
)

// full_only: false
func TestPublicExecutionPreservesAWSContractsAndLocalRefusals(t *testing.T) {
	raw, err := os.ReadFile("../cmd/enkv-output-aws-secrets-manager/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := execution.NewImplementation(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"config", "route-mode"} {
		t.Run(condition, func(t *testing.T) {
			descriptor, err := artifact.DecodeDescriptor(raw)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "config" {
				descriptor.Output.ConfigContractID = "other/config"
			} else {
				route, err := credentialroute.Decode(descriptor.Output.CredentialRoute)
				if err != nil {
					t.Fatal(err)
				}
				route.Mode = credentialroute.ModeEnvironment
				descriptor.Output.CredentialRoute, err = credentialroute.Encode(route)
				if err != nil {
					t.Fatal(err)
				}
			}
			body, err := artifact.EncodeDescriptor(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := execution.NewImplementation(body); err == nil {
				t.Fatal("unsupported plugin semantics accepted")
			}
		})
	}
	expected, err := hex.DecodeString("f1c462b07394555dd7a2d602b48c678bb2b2f8901310cff5713a972fbc43d6c0")
	if err != nil {
		t.Fatal(err)
	}
	var descriptorID protocol.ID
	copy(descriptorID[:], expected)
	if implementation.Identity() != (output.ImplementationIdentity{ProtocolID: sha256.Sum256([]byte("ENKV/OUTPUT-WIRE/v6\x00")), DescriptorID: descriptorID}) {
		t.Fatal("pre-build identity")
	}
	destination, err := implementation.NormalizeDestination(t.Context(), []byte(`{"account":"123456789012","region":"us-east-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := implementation.ValidateCanonical(t.Context(), destination); err != nil {
		t.Fatal(err)
	}
	target, err := implementation.InterpretTarget(t.Context(), output.TargetRequest{Destination: destination, EntryName: "TOKEN", PayloadEncoding: protocol.EncodingRaw})
	if err != nil {
		t.Fatal(err)
	}
	request := output.ActionCheck{Action: protocol.ActionCreateEmpty, Target: target}
	if bounds, err := implementation.CheckAction(t.Context(), request, protocol.Policy{}); err != nil || bounds != (protocol.PayloadBounds{}) {
		t.Fatal("metadata action", err)
	}
	request.Action = protocol.Action(0)
	if _, err := implementation.CheckAction(t.Context(), request, protocol.Policy{}); err == nil {
		t.Fatal("invalid action accepted")
	}
	request.Action = protocol.ActionCreateEmpty
	for _, data := range [][]byte{[]byte(`[]`), []byte(`["principal"]`)} {
		if _, err := implementation.CheckAction(t.Context(), request, protocol.Policy{ContractID: "cloud-iam", Data: data}); err == nil {
			t.Fatal("external IAM policy accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := implementation.CheckAction(ctx, request, protocol.Policy{}); err == nil {
		t.Fatal("canceled passive request accepted")
	}
}
