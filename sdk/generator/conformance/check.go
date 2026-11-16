package conformance

import (
	"bytes"
	"context"
	"errors"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// Check uses an independent synthetic managed resource, not an official plugin.
// It establishes no installation trust, provider correctness or effect authority.
func Check(serve Serve) error {
	implementation, fixture, err := synthetic()
	if err != nil {
		return err
	}
	return CheckImplementation(context.Background(), serve, implementation, fixture)
}
func repeatedID(n byte) protocol.ID {
	var id protocol.ID
	for i := range id {
		id[i] = n
	}
	return id
}
func synthetic() (generator.Implementation, Fixture, error) {
	intent := protocol.Intent{Schema: 1, ConfigContractID: repeatedID(3), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: repeatedID(4), Settings: []byte(`{"private_counter":7}`)}
	encoded, _ := protocol.EncodeIntent(intent)
	intentDigest, _ := protocol.IntentDigest(encoded)
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte(repeatedID(5)), Mode: credentialroute.ModeEnvironment}
	routeBytes, err := credentialroute.Encode(route)
	if err != nil {
		return generator.Implementation{}, Fixture{}, err
	}
	descriptorBytes, err := artifact.EncodeDescriptor(artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "synthetic", Role: "generator", Version: "1.0.0", Wire: generator.DescriptorWire(), Generator: &artifact.GeneratorDeclaration{ConfigContractID: artifact.Digest(repeatedID(3)), CredentialRoute: routeBytes}})
	if err != nil {
		return generator.Implementation{}, Fixture{}, err
	}
	binding, err := generator.Bind(descriptorBytes, repeatedID(3))
	if err != nil {
		return generator.Implementation{}, Fixture{}, err
	}
	routeID, _ := credentialroute.Identity(route)
	command := protocol.Command{Schema: 1, Action: protocol.ActionCreate, DeadlineUnixMillis: 4102444800000, DomainID: repeatedID(6), OperationID: repeatedID(7), RequestIdentityDigest: repeatedID(8), PlanGraphID: repeatedID(9), LineageID: repeatedID(10), AttemptID: repeatedID(11), TransmissionID: repeatedID(12), ResultID: repeatedID(13), ResultContractID: repeatedID(14), DescriptorID: binding.Identity().DescriptorID, ExecutorID: repeatedID(15), RequestDigest: repeatedID(16), IntentDigest: intentDigest, ResourceContractID: repeatedID(4), CredentialRouteID: protocol.ID(routeID), LifecycleMode: protocol.LifecycleManaged, Intent: encoded}
	facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	facts.Target = []byte("private/account")
	facts.ResourceData = []byte("independent-handle")
	implementation := generator.Implementation{Binding: binding, Normalize: func(context.Context, protocol.NormalizeRequest) (protocol.Intent, error) {
		return protocol.Intent{}, errors.New("unused")
	}, ValidateCanonical: func(context.Context, protocol.Intent) error { return nil }, CheckRetirementCompatibility: func(context.Context, protocol.RetirementCompatibilityRequest) (bool, error) { return true, nil }, Retire: func(context.Context, generator.Invocation) (protocol.SafeFacts, error) {
		return protocol.SafeFacts{}, errors.New("unused")
	}}
	implementation.Create = func(_ context.Context, _ generator.Invocation) (protocol.SafeFacts, []byte, error) {
		return cloneFacts(facts), []byte{0, 255, 7}, nil
	}
	return implementation, Fixture{Command: command, Inputs: []credentialroute.Input{}, ExpectedFacts: facts, ExpectedValue: []byte{0, 255, 7}}, nil
}
func cloneFacts(v protocol.SafeFacts) protocol.SafeFacts {
	v.Target = bytes.Clone(v.Target)
	v.ResourceData = bytes.Clone(v.ResourceData)
	v.ProviderFacts = bytes.Clone(v.ProviderFacts)
	return v
}
