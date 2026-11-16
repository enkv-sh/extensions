package output

import (
	"fmt"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

// Binding holds checked startup facts. Its zero value cannot serve an exchange.
// It grants no executable authentication or host admission.
type Binding struct {
	identity ImplementationIdentity
	name     string
	route    credentialroute.Route
}

// DescriptorWire returns the current family declaration for author descriptors.
func DescriptorWire() artifact.Contract {
	return artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: uint32(protocol.Version)}
}

// Bind checks the family declaration against the implementation's supported
// config contract. It decodes body without retaining it. Family, wire and config
// mismatches wrap protocol.ErrProtocol for errors.Is; descriptor and route
// decoder errors retain their own causes. Service-specific route checks remain
// with the implementation. Success supplies startup facts, not installation trust.
func Bind(body []byte, config string) (Binding, error) {
	descriptor, err := artifact.DecodeDescriptor(body)
	if err != nil {
		return Binding{}, err
	}
	if descriptor.Role != "output" || descriptor.Output == nil {
		return Binding{}, fmt.Errorf("output binding: descriptor.role: unsupported family: %w", protocol.ErrProtocol)
	}
	if descriptor.Wire != DescriptorWire() {
		return Binding{}, fmt.Errorf("output binding: descriptor.wire: unsupported protocol: %w", protocol.ErrProtocol)
	}
	if descriptor.Output.ConfigContractID != config {
		return Binding{}, fmt.Errorf("output binding: descriptor.output.config_contract_id: unsupported contract: %w", protocol.ErrProtocol)
	}
	identity, err := descriptor.Identity()
	if err != nil {
		return Binding{}, err
	}
	route, err := credentialroute.Decode(descriptor.Output.CredentialRoute)
	if err != nil {
		return Binding{}, err
	}
	return Binding{name: descriptor.Name, identity: ImplementationIdentity{ProtocolID: protocol.ProtocolID(), DescriptorID: protocol.ID(identity)}, route: route}, nil
}

// Identity returns the canonical descriptor and family identities.
func (b Binding) Identity() ImplementationIdentity { return b.identity }

// CredentialRoute returns a copy of the checked public route.
func (b Binding) CredentialRoute() credentialroute.Route {
	route := b.route
	route.Names = append([]string(nil), route.Names...)
	route.PublicData = append([]byte(nil), route.PublicData...)
	return route
}

// Name returns the declared plugin name.
func (b Binding) Name() string { return b.name }
