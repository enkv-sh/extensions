package native

import (
	"fmt"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

// Implementation combines checked startup facts with the author's callbacks.
// Its zero value cannot serve. It grants no host or Reader admission.
type Implementation struct {
	manifest.Implementation
	identity manifest.Identity
}

// Identity returns the canonical descriptor and family identities.
func (v Implementation) Identity() manifest.Identity { return v.identity }

// DescriptorWire returns the current family declaration for author descriptors.
func DescriptorWire() artifact.Contract {
	return artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: protocol.Version}
}

// Bind checks the family and the explicitly supported config and format
// contracts before any author callback can receive a request. It derives the
// identity from the decoded descriptor and does not retain body. It does not
// invoke or check callback presence; Serve requires both callbacks. Invalid
// descriptors and unsupported declarations wrap artifact.ErrRecord for errors.Is.
// Binding establishes startup compatibility, not installed-build trust.
func Bind(body []byte, config, format string, callbacks manifest.Implementation) (Implementation, error) {
	descriptor, err := artifact.DecodeDescriptor(body)
	if err != nil {
		return Implementation{}, err
	}
	if descriptor.Role != "manifest-generator" || descriptor.Manifest == nil {
		return Implementation{}, fmt.Errorf("manifest binding: descriptor.role: unsupported family: %w", artifact.ErrRecord)
	}
	if descriptor.Wire != DescriptorWire() {
		return Implementation{}, fmt.Errorf("manifest binding: descriptor.wire: unsupported protocol: %w", artifact.ErrRecord)
	}
	if descriptor.Manifest.ConfigContractID != config {
		return Implementation{}, fmt.Errorf("manifest binding: descriptor.manifest.config_contract_id: unsupported contract: %w", artifact.ErrRecord)
	}
	if descriptor.Manifest.FormatContractID != format {
		return Implementation{}, fmt.Errorf("manifest binding: descriptor.manifest.format_contract_id: unsupported contract: %w", artifact.ErrRecord)
	}
	identity, err := descriptor.Identity()
	if err != nil {
		return Implementation{}, err
	}
	return Implementation{Implementation: callbacks, identity: manifest.Identity{ProtocolID: protocol.ProtocolID(), DescriptorID: manifest.ID(identity)}}, nil
}
