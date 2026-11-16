package artifact

import (
	"context"
	"unicode/utf8"

	"enkv.sh/sdk/artifact/credentialroute"
)

const (
	// DescriptorSchema is the author descriptor schema version.
	DescriptorSchema uint16 = 1
	// FamilySchema is the measured family-facts schema version.
	FamilySchema uint16 = 2
	// MaxDescriptorBytes bounds the complete author JSON file in bytes.
	MaxDescriptorBytes = 16384
	// MaxFamilyFactsBytes bounds canonical family-facts JSON bytes.
	MaxFamilyFactsBytes = 65536
	// MaxSemanticBytes bounds each public semantic contract string in UTF-8 bytes.
	MaxSemanticBytes = 256
)

// Descriptor is the author-owned pre-build declaration. Schema is DescriptorSchema;
// Name is a portable plugin ID, Version is an exact semantic version and Role is
// "generator", "output" or "manifest-generator". Wire declares the family protocol.
// Exactly the matching declaration pointer must be set. It contains no measured
// build facts and grants no host or service permission.
type Descriptor struct {
	Schema    uint16                `json:"schema"`
	Name      string                `json:"name"`
	Role      string                `json:"role"`
	Version   string                `json:"version"`
	Wire      Contract              `json:"wire"`
	Generator *GeneratorDeclaration `json:"generator"`
	Output    *OutputDeclaration    `json:"output"`
	Manifest  *ManifestDeclaration  `json:"manifest"`
}

// GeneratorDeclaration declares the nonzero configuration-contract digest and
// encoded public credential route. CredentialRoute must pass credentialroute.Decode.
type GeneratorDeclaration struct {
	ConfigContractID Digest `json:"config_contract_id"`
	CredentialRoute  []byte `json:"credential_route"`
}

// OutputDeclaration declares a nonempty configuration-contract string and encoded
// public credential route. The string is bounded by MaxSemanticBytes; the route
// must pass credentialroute.Decode.
type OutputDeclaration struct {
	ConfigContractID string `json:"config_contract_id"`
	CredentialRoute  []byte `json:"credential_route"`
}

// ManifestDeclaration declares nonempty configuration and format contract strings,
// each bounded by MaxSemanticBytes of valid UTF-8. Their meanings belong to the plugin.
type ManifestDeclaration struct {
	ConfigContractID string `json:"config_contract_id"`
	FormatContractID string `json:"format_contract_id"`
}

func validSemantic(s string) bool {
	return len(s) > 0 && len(s) <= MaxSemanticBytes && utf8.ValidString(s)
}

func validDescriptor(v Descriptor) bool {
	wire, err := ParseDigest(v.Wire.Identity)
	if v.Schema != DescriptorSchema || !safeBasename(v.Name) || !validRole(v.Role) || !ValidVersion(v.Version) || v.Wire.Kind != "wire" || v.Wire.Version == 0 || err != nil || wire.IsZero() {
		return false
	}
	switch v.Role {
	case "generator":
		if v.Generator == nil || v.Output != nil || v.Manifest != nil || v.Generator.ConfigContractID.IsZero() {
			return false
		}
		_, err = credentialroute.Decode(v.Generator.CredentialRoute)
		return err == nil
	case "output":
		if v.Output == nil || v.Generator != nil || v.Manifest != nil || !validSemantic(v.Output.ConfigContractID) {
			return false
		}
		_, err = credentialroute.Decode(v.Output.CredentialRoute)
		return err == nil
	case "manifest-generator":
		return v.Manifest != nil && v.Generator == nil && v.Output == nil && validSemantic(v.Manifest.ConfigContractID) && validSemantic(v.Manifest.FormatContractID)
	}
	return false
}

// EncodeDescriptor validates the author declaration and returns canonical JSON.
func EncodeDescriptor(v Descriptor) ([]byte, error) {
	return encodeRecord(v, MaxDescriptorBytes, validDescriptor(v))
}

// DecodeDescriptor validates bounded author JSON. It accepts whitespace and field
// order, but rejects unknown, duplicate and incorrectly cased field names. Returned
// slices are owned and do not borrow body. Refusals support errors.Is(err, ErrRecord).
func DecodeDescriptor(body []byte) (Descriptor, error) {
	var v Descriptor
	if err := decodeRecord(body, MaxDescriptorBytes, &v); err != nil {
		return Descriptor{}, err
	}
	if _, err := EncodeDescriptor(v); err != nil {
		return Descriptor{}, ErrRecord
	}
	return v, nil
}

// ReadDescriptor reads one bounded regular author file and returns its exact
// original bytes for a later source-stability check.
func ReadDescriptor(ctx context.Context, path string) (Descriptor, []byte, error) {
	if ctx == nil {
		return Descriptor{}, nil, ErrRecord
	}
	body, err := readBounded(ctx, path, MaxDescriptorBytes)
	if err != nil {
		return Descriptor{}, nil, err
	}
	descriptor, err := DecodeDescriptor(body)
	if err != nil {
		return Descriptor{}, nil, err
	}
	return descriptor, body, nil
}

// Identity validates v and hashes its canonical author declaration with the
// descriptor domain separator. Formatting and measured build facts are excluded.
func (v Descriptor) Identity() (Digest, error) {
	body, err := EncodeDescriptor(v)
	if err != nil {
		return Digest{}, err
	}
	return Hash(blob([]byte("ENKV/PLUGIN-DESCRIPTOR/v1\x00"), body)), nil
}

// ValidPluginID checks the portable local identity grammar without a catalog.
func ValidPluginID(name string) bool { return safeBasename(name) }
