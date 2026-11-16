package artifact

import (
	"encoding/binary"
	"slices"
)

func bindExecution(role string, descriptor Descriptor, execution ExecutionFacts, digest Digest, length uint64, dependency Digest) (ExecutionFacts, error) {
	if descriptor.Role != role || !validDescriptor(descriptor) || digest.IsZero() || length == 0 || length > MaxExecutableBytes || dependency.IsZero() || !text(execution.Module) || !text(execution.Command) || !text(execution.GoVersion) || !validPlatform(execution.NativeTuple) {
		return ExecutionFacts{}, ErrRecord
	}
	descriptorID, err := descriptor.Identity()
	if err != nil {
		return ExecutionFacts{}, err
	}
	execution.DescriptorID = descriptorID
	execution.ArtifactSHA256, execution.ArtifactLength, execution.DependencyManifestID = digest, length, dependency
	body := blob([]byte("ENKV/PLUGIN-EXECUTOR/v1\x00"), []byte(role))
	body = append(body, digest[:]...)
	body = binary.BigEndian.AppendUint64(body, length)
	body = append(body, dependency[:]...)
	for _, value := range []string{execution.Module, execution.Command, execution.GoVersion, execution.NativeTuple} {
		body = blob(body, []byte(value))
	}
	execution.ExecutorID = Hash(body)
	body = append([]byte("ENKV/PLUGIN-ARTIFACT/v1\x00"), execution.ExecutorID[:]...)
	execution.ArtifactContractID = Hash(append(body, descriptorID[:]...))
	return execution, nil
}

func bindFamily(role string, v familyFacts, digest Digest, length uint64, dependency Digest) (familyFacts, error) {
	if v.Schema != FamilySchema {
		return familyFacts{}, ErrRecord
	}
	execution, err := bindExecution(role, v.Descriptor, v.ExecutionFacts, digest, length, dependency)
	if err != nil {
		return familyFacts{}, err
	}
	v.ExecutionFacts = execution
	return v, nil
}

// BindGeneratorFacts validates the generator declaration and derives execution bindings.
// Supply measured executable digest/length, the role-specific DependencyID, and
// Module, Command, GoVersion and NativeTuple in v. Derived fields are overwritten;
// no file is read. Descriptor slices/pointers remain shared with v.
func BindGeneratorFacts(v GeneratorFacts, digest Digest, length uint64, dependency Digest) (GeneratorFacts, error) {
	value, err := bindFamily("generator", familyFacts(v), digest, length, dependency)
	return GeneratorFacts(value), err
}

// BindOutputFacts validates the output declaration and derives execution bindings.
// Supply measured executable digest/length, the role-specific DependencyID, and
// Module, Command, GoVersion and NativeTuple in v. Derived fields are overwritten;
// no file is read. Descriptor slices/pointers remain shared with v.
func BindOutputFacts(v OutputFacts, digest Digest, length uint64, dependency Digest) (OutputFacts, error) {
	value, err := bindFamily("output", familyFacts(v), digest, length, dependency)
	return OutputFacts(value), err
}

// BindManifestFacts validates the manifest-generator declaration and derives execution bindings.
// Supply measured executable digest/length, the role-specific DependencyID, and
// Module, Command, GoVersion and NativeTuple in v. Derived fields are overwritten;
// no file is read. Descriptor slices/pointers remain shared with v.
func BindManifestFacts(v ManifestFacts, digest Digest, length uint64, dependency Digest) (ManifestFacts, error) {
	value, err := bindFamily("manifest-generator", familyFacts(v), digest, length, dependency)
	return ManifestFacts(value), err
}

func (m Metadata) family(role string) (familyFacts, error) {
	var v familyFacts
	if m.Role != role || m.Family == nil || m.Family.Schema != FamilySchema {
		return familyFacts{}, ErrRecord
	}
	if err := decodeRecord(m.Family.Facts, MaxFamilyFactsBytes, &v); err != nil {
		return familyFacts{}, err
	}
	bound, err := bindFamily(role, v, v.ArtifactSHA256, v.ArtifactLength, v.DependencyManifestID)
	if err != nil || bound.ExecutionFacts != v.ExecutionFacts {
		return familyFacts{}, ErrRecord
	}
	body, err := encodeRecord(v, MaxFamilyFactsBytes, true)
	if canonical(m.Family.Facts, body, err) != nil {
		return familyFacts{}, ErrRecord
	}
	return v, nil
}

// GeneratorFacts decodes canonical generator facts and checks their derived bindings.
// It does not validate the complete outer metadata or authenticate its source.
func (m Metadata) GeneratorFacts() (GeneratorFacts, error) {
	value, err := m.family("generator")
	return GeneratorFacts(value), err
}

// OutputFacts decodes canonical output facts and checks their derived bindings.
// It does not validate the complete outer metadata or authenticate its source.
func (m Metadata) OutputFacts() (OutputFacts, error) {
	value, err := m.family("output")
	return OutputFacts(value), err
}

// ManifestFacts decodes canonical manifest-generator facts and checks their derived bindings.
// It does not validate the complete outer metadata or authenticate its source.
func (m Metadata) ManifestFacts() (ManifestFacts, error) {
	value, err := m.family("manifest-generator")
	return ManifestFacts(value), err
}

// Descriptor returns the decoded author declaration after checking canonical
// family facts and derived bindings; it does not validate all outer metadata fields.
func (m Metadata) Descriptor() (Descriptor, error) {
	value, err := m.family(m.Role)
	return value.Descriptor, err
}

// ExecutionFacts returns checked family execution bindings without measuring files
// or validating every outer metadata field.
func (m Metadata) ExecutionFacts() (ExecutionFacts, error) {
	value, err := m.family(m.Role)
	return value.ExecutionFacts, err
}

func validateMetadata(m Metadata) error {
	if !safeBasename(m.Name) || !validRole(m.Role) || m.Schema != "enkv/plugin-artifact/v2" || m.Purpose != "plugin-executable" || !ValidVersion(m.Version) || !validBuildFacts(m.BuildFacts()) || m.Executable.SHA256.IsZero() || m.Executable.Length == 0 || m.Executable.Length > MaxExecutableBytes || m.Family == nil || m.Family.Schema != FamilySchema || m.Family.Dependency.SHA256.IsZero() || m.Family.Dependency.Length == 0 || m.Family.Dependency.Length > MaxDependencyBytes {
		return ErrRecord
	}
	v, err := m.family(m.Role)
	if err != nil {
		return err
	}
	if v.Descriptor.Name != m.Name || v.Descriptor.Role != m.Role || v.Descriptor.Version != m.Version || !slices.Equal(m.Contracts, []Contract{v.Descriptor.Wire}) || v.ArtifactSHA256 != m.Executable.SHA256 || v.ArtifactLength != m.Executable.Length || v.Module != m.MainModule || v.Command != m.Command || v.GoVersion != m.Toolchain || v.NativeTuple != m.Platform {
		return ErrRecord
	}
	return nil
}

// EncodeMetadata validates the complete metadata relations and returns canonical JSON.
func EncodeMetadata(v Metadata) ([]byte, error) {
	if err := validateMetadata(v); err != nil {
		return nil, err
	}
	return encodeRecord(v, MaxMetadataBytes, true)
}

// DecodeMetadata checks bounded canonical JSON and all metadata relations.
// On error, disregard the returned value. Success does not authenticate its producer.
func DecodeMetadata(body []byte) (Metadata, error) {
	var v Metadata
	if err := decodeRecord(body, MaxMetadataBytes, &v); err != nil {
		return v, err
	}
	encoded, err := EncodeMetadata(v)
	if err != nil {
		return Metadata{}, err
	}
	if canonical(body, encoded, err) != nil {
		return Metadata{}, ErrRecord
	}
	return v, nil
}
