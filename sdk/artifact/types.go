// Package artifact defines bounded public plugin artifact records.
// Record validation checks structure and byte bindings, not source trust, protocol
// semantics or permission to execute a plugin. The zero values of records require
// completion before encoding; Digest alone permits a zero value.
//
// Encode functions return newly allocated canonical bytes. Except for
// DecodeDescriptor, JSON record decoders require those exact canonical bytes.
// Malformed records support errors.Is(err, ErrRecord). File and build operations
// can also return I/O and context errors and require a nonnil context.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	// MaxMetadataBytes bounds canonical metadata bytes.
	MaxMetadataBytes = 1 << 20
	// MaxDependencyBytes bounds the complete encoded dependency body in bytes.
	MaxDependencyBytes = 1 << 20
	// MaxArchiveBytes bounds compressed archive bytes and expanded archive framing.
	MaxArchiveBytes = 545259520
	// MaxExecutableBytes bounds executable file bytes.
	MaxExecutableBytes = 536870912
	// MaxMarkerBytes bounds encoded local build-marker bytes.
	MaxMarkerBytes = 4096
	// MaxProofBytes bounds encoded official-proof bytes.
	MaxProofBytes = 1024
	// MaxRecordBytes bounds general encoded record bytes.
	MaxRecordBytes = 1 << 20
)

// ErrRecord identifies a refused artifact record; use errors.Is for wrapped errors.
var ErrRecord = errors.New("artifact record refused")

// Digest is a SHA-256 value. Its zero value is allowed by the codec; individual
// records can require a nonzero identity.
type Digest [32]byte

// Hash returns the SHA-256 of the exact bytes without retaining body.
func Hash(body []byte) Digest { return sha256.Sum256(body) }

// String returns 64 lowercase hexadecimal digits, including for a zero digest.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether all digest bytes are zero.
func (d Digest) IsZero() bool { return d == Digest{} }

// ParseDigest accepts exactly 64 lowercase hexadecimal digits or returns ErrRecord.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != 64 {
		return d, ErrRecord
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return d, ErrRecord
		}
	}
	_, err := hex.Decode(d[:], []byte(s))
	if err != nil {
		return Digest{}, ErrRecord
	}
	return d, nil
}

// MarshalJSON encodes the digest as a lowercase hexadecimal JSON string.
func (d Digest) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON accepts a JSON string containing 64 lowercase hexadecimal digits.
// It leaves d unchanged on failure and requires a nonnil receiver.
func (d *Digest) UnmarshalJSON(body []byte) error {
	var s string
	if json.Unmarshal(body, &s) != nil {
		return ErrRecord
	}
	v, err := ParseDigest(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// DigestLength binds the SHA-256 and length in bytes of one exact body.
type DigestLength struct {
	SHA256 Digest `json:"sha256"`
	Length uint64 `json:"length"`
}

// BuildOption preserves one executable build setting as a name/value pair.
type BuildOption struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Contract declares an identity and version for a wire protocol. Kind must be
// "wire", Identity must be a nonzero lowercase digest and Version must be nonzero.
// The declaration does not prove the executable implements that protocol.
type Contract struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Version  uint32 `json:"version"`
}

// Source binds a module path to the selected source-set digest for its family.
type Source struct {
	Module string `json:"module"`
	Digest Digest `json:"digest"`
}

// Replacement records the actual source owner of a replaced module. Local owners
// use an empty resolved version or "(devel)" compiled version, no Sum, and a
// nonzero SourceDigest. Versioned replacements use Version and Sum instead.
type Replacement struct {
	Path         string `json:"path"`
	Version      string `json:"version"`
	Sum          string `json:"sum"`
	SourceDigest Digest `json:"source_digest"`
}

// Dependency preserves a module path, version, checksum and optional replacement.
// Resolved and compiled representations remain separate; local resolved versions
// are empty, while compiled versions use "(devel)".
type Dependency struct {
	Path        string       `json:"path"`
	Version     string       `json:"version"`
	Sum         string       `json:"sum"`
	Replacement *Replacement `json:"replacement"`
}

// Family contains canonical family facts and the raw dependency-body binding.
// Facts uses FamilySchema; Dependency binds bytes rather than their semantic identity.
type Family struct {
	Schema     uint16          `json:"schema"`
	Facts      json.RawMessage `json:"facts"`
	Dependency DigestLength    `json:"dependency"`
}

// BuildFacts contains measured build and dependency facts without the executable
// digest. All slices must be nonnil. Options and sources are sorted by name/module;
// resolved and compiled modules are sorted by path. Contracts are sorted by kind,
// identity and version. Compiled is the actual contributing closure, including main;
// Resolved is the complete module graph. Sources includes local uncompiled owners.
type BuildFacts struct {
	Role         string        `json:"role"`
	MainModule   string        `json:"main_module"`
	Command      string        `json:"command"`
	Platform     string        `json:"platform"`
	Toolchain    string        `json:"toolchain"`
	BuildOptions []BuildOption `json:"build_options"`
	Contracts    []Contract    `json:"contracts"`
	Sources      []Source      `json:"sources"`
	Resolved     []Dependency  `json:"resolved"`
	Compiled     []Dependency  `json:"compiled"`
}

// Metadata binds author declarations to measured build facts and executable bytes.
// Schema is "enkv/plugin-artifact/v2" and Purpose is "plugin-executable". Family
// must agree with Name, Role, Version, Contracts and measured execution fields.
// Build-fact slice rules are those of BuildFacts. Valid metadata is not a trust grant.
type Metadata struct {
	Schema       string        `json:"schema"`
	Purpose      string        `json:"purpose"`
	Name         string        `json:"name"`
	Role         string        `json:"role"`
	Version      string        `json:"version"`
	MainModule   string        `json:"main_module"`
	Command      string        `json:"command"`
	Platform     string        `json:"platform"`
	Toolchain    string        `json:"toolchain"`
	BuildOptions []BuildOption `json:"build_options"`
	Contracts    []Contract    `json:"contracts"`
	Family       *Family       `json:"family"`
	Executable   DigestLength  `json:"executable"`
	Sources      []Source      `json:"sources"`
	Resolved     []Dependency  `json:"resolved"`
	Compiled     []Dependency  `json:"compiled"`
}

// BuildFacts returns a shallow projection. Slices and replacement pointers still
// alias m; the result is not a validated or immutable snapshot.
func (m Metadata) BuildFacts() BuildFacts {
	return BuildFacts{m.Role, m.MainModule, m.Command, m.Platform, m.Toolchain, m.BuildOptions, m.Contracts, m.Sources, m.Resolved, m.Compiled}
}

// Identity validates m and hashes its exact canonical metadata bytes.
func (m Metadata) Identity() (Digest, error) {
	b, err := EncodeMetadata(m)
	if err != nil {
		return Digest{}, err
	}
	return Hash(b), nil
}

// ExecutionFacts binds the descriptor, executable and dependency identities.
// BindGeneratorFacts, BindOutputFacts and BindManifestFacts derive the identity
// fields from the executable digest/length, dependency identity and declared
// Module, Command, GoVersion and NativeTuple. They do not measure an executable.
type ExecutionFacts struct {
	DescriptorID         Digest `json:"descriptor_id"`
	ExecutorID           Digest `json:"executor_id"`
	ArtifactContractID   Digest `json:"artifact_contract_id"`
	DependencyManifestID Digest `json:"dependency_manifest_id"`
	ArtifactSHA256       Digest `json:"artifact_sha256"`
	ArtifactLength       uint64 `json:"artifact_length"`
	Module               string `json:"module"`
	Command              string `json:"command"`
	GoVersion            string `json:"go_version"`
	NativeTuple          string `json:"native_tuple"`
}

type familyFacts struct {
	Schema     uint16     `json:"schema"`
	Descriptor Descriptor `json:"descriptor"`
	ExecutionFacts
}

// GeneratorFacts combines Schema, Descriptor and ExecutionFacts for a generator.
// Use FamilySchema and BindGeneratorFacts before encoding metadata.
type GeneratorFacts familyFacts

// OutputFacts combines Schema, Descriptor and ExecutionFacts for an output plugin.
// Use FamilySchema and BindOutputFacts before encoding metadata.
type OutputFacts familyFacts

// ManifestFacts combines Schema, Descriptor and ExecutionFacts for a manifest
// generator. Use FamilySchema and BindManifestFacts before encoding metadata.
type ManifestFacts familyFacts
