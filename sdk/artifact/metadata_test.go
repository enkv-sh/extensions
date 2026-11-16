package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func codecMetadata() Metadata {
	d := Digest{1}
	descriptor := authorDescriptor("manifest-generator")
	m := Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: descriptor.Role, Version: descriptor.Version, MainModule: "example.test/main", Command: "example.test/main/cmd/plugin", Platform: "linux/amd64", Toolchain: "go1.27.0", BuildOptions: []BuildOption{}, Contracts: []Contract{descriptor.Wire}, Executable: DigestLength{d, 1}, Sources: []Source{{Module: "example.test/main", Digest: d}}, Resolved: []Dependency{{Path: "example.test/main"}}, Compiled: []Dependency{{Path: "example.test/main", Version: "(devel)"}}}
	return fixtureBoundMetadata(m, descriptor)
}

func fixtureDependency(m Metadata) []byte {
	body, err := EncodeDependency(m.BuildFacts())
	if err != nil {
		panic(err)
	}
	return body
}

func fixtureBoundMetadata(m Metadata, descriptor Descriptor) Metadata {
	m.Name, m.Role, m.Version, m.Contracts = descriptor.Name, descriptor.Role, descriptor.Version, []Contract{descriptor.Wire}
	dependency := fixtureDependency(m)
	identity, err := DependencyID(m.Role, dependency)
	if err != nil {
		panic(err)
	}
	execution := ExecutionFacts{Module: m.MainModule, Command: m.Command, GoVersion: m.Toolchain, NativeTuple: m.Platform}
	var facts any
	switch descriptor.Role {
	case "generator":
		facts, err = BindGeneratorFacts(GeneratorFacts{Schema: FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, m.Executable.SHA256, m.Executable.Length, identity)
	case "output":
		facts, err = BindOutputFacts(OutputFacts{Schema: FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, m.Executable.SHA256, m.Executable.Length, identity)
	case "manifest-generator":
		facts, err = BindManifestFacts(ManifestFacts{Schema: FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, m.Executable.SHA256, m.Executable.Length, identity)
	}
	if err != nil {
		panic(err)
	}
	body, err := json.Marshal(facts)
	if err != nil {
		panic(err)
	}
	m.Family = &Family{Schema: FamilySchema, Facts: body, Dependency: DigestLength{SHA256: Hash(dependency), Length: uint64(len(dependency))}}
	return m
}

// full_only: false
func TestMetadataCanonicalBoundary(t *testing.T) {
	m := codecMetadata()
	body, err := EncodeMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	round, err := EncodeMetadata(decoded)
	if err != nil || !bytes.Equal(body, round) {
		t.Fatal("round trip", err)
	}
	for name, damage := range map[string][]byte{
		"newline":     append(append([]byte(nil), body...), '\n'),
		"unknown":     bytes.Replace(body, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		"duplicate":   bytes.Replace(body, []byte(`"schema":`), []byte(`"schema":"enkv/plugin-artifact/v2","schema":`), 1),
		"null_vector": bytes.Replace(body, []byte(`"build_options":[]`), []byte(`"build_options":null`), 1),
		"escape":      bytes.Replace(body, []byte(`private-local-inventory`), []byte(`private\u002dlocal-inventory`), 1),
		"trailing":    append(append([]byte(nil), body...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMetadata(damage); !errors.Is(err, ErrRecord) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

// full_only: false
func TestMetadataFutureSemanticsRemainDecodable(t *testing.T) {
	m := codecMetadata()
	descriptor := authorDescriptor("manifest-generator")
	descriptor.Wire = Contract{Kind: "wire", Identity: Digest{99}.String(), Version: 30}
	descriptor.Manifest.ConfigContractID = "future-settings/v20"
	descriptor.Manifest.FormatContractID = "future-format/v90"
	m = fixtureBoundMetadata(m, descriptor)
	body, err := EncodeMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMetadata(body); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestMetadataStringAndVectorBounds(t *testing.T) {
	m := codecMetadata()
	m.Toolchain = strings.Repeat("x", 1024)
	descriptor, _ := m.Descriptor()
	m = fixtureBoundMetadata(m, descriptor)
	if _, err := EncodeMetadata(m); err != nil {
		t.Fatal(err)
	}
	m.Toolchain += "x"
	if _, err := EncodeMetadata(m); !errors.Is(err, ErrRecord) {
		t.Fatal("long string accepted")
	}
	m = codecMetadata()
	for i := 0; i < 65; i++ {
		m.BuildOptions = append(m.BuildOptions, BuildOption{Name: strings.Repeat("a", i+1)})
	}
	body, _ := json.Marshal(m)
	if _, err := DecodeMetadata(body); !errors.Is(err, ErrRecord) {
		t.Fatal("large vector accepted")
	}
}

// full_only: false
func TestMeasuredToolchainBounds(t *testing.T) {
	for _, length := range []int{1024, 1025} {
		toolchain := strings.Repeat("x", length)
		m := codecMetadata()
		facts := m.BuildFacts()
		facts.Toolchain = toolchain
		if _, err := EncodeDependency(facts); (err == nil) != (length == 1024) {
			t.Fatalf("dependency toolchain length %d: %v", length, err)
		}
		for _, role := range []string{"generator", "output", "manifest-generator"} {
			execution := ExecutionFacts{Module: m.MainModule, Command: m.Command, GoVersion: toolchain, NativeTuple: m.Platform}
			declaration := familyFacts{Schema: FamilySchema, Descriptor: authorDescriptor(role), ExecutionFacts: execution}
			var err error
			switch role {
			case "generator":
				_, err = BindGeneratorFacts(GeneratorFacts(declaration), m.Executable.SHA256, m.Executable.Length, Digest{1})
			case "output":
				_, err = BindOutputFacts(OutputFacts(declaration), m.Executable.SHA256, m.Executable.Length, Digest{1})
			case "manifest-generator":
				_, err = BindManifestFacts(ManifestFacts(declaration), m.Executable.SHA256, m.Executable.Length, Digest{1})
			}
			if (err == nil) != (length == 1024) {
				t.Fatalf("%s toolchain length %d: %v", role, length, err)
			}
		}
	}
}

// full_only: false
func TestFamilyBindingsRejectChangedDerivedIdentity(t *testing.T) {
	m := fixtureBoundMetadata(codecMetadata(), authorDescriptor("output"))
	bound, err := m.OutputFacts()
	if err != nil {
		t.Fatal(err)
	}
	bound.ExecutorID[0] ^= 1
	m.Family.Facts, _ = json.Marshal(bound)
	if _, err := m.OutputFacts(); !errors.Is(err, ErrRecord) {
		t.Fatal("changed executor accepted")
	}
}

// full_only: false
func TestGeneratorArtifactProjectionRejectsRuntimeBindings(t *testing.T) {
	m := fixtureBoundMetadata(codecMetadata(), authorDescriptor("generator"))
	for _, field := range []string{"account", "credential_producer_id", "permission_contract_id"} {
		bad := m
		bad.Family = &Family{Schema: FamilySchema, Facts: bytes.Replace(m.Family.Facts, []byte(`"schema":2`), []byte(`"schema":2,"`+field+`":"runtime"`), 1)}
		if _, err := bad.GeneratorFacts(); !errors.Is(err, ErrRecord) {
			t.Fatal("runtime binding accepted", field)
		}
	}
}

// full_only: false
func TestMetadataIndependentManifestFixture(t *testing.T) {
	// Fixed metadata and its dependency were derived with Python hashlib/json,
	// independently from the Go codec, in archive_test.go.
	const body = packageMetadata
	const identity = packageMetadataIdentity
	m, err := DecodeMetadata([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeMetadata(m)
	if err != nil || string(got) != body {
		t.Fatal("independent canonical bytes differ", err)
	}
	id, err := m.Identity()
	if err != nil || id.String() != identity {
		t.Fatal("independent identity differs", id, err)
	}
}
