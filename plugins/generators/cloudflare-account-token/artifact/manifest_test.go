package artifact

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	public "enkv.sh/sdk/artifact"
)

func currentBuildFacts() public.BuildFacts {
	const module = "example.test/plugin"
	return public.BuildFacts{Role: "generator", MainModule: module, Command: module + "/cmd/plugin", Platform: "darwin/arm64", Toolchain: "go1.27.0", BuildOptions: []public.BuildOption{}, Contracts: []public.Contract{}, Sources: []public.Source{{Module: module, Digest: public.Digest{1}}}, Resolved: []public.Dependency{{Path: module}}, Compiled: []public.Dependency{{Path: module, Version: "(devel)"}}}
}

// full_only: false
func TestDependencyManifestBindsActualBuildFacts(t *testing.T) {
	facts := currentBuildFacts()
	body, identity, err := DependencyManifest(facts)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(body) != 3 {
		t.Fatal("new construction did not use schema3")
	}
	decoded, err := public.DecodeDependency(body)
	if err != nil || decoded.Command != facts.Command {
		t.Fatalf("current facts differ: %v", err)
	}
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v3/dependency-manifest\x00"), uint32(len(body)))
	expected := sha256.Sum256(append(preimage, body...))
	if identity != expected {
		t.Fatalf("identity differs: %x", identity)
	}
	for name, mutate := range map[string]func(*public.BuildFacts){
		"source":  func(f *public.BuildFacts) { f.Sources[0].Digest[1] ^= 1 },
		"command": func(f *public.BuildFacts) { f.Command += "-other" },
		"option": func(f *public.BuildFacts) {
			f.BuildOptions = []public.BuildOption{{Name: "-tags", Value: "controlled"}}
		},
		"tuple":      func(f *public.BuildFacts) { f.Platform = "linux/amd64" },
		"dependency": func(f *public.BuildFacts) { f.Resolved[0].Version = "v1.2.3"; f.Compiled[0].Version = "v1.2.3" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := currentBuildFacts()
			mutate(&changed)
			_, changedID, err := DependencyManifest(changed)
			if err != nil || changedID == identity {
				t.Fatalf("input did not bind: %x %v", changedID, err)
			}
		})
	}
	invalid := currentBuildFacts()
	invalid.Role = "output"
	if _, _, err := DependencyManifest(invalid); !errors.Is(err, ErrManifest) {
		t.Fatal("accepted wrong family", err)
	}
	invalid = currentBuildFacts()
	invalid.Sources = nil
	if _, _, err := DependencyManifest(invalid); !errors.Is(err, ErrManifest) {
		t.Fatal("accepted missing sources", err)
	}
}
