package artifact

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// full_only: false
func TestDependencyPreservesWorkspaceRepresentations(t *testing.T) {
	f := codecMetadata().BuildFacts()
	body, err := EncodeDependency(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDependency(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Resolved[0].Version != "" || got.Compiled[0].Version != "(devel)" {
		t.Fatal("representations changed")
	}
	for name, change := range map[string]func(*BuildFacts){"missing source": func(v *BuildFacts) { v.Sources = []Source{} }, "missing owner": func(v *BuildFacts) { v.Resolved = []Dependency{} }, "wrong main": func(v *BuildFacts) { v.MainModule = "example.test/other" }, "wrong version": func(v *BuildFacts) { v.Compiled[0].Version = "v1.0.0" }, "extra compiled": func(v *BuildFacts) {
		v.Compiled = append(v.Compiled, Dependency{Path: "example.test/z", Version: "v1.0.0"})
	}} {
		t.Run(name, func(t *testing.T) {
			v := codecMetadata().BuildFacts()
			change(&v)
			if _, err := EncodeDependency(v); !errors.Is(err, ErrRecord) {
				t.Fatal("incoherent closure accepted")
			}
		})
	}
}

// full_only: false
func TestDependencyFramingAndRoleBinding(t *testing.T) {
	f := codecMetadata().BuildFacts()
	f.Role = "generator"
	f.Contracts = []Contract{}
	body, err := EncodeDependency(f)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(body) != 3 || int(binary.BigEndian.Uint32(body[2:])) != len(body)-6 {
		t.Fatal("framing")
	}
	id, err := DependencyID("generator", body)
	if err != nil || id.IsZero() {
		t.Fatal(err)
	}
	if _, err := DependencyID("output", body); !errors.Is(err, ErrRecord) {
		t.Fatal("wrong role accepted")
	}
	changed := append([]byte(nil), body...)
	changed[5] ^= 1
	for _, bad := range [][]byte{body[:5], changed, append(append([]byte(nil), body...), 0), bytes.Repeat([]byte{0}, MaxDependencyBytes+1)} {
		if _, err := DecodeDependency(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid framing accepted")
		}
	}
}

// full_only: false
func TestDependencyLocalReplacementExactRelation(t *testing.T) {
	f := codecMetadata().BuildFacts()
	d := Digest{7}
	f.Sources = []Source{{Module: "example.test/main", Digest: d}}
	f.Resolved[0].Replacement = &Replacement{Path: "./helper", SourceDigest: d}
	f.Compiled[0].Replacement = &Replacement{Path: "./helper", Version: "(devel)", SourceDigest: d}
	if _, err := EncodeDependency(f); err != nil {
		t.Fatal(err)
	}
	f.Compiled[0].Replacement.Version = ""
	if _, err := EncodeDependency(f); !errors.Is(err, ErrRecord) {
		t.Fatal("rewritten compiled replacement accepted")
	}
}

// full_only: false
func TestDependencySourcesBindUncompiledResolvedLocalOwner(t *testing.T) {
	f := codecMetadata().BuildFacts()
	d := Digest{8}
	f.Resolved = append(f.Resolved, Dependency{Path: "example.test/unused", Version: "v1.0.0", Replacement: &Replacement{Path: "../unused", SourceDigest: d}})
	f.Sources = append(f.Sources, Source{Module: "example.test/unused", Digest: d})
	if _, err := EncodeDependency(f); err != nil {
		t.Fatal("resolved local metadata source refused", err)
	}
	f.Sources[1].Digest[0] ^= 1
	if _, err := EncodeDependency(f); !errors.Is(err, ErrRecord) {
		t.Fatal("unbound replacement digest accepted")
	}
	f.Sources[1].Digest = d
	f.Resolved = f.Resolved[:1]
	if _, err := EncodeDependency(f); !errors.Is(err, ErrRecord) {
		t.Fatal("source with no resolved owner accepted")
	}
}
