package artifact

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// full_only: false
func TestArtifactVectorFieldBounds(t *testing.T) {
	for _, row := range []struct {
		field string
		bound int
	}{{"build_options", 64}, {"contracts", 64}, {"sources", 256}, {"resolved", 256}, {"compiled", 256}} {
		for _, n := range []int{row.bound - 1, row.bound, row.bound + 1} {
			t.Run(fmt.Sprintf("%s/%d", row.field, n), func(t *testing.T) {
				v := codecMetadata().BuildFacts()
				switch row.field {
				case "build_options":
					v.BuildOptions = make([]BuildOption, n)
					for i := range v.BuildOptions {
						v.BuildOptions[i] = BuildOption{Name: fmt.Sprintf("option%03d", i), Value: "value"}
					}
				case "contracts":
					v.Contracts = make([]Contract, n)
					for i := range v.Contracts {
						v.Contracts[i] = Contract{Kind: "wire", Identity: Digest{1}.String(), Version: uint32(i + 1)}
					}
				case "resolved":
					v.Resolved = make([]Dependency, n)
					for i := range v.Resolved {
						path := v.MainModule
						if i > 0 {
							path = fmt.Sprintf("example.test/other%03d", i)
						}
						v.Resolved[i] = Dependency{Path: path}
					}
				case "sources", "compiled":
					v.Sources = make([]Source, n)
					v.Resolved = make([]Dependency, n)
					for i := range n {
						path := v.MainModule
						if i > 0 {
							path = fmt.Sprintf("example.test/other%03d", i)
						}
						v.Sources[i] = Source{Module: path, Digest: Digest{1}}
						v.Resolved[i] = Dependency{Path: path}
					}
					if row.field == "compiled" {
						v.Compiled = make([]Dependency, n)
						for i := range n {
							v.Compiled[i] = Dependency{Path: v.Resolved[i].Path, Version: "(devel)"}
						}
					}
				}
				if row.field == "resolved" && (len(v.Sources) != 1 || len(v.Compiled) != 1) {
					t.Fatal("resolved-module bound fixture also changes source or compiled counts")
				}
				body, err := EncodeDependency(v)
				want := n <= row.bound
				if (err == nil) != want {
					t.Fatal("typed dependency count admission changed", err)
				}
				if want {
					decoded, err := DecodeDependency(body)
					if err != nil || !reflect.DeepEqual(decoded, v) {
						t.Fatal("complete dependency changed", err)
					}
				}
				raw, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				framed := binary.BigEndian.AppendUint16(nil, 3)
				framed = binary.BigEndian.AppendUint32(framed, uint32(len(raw)))
				_, err = DecodeDependency(append(framed, raw...))
				if (err == nil) != want {
					t.Fatal("raw dependency count admission changed", err)
				}
			})
		}
	}
	for _, row := range []struct {
		field string
		bound int
	}{{"releases", 256}, {"applications", 256}, {"plugins", 64}, {"selections", 64}} {
		for _, n := range []int{row.bound - 1, row.bound, row.bound + 1} {
			t.Run(fmt.Sprintf("%s/%d", row.field, n), func(t *testing.T) {
				var value any
				var encode func() ([]byte, error)
				var decode func([]byte) error
				switch row.field {
				case "releases":
					v := ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: "plugin", Releases: make([]Release, n)}
					for i := range n {
						v.Releases[i] = Release{Version: fmt.Sprintf("1.0.%d", i), Platform: "linux/amd64", Artifact: Digest{1}}
					}
					value, encode, decode = v, func() ([]byte, error) { return EncodeReleaseIndex(v) }, func(b []byte) error { _, e := DecodeReleaseIndex(b); return e }
				case "applications", "plugins":
					v := Settings{Schema: "enkv/plugin-settings/v1", Applications: []Application{{Directory: "/app", Plugins: []LocalPlugin{}}}}
					if row.field == "applications" {
						v.Applications = make([]Application, n)
						for i := range n {
							v.Applications[i] = Application{Directory: fmt.Sprintf("/app%03d", i), Plugins: []LocalPlugin{}}
						}
					} else {
						v.Applications[0].Plugins = make([]LocalPlugin, n)
						for i := range n {
							v.Applications[0].Plugins[i] = LocalPlugin{Name: fmt.Sprintf("plugin%03d", i), Directory: "/build"}
						}
					}
					value, encode, decode = v, func() ([]byte, error) { return EncodeSettings(v) }, func(b []byte) error { _, e := DecodeSettings(b); return e }
				case "selections":
					v := SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: "/app", Selections: make([]Selection, n)}
					for i := range n {
						v.Selections[i] = Selection{Name: fmt.Sprintf("plugin%03d", i), Version: "1.0.0", Platform: "linux/amd64", Artifact: Digest{1}, Proof: Digest{2}}
					}
					value, encode, decode = v, func() ([]byte, error) { return EncodeSelectionRecord(v) }, func(b []byte) error { _, e := DecodeSelectionRecord(b); return e }
				}
				body, err := encode()
				want := n <= row.bound
				if (err == nil) != want {
					t.Fatal("typed record count admission changed", err)
				}
				if want && decode(body) != nil {
					t.Fatal("encoded complete record refused")
				}
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if (decode(raw) == nil) != want {
					t.Fatal("raw record count admission changed")
				}
			})
		}
	}
}

// full_only: false
func TestArchiveVectorBoundKeepsClosedMemberNames(t *testing.T) {
	base := ArchiveRecord{Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: Digest{1}, Name: "plugin", Version: "1.0.0", Platform: "linux/amd64", Archive: ArchiveFile{Filename: "plugin.tar.gz", SHA256: Digest{1}, Length: 1}}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "dependencies.bin", "metadata.json", "metadata.sig", "plugin"} {
		length := uint64(1)
		if name == "metadata.sig" {
			length = 64
		}
		base.Members = append(base.Members, ArchiveMember{Name: name, Length: length, SHA256: Digest{1}})
	}
	for _, n := range []int{7, 8, 9} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			v := base
			v.Members = append([]ArchiveMember(nil), base.Members...)
			for len(v.Members) < n {
				v.Members = append(v.Members, base.Members[len(base.Members)-1])
			}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var decoded ArchiveRecord
			if err := decodeRecord(raw, MaxRecordBytes, &decoded); (err == nil) != (n <= 8) {
				t.Fatal("raw vector boundary changed", err)
			}
			// The closed name set has only seven members; the generic eight-item
			// vector bound does not permit duplicate or additional member names.
			if _, err := EncodeArchiveRecord(v); (err == nil) != (n == 7) {
				t.Fatal("typed closed member set changed", err)
			}
			if _, err := DecodeArchiveRecord(raw); (err == nil) != (n == 7) {
				t.Fatal("raw closed member set changed", err)
			}
		})
	}
}
