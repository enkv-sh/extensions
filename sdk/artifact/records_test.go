package artifact

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestBuildMarkerIndependentCanonicalBytes(t *testing.T) {
	d := Digest{1}
	v := BuildMarker{Schema: "enkv/plugin-build/v1", Artifact: d, Directory: "builds/" + d.String()}
	const want = `{"schema":"enkv/plugin-build/v1","artifact":"0100000000000000000000000000000000000000000000000000000000000000","directory":"builds/0100000000000000000000000000000000000000000000000000000000000000"}`
	b, err := EncodeBuildMarker(v)
	if err != nil || string(b) != want {
		t.Fatalf("marker %s %v", b, err)
	}
	if _, err := DecodeBuildMarker([]byte(want)); err != nil {
		t.Fatal(err)
	}
	v.Directory = "builds/other"
	if _, err := EncodeBuildMarker(v); !errors.Is(err, ErrRecord) {
		t.Fatal("unbound directory accepted")
	}
}

// full_only: false
func TestOfficialProofClosedNonzeroFields(t *testing.T) {
	v := OfficialProof{Schema: "enkv/plugin-official-proof/v1", Artifact: Digest{1}, ArchiveRecord: Digest{2}, MetadataSignature: Digest{3}, ArchiveSignature: Digest{4}}
	b, err := EncodeOfficialProof(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOfficialProof(b); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{"unknown": bytes.Replace(b, []byte(`"schema":`), []byte(`"key":"key","schema":`), 1), "missing": bytes.Replace(b, []byte(`"artifact":"0100000000000000000000000000000000000000000000000000000000000000",`), nil, 1), "trailing": append(append([]byte(nil), b...), '\n')} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeOfficialProof(bad); !errors.Is(err, ErrRecord) {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	v.ArchiveSignature = Digest{}
	if _, err := EncodeOfficialProof(v); !errors.Is(err, ErrRecord) {
		t.Fatal("zero evidence accepted")
	}
}

// full_only: false
func TestReleaseIndexSemanticOrderAndImmutablePair(t *testing.T) {
	v := ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: "generic-json", Releases: []Release{{Version: "1.0.0-rc.1", Platform: "linux/amd64", Artifact: Digest{1}}, {Version: "1.0.0", Platform: "linux/amd64", Artifact: Digest{2}}}}
	b, err := EncodeReleaseIndex(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReleaseIndex(b); err != nil {
		t.Fatal(err)
	}
	v.Releases = append(v.Releases, Release{Version: "1.0.0", Platform: "linux/amd64", Artifact: Digest{3}})
	if _, err := EncodeReleaseIndex(v); !errors.Is(err, ErrRecord) {
		t.Fatal("conflicting pair accepted")
	}
}

// full_only: false
func TestSettingsAndSelectionClosedShapes(t *testing.T) {
	s := Settings{Schema: "enkv/plugin-settings/v1", Applications: []Application{{Directory: "/app", Plugins: []LocalPlugin{{Name: "generic-json", Directory: "/build"}}}}}
	b, err := EncodeSettings(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSettings(b); err != nil {
		t.Fatal(err)
	}
	s.Applications[0].Directory = "/app/../app"
	if _, err := EncodeSettings(s); !errors.Is(err, ErrRecord) {
		t.Fatal("unclean directory accepted")
	}
	r := SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: "/app", Selections: []Selection{{Name: "generic-json", Version: "1.0.0", Platform: "linux/amd64", Artifact: Digest{1}, Proof: Digest{2}}}}
	b, err = EncodeSelectionRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSelectionRecord(b); err != nil {
		t.Fatal(err)
	}
	r.Selections[0].Proof = Digest{}
	if _, err := EncodeSelectionRecord(r); !errors.Is(err, ErrRecord) {
		t.Fatal("proofless official selection accepted")
	}
}

// full_only: false
func TestSettingsEditableJSONPreservesApplicationTrust(t *testing.T) {
	const editable = `{
  "applications": [
    {"plugins":[{"directory":"/build/beta-z","name":"zeta"},{"name":"alpha","directory":"/build/beta-a"}],"directory":"/beta"},
    {"directory":"/alpha","plugins":[{"name":"zeta","directory":"/build/alpha-z"},{"directory":"/build/alpha-a","name":"alpha"}]}
  ], "schema":"enkv/plugin-settings/v1"
}
`
	want := Settings{Schema: "enkv/plugin-settings/v1", Applications: []Application{
		{Directory: "/alpha", Plugins: []LocalPlugin{{Name: "alpha", Directory: "/build/alpha-a"}, {Name: "zeta", Directory: "/build/alpha-z"}}},
		{Directory: "/beta", Plugins: []LocalPlugin{{Name: "alpha", Directory: "/build/beta-a"}, {Name: "zeta", Directory: "/build/beta-z"}}},
	}}
	got, err := DecodeSettings([]byte(editable))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("editable settings changed application trust: got=%+v err=%v", got, err)
	}
}

// full_only: false
func TestSettingsEditableJSONRejectsInvalidRecords(t *testing.T) {
	const valid = `{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/app","plugins":[{"name":"alpha","directory":"/build"}]}]}`
	for name, body := range map[string][]byte{
		"duplicate-key":          []byte(strings.Replace(valid, `"schema":`, `"schema":"enkv/plugin-settings/v1","schema":`, 1)),
		"duplicate-decoded-key":  []byte(strings.Replace(valid, `"schema":`, `"sch\u0065ma":"enkv/plugin-settings/v1","schema":`, 1)),
		"duplicate-application":  []byte(`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/app","plugins":[]},{"directory":"/other","plugins":[]},{"directory":"/app","plugins":[]}]}`),
		"duplicate-plugin":       []byte(`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/app","plugins":[{"name":"alpha","directory":"/a"},{"name":"zeta","directory":"/z"},{"name":"alpha","directory":"/other"}]}]}`),
		"unknown-field":          []byte(strings.Replace(valid, `"schema":`, `"extra":true,"schema":`, 1)),
		"field-case":             []byte(strings.Replace(valid, `"schema":`, `"Schema":`, 1)),
		"invalid-path":           []byte(strings.Replace(valid, `"/build"`, `"relative"`, 1)),
		"lone-high-surrogate":    []byte(strings.Replace(valid, `"/build"`, `"/build/\ud800"`, 1)),
		"lone-low-surrogate":     []byte(strings.Replace(valid, `"/build"`, `"/build/\udc00"`, 1)),
		"invalid-surrogate-pair": []byte(strings.Replace(valid, `"/build"`, `"/build/\ud800\u0061"`, 1)),
		"invalid-utf8":           bytes.Replace([]byte(valid), []byte("/build"), []byte{'/', 0xff}, 1),
		"trailing-data":          []byte(valid + ` {}`),
		"size-limit":             []byte(strings.Repeat(" ", MaxRecordBytes) + valid),
		"plugin-limit":           []byte(`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/app","plugins":[` + strings.Repeat(`{"name":"alpha","directory":"/build"},`, 64) + `{"name":"zeta","directory":"/build"}]}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSettings(body); !errors.Is(err, ErrRecord) {
				t.Fatal("invalid settings accepted", err)
			}
		})
	}
}

// full_only: false
func TestSettingsDecodeReasonsAndTokenLocations(t *testing.T) {
	for _, tc := range []struct {
		body, reason string
		location     *SettingsLocation
	}{
		{`{
  "unexpected":true,"schema":"enkv/plugin-settings/v1","applications":[]}`, "unknown-field", &SettingsLocation{Byte: 4, Line: 2, Column: 3, Precision: "exact"}},
		{`{"schema":"enkv/plugin-settings/v1","schema":"enkv/plugin-settings/v1","applications":[]}`, "duplicate-key", &SettingsLocation{Byte: 36, Line: 1, Column: 37, Precision: "exact"}},
		{`{`, "invalid-json", nil},
		{`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/a","plugins":[]},{"directory":"/a","plugins":[]}]}`, "duplicate-application", nil},
		{`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/a","plugins":[{"name":"a","directory":"/a"},{"name":"a","directory":"/b"}]}]}`, "duplicate-plugin", nil},
		{`{"schema":"enkv/plugin-settings/v1","applications":null}`, "invalid-value", nil},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			_, err := DecodeSettings([]byte(tc.body))
			var failure *SettingsError
			if !errors.As(err, &failure) || !errors.Is(err, ErrRecord) || failure.Reason != tc.reason {
				t.Fatal("safe reason lost", err, failure)
			}
			if tc.location != nil && !reflect.DeepEqual(failure.Location, tc.location) {
				t.Fatal("fault token origin changed", failure.Location, tc.location)
			}
		})
	}
	for _, tc := range []struct{ path, want string }{{`/build/\ud83d\ude00`, "/build/😀"}, {`/build/\ufffd`, "/build/�"}, {"/build/�", "/build/�"}, {`/build/\\ud800`, `/build/\ud800`}} {
		body := []byte(`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"/app","plugins":[{"name":"alpha","directory":"` + tc.path + `"}]}]}`)
		got, err := DecodeSettings(body)
		if err != nil || got.Applications[0].Plugins[0].Directory != tc.want {
			t.Fatal("valid Unicode spelling refused", tc.path, got, err)
		}
	}
}
