package artifact

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestRecordDecodeDiagnosticsUseCanonicalFields(t *testing.T) {
	decoders := []struct {
		name, field string
		decode      func([]byte) error
	}{
		{"descriptor", "schema", func(b []byte) error { _, e := DecodeDescriptor(b); return e }},
		{"metadata", "schema", func(b []byte) error { _, e := DecodeMetadata(b); return e }},
		{"dependency", "role", func(b []byte) error {
			framed := binary.BigEndian.AppendUint16(nil, 3)
			framed = binary.BigEndian.AppendUint32(framed, uint32(len(b)))
			_, e := DecodeDependency(append(framed, b...))
			return e
		}},
		{"archive", "schema", func(b []byte) error { _, e := DecodeArchiveRecord(b); return e }},
		{"release", "schema", func(b []byte) error { _, e := DecodeReleaseIndex(b); return e }},
		{"marker", "schema", func(b []byte) error { _, e := DecodeBuildMarker(b); return e }},
		{"proof", "schema", func(b []byte) error { _, e := DecodeOfficialProof(b); return e }},
		{"settings", "schema", func(b []byte) error { _, e := DecodeSettings(b); return e }},
		{"selection", "schema", func(b []byte) error { _, e := DecodeSelectionRecord(b); return e }},
	}
	for _, decoder := range decoders {
		t.Run(decoder.name, func(t *testing.T) {
			for _, tc := range []struct{ name, body, path string }{
				{"variant", `{"` + strings.ToUpper(decoder.field) + `":"private-supplied-value"}`, "record." + decoder.field},
				{"unknown", `{"private-credential-key":"private-supplied-value"}`, "record"},
			} {
				t.Run(tc.name, func(t *testing.T) { assertSafeRecordError(t, decoder.decode([]byte(tc.body)), tc.path) })
			}
		})
	}
	for _, tc := range []struct{ name, old, replacement, path string }{
		{"pointer", `"replacement":null`, `"replacement":{"PATH":"private-supplied-value"}`, "record.resolved.replacement.path"},
		{"slice", `"build_options":[]`, `"build_options":[{"NAME":"private-supplied-value"}]`, "record.build_options.name"},
		{"family", `"schema":2`, `"SCHEMA":2`, "record.schema"},
		{"embedded", `"descriptor_id":`, `"DESCRIPTOR_ID":`, "record.descriptor_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := codecMetadata()
			if tc.name == "family" || tc.name == "embedded" {
				m.Family.Facts = bytes.Replace(m.Family.Facts, []byte(tc.old), []byte(tc.replacement), 1)
				_, err := m.ManifestFacts()
				assertSafeRecordError(t, err, tc.path)
			} else {
				body, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				_, err = DecodeMetadata(bytes.Replace(body, []byte(tc.old), []byte(tc.replacement), 1))
				assertSafeRecordError(t, err, tc.path)
			}
		})
	}
	for _, method := range []string{"encode", "decode"} {
		t.Run("family_"+method, func(t *testing.T) {
			m := codecMetadata()
			m.Family.Facts = bytes.Replace(m.Family.Facts, []byte(`"schema":2`), []byte(`"SCHEMA":2`), 1)
			var err error
			if method == "encode" {
				_, err = EncodeMetadata(m)
			} else {
				body, marshalErr := json.Marshal(m)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = DecodeMetadata(body)
			}
			assertSafeRecordError(t, err, "record.schema")
		})
	}
}

func assertSafeRecordError(t *testing.T, err error, path string) {
	t.Helper()
	if !errors.Is(err, ErrRecord) || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "SCHEMA") || strings.Contains(err.Error(), "DESCRIPTOR_ID") {
		t.Fatal("record error lost safe canonical diagnosis", err)
	}
}
