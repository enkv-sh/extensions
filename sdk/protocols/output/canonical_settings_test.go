package output

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// full_only: false
func TestCanonicalSettingsGrammarAcrossDestinationAdmission(t *testing.T) {
	for _, tc := range canonicalSettingsCases() {
		t.Run(tc.name, func(t *testing.T) {
			v := Destination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(tc.text)}
			// Three blob32 fields, absent policy contract/data, then capabilities.
			var body []byte
			for _, field := range []string{"c", "s", tc.text, "", ""} {
				body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
				body = append(body, field...)
			}
			body = append(body, 0)
			for name, check := range map[string]func(*testing.T) error{
				"encode": func(t *testing.T) error {
					got, err := EncodeDestination(v)
					if err == nil && !bytes.Equal(got, body) {
						t.Fatal("settings bytes changed")
					}
					return err
				},
				"decode": func(t *testing.T) error {
					got, err := DecodeDestination(body)
					if err == nil && !bytes.Equal(got.CanonicalSettings, []byte(tc.text)) {
						t.Fatal("decoded settings changed")
					}
					return err
				},
				"canonical_request": func(t *testing.T) error {
					_, err := EncodeCanonicalRequest(CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: v})
					return err
				},
				"normalize_result": func(t *testing.T) error {
					_, err := EncodeNormalizeResult(NormalizeResult{Schema: 1, RequestDigest: testID(4), Accepted: true, Destination: v})
					return err
				},
			} {
				t.Run(name, func(t *testing.T) {
					if err := check(t); (err == nil) != tc.valid {
						t.Fatalf("canonical admission validity = %t, want %t: %v", err == nil, tc.valid, err)
					}
				})
			}
		})
	}
}

func canonicalSettingsCases() []struct {
	name, text string
	valid      bool
} {
	return []struct {
		name, text string
		valid      bool
	}{
		{"duplicate", `{"x":1,"x":2}`, false},
		{"nested_duplicate", `{"outer":{"x":1,"x":2}}`, false},
		{"array_duplicate", `[{"x":1,"x":2}]`, false},
		{"escaped_key_collision", `{"x":1,"\u0078":2}`, false},
		{"high_surrogate", `"\ud800"`, false},
		{"low_surrogate", `"\udfff"`, false},
		{"reversed_surrogates", `"\udc00\ud800"`, false},
		{"surrogate_key", `{"\ud800":1}`, false},
		{"invalid_utf8", "\"\xff\"", false},
		{"scalar_number", `1.00e+09`, true},
		{"scalar_boolean", `true`, true},
		{"scalar_null", `null`, true},
		{"surrogate_pair", `{"\ud83d\ude00":"\ud83d\ude00"}`, true},
		{"escaped_spelling", ` { "z": "\u0078\/", "a": 1.00 } `, true},
		{"separate_object_keys", `[{"x":1},{"x":2}]`, true},
		{"maximum_depth", strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000), true},
	}
}
