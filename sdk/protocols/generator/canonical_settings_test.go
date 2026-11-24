package generator

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// full_only: false
func TestCanonicalSettingsGrammarAcrossIntentAdmission(t *testing.T) {
	for _, tc := range canonicalSettingsCases() {
		t.Run(tc.name, func(t *testing.T) {
			v := testIntent(LifecycleNone)
			v.Settings = []byte(tc.text)
			// Fixed schema/config/lifecycle/resource framing and a blob32 settings field.
			body := []byte{0, 1}
			body = append(body, bytes.Repeat([]byte{1}, 32)...)
			body = append(body, LifecycleNone)
			body = append(body, make([]byte, 32)...)
			body = binary.BigEndian.AppendUint32(body, uint32(len(tc.text)))
			body = append(body, tc.text...)
			for name, check := range map[string]func(*testing.T) error{
				"encode": func(t *testing.T) error {
					got, err := EncodeIntent(v)
					if err == nil && !bytes.Equal(got, body) {
						t.Fatal("settings bytes changed")
					}
					return err
				},
				"decode": func(t *testing.T) error {
					got, err := DecodeIntent(body)
					if err == nil && !bytes.Equal(got.Settings, []byte(tc.text)) {
						t.Fatal("decoded settings changed")
					}
					return err
				},
				"digest": func(t *testing.T) error { _, err := IntentDigest(body); return err },
				"canonical_request": func(t *testing.T) error {
					_, err := CanonicalInputDigest(CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Purpose: CanonicalHistorical, Intent: body})
					return err
				},
				"normalize_response": func(t *testing.T) error {
					_, err := EncodeNormalizeResponse(NormalizeResponse{Schema: 1, InputDigest: repeatedID(4), Accepted: true, Intent: body})
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
		{"punctuation_within_string", `{"{":"[::]","nested":[{"q":"long\"quoted\"value"}]}`, true},
		{"escaped_quote_before_lone_surrogate", `"abc\"def\ud800"`, false},
		{"separate_object_keys", `[{"x":1},{"x":2}]`, true},
		{"maximum_depth", strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000), true},
	}
}
