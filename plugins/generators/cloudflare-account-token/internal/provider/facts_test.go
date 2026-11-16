package provider

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func factsFixture() SafeFacts {
	id := func(value byte) ID {
		var result ID
		for i := range result {
			result[i] = value
		}
		return result
	}
	return SafeFacts{Schema: 1, Disposition: DispositionCompleteCreate, HTTPStatus: 200,
		Account: id(14), TokenPresent: 1, TokenID: id(16), TokenStatus: TokenStatusActive,
		EchoPresence: EchoName | EchoPolicies, RequestDigest: id(13), IntentDigest: id(17), MatchedControlsDigest: id(17), ErrorCodes: []uint32{}}
}

// full_only: false
func TestSafeFactsMaximumAndMalformedFields(t *testing.T) {
	facts := factsFixture()
	// Schema, disposition, reason, status; account; optional token; status,
	// echo mask; three digests; error count; three absent timestamps.
	literal := "0001010000c8" + strings.Repeat("0e", 32) + "01" + strings.Repeat("10", 32) +
		"010003" + strings.Repeat("0d", 32) + strings.Repeat("11", 64) + "00000000"
	want, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeFacts(facts)
	if err != nil || len(want) != 174 || !bytes.Equal(body, want) {
		t.Fatal("independent provider facts vector differs", len(body), err)
	}
	decoded, err := DecodeFacts(want)
	if err != nil || !reflect.DeepEqual(decoded, facts) {
		t.Fatal("independent provider facts vector did not decode exactly", err)
	}

	facts.Disposition, facts.Reason, facts.HTTPStatus = DispositionUnknown, ReasonIdentityConflict, 599
	facts.TokenStatus, facts.EchoPresence = TokenStatusExpired, EchoMask
	facts.ErrorCodes = make([]uint32, 16)
	facts.IssuedUTC = []byte("2026-09-16T01:02:03." + strings.Repeat("1", 43) + "Z")
	facts.ModifiedUTC, facts.LastUsedUTC = bytes.Clone(facts.IssuedUTC), bytes.Clone(facts.IssuedUTC)
	body, err = EncodeFacts(facts)
	// The 174-byte base includes each presence flag. Each present timestamp
	// adds its four-byte length and 64 bytes; sixteen errors add 64 bytes.
	const maximum = 174 + 16*4 + 3*(4+64)
	if err != nil || maximum != 442 || MaximumSafeFactsBody != maximum || len(body) != maximum {
		t.Fatal("safe facts exact maximum differs", len(body), err)
	}
	decoded, err = DecodeFacts(body)
	if err != nil || !reflect.DeepEqual(decoded, facts) {
		t.Fatal("maximum safe facts changed", err)
	}
	for cut := range len(body) {
		if _, err := DecodeFacts(body[:cut]); err == nil {
			t.Fatalf("safe facts truncation %d passed", cut)
		}
	}
	if _, err := DecodeFacts(append(bytes.Clone(body), 0)); !errors.Is(err, ErrCapacity) {
		t.Fatal("one excess safe facts byte passed", err)
	}
	if _, err := DecodeFacts(append(bytes.Clone(want), 0)); err == nil {
		t.Fatal("safe facts trailing byte passed")
	}

	for _, test := range []struct {
		name   string
		change func(*SafeFacts)
	}{
		{"schema", func(v *SafeFacts) { v.Schema = 2 }},
		{"disposition", func(v *SafeFacts) { v.Disposition = 5 }},
		{"reason", func(v *SafeFacts) { v.Reason = 11 }},
		{"http-status", func(v *SafeFacts) { v.HTTPStatus = 600 }},
		{"account", func(v *SafeFacts) { v.Account = ID{} }},
		{"request", func(v *SafeFacts) { v.RequestDigest = ID{} }},
		{"intent", func(v *SafeFacts) { v.IntentDigest = ID{} }},
		{"token-presence", func(v *SafeFacts) { v.TokenPresent = 2 }},
		{"absent-token-id", func(v *SafeFacts) { v.TokenPresent = 0 }},
		{"present-zero-token", func(v *SafeFacts) { v.TokenID = ID{} }},
		{"token-status", func(v *SafeFacts) { v.TokenStatus = 4 }},
		{"echo-mask", func(v *SafeFacts) { v.EchoPresence = 32 }},
		{"matched-controls", func(v *SafeFacts) { v.MatchedControlsDigest[0] ^= 1 }},
		{"error-count", func(v *SafeFacts) { v.ErrorCodes = make([]uint32, 17) }},
		{"timestamp-length", func(v *SafeFacts) { v.IssuedUTC = bytes.Repeat([]byte{'1'}, 65) }},
		{"timestamp-utf8", func(v *SafeFacts) { v.ModifiedUTC = []byte{0xff} }},
		{"timestamp-syntax", func(v *SafeFacts) { v.LastUsedUTC = []byte("yesterday") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := factsFixture()
			test.change(&invalid)
			if _, err := EncodeFacts(invalid); err == nil {
				t.Fatal("invalid provider facts passed")
			}
		})
	}
}

// full_only: false
func TestDecodedTimestampFieldsKeepAppendWithinOwnSpan(t *testing.T) {
	for _, count := range []int{2, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			facts := factsFixture()
			facts.IssuedUTC, facts.ModifiedUTC = []byte("2026-09-16T01:02:03Z"), []byte("2026-09-17T04:05:06Z")
			if count == 3 {
				facts.LastUsedUTC = []byte("2026-09-18T07:08:09Z")
			}
			wire, err := EncodeFacts(facts)
			if err != nil || len(wire) != 174+24*count {
				t.Fatal("timestamp fixture length differs", len(wire), err)
			}
			backing := bytes.Repeat([]byte{0xa5}, len(wire)+8)
			copy(backing, wire)
			decoded, err := DecodeFacts(backing[:len(wire)])
			if err != nil {
				t.Fatal(err)
			}
			fields := []struct {
				name   string
				body   []byte
				want   []byte
				offset int
			}{
				{"issued", decoded.IssuedUTC, facts.IssuedUTC, 176},
				{"modified", decoded.ModifiedUTC, facts.ModifiedUTC, 201},
				{"last-used", decoded.LastUsedUTC, facts.LastUsedUTC, 226},
			}
			before := bytes.Clone(backing)
			for _, field := range fields {
				if !bytes.Equal(field.body, field.want) || cap(field.body) != len(field.body) {
					t.Fatal("timestamp bytes or exact capacity changed", field.name)
				}
				appended := append(field.body, 0xd3)
				if len(appended) != len(field.want)+1 || !bytes.Equal(appended[:len(field.want)], field.want) || appended[len(field.want)] != 0xd3 || !bytes.Equal(backing, before) {
					t.Fatal("timestamp append changed its input or adjacent backing", field.name)
				}
				for _, adjacent := range fields {
					if !bytes.Equal(adjacent.body, adjacent.want) {
						t.Fatal("timestamp append changed an adjacent field", field.name, adjacent.name)
					}
				}
				if len(field.body) == 0 {
					continue
				}
				field.body[0] ^= 0x80
				want := bytes.Clone(before)
				want[field.offset] ^= 0x80
				if !bytes.Equal(backing, want) {
					t.Fatal("timestamp no longer borrows its independent wire span", field.name)
				}
				copy(backing, before)
			}
		})
	}
}

// full_only: false
func TestBearerLengthAndGrammarBoundary(t *testing.T) {
	for _, length := range []int{39, 40, 80, 81} {
		accepted := length == 40 || length == 80
		if ValidBearer(bytes.Repeat([]byte{'a'}, length)) != accepted {
			t.Fatal("bearer length boundary differs", length)
		}
	}
	for _, value := range []string{
		strings.Repeat("Az09_-", 7),
		"cfut_" + strings.Repeat("A", 35),
		"cfat_" + strings.Repeat("z", 75),
	} {
		if !ValidBearer([]byte(value)) {
			t.Fatal("supported bearer grammar refused")
		}
	}
	for _, invalid := range []byte{' ', '\n', '\t', '.', '+', '/', '=', 0, 0xff} {
		value := bytes.Repeat([]byte{'a'}, 40)
		value[20] = invalid
		if ValidBearer(value) {
			t.Fatal("invalid bearer byte passed", invalid)
		}
	}
}
