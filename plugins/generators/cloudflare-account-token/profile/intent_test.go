package profile_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

// The literal encodes schema 1, three 32-byte ASCII tags, the 15-byte name,
// one allow policy, two resources, two network prefixes and two Unix times.
// Independently calculated SHA-256 input is ENKV/GENERATOR/v1/intent, NUL,
// big-endian u32 length 216, then these bytes; no production encoder is used.
const intentHex = "000130313233343536373839616263646566303132333435363738396162636465660000000f656467652d22746f6b656e5c6f6e65000101000131323334353637383961626364656630313233343536373839616263646566300002013031323334353637383961626364656630313233343536373839616263646566023233343536373839616263646566303132333435363738396162636465663031000104000000000000000000000000c00002001800010620010db800000000000000000000000020010000000065920080010000000067748580"

const requestJSON = `{"name":"edge-\"token\\one","policies":[{"effect":"allow","permission_groups":[{"id":"123456789abcdef0123456789abcdef0"}],"resources":{"com.cloudflare.api.account.0123456789abcdef0123456789abcdef":"*","com.cloudflare.api.account.zone.23456789abcdef0123456789abcdef01":"*"}}],"condition":{"request.ip":{"in":["192.0.2.0/24"],"not_in":["2001:db8::/32"]}},"not_before":"2024-01-01T00:00:00Z","expires_on":"2025-01-01T00:00:00Z"}`

func intentFixture(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	body, err := hex.DecodeString(intentHex)
	if err != nil {
		t.Fatal(err)
	}
	var account [32]byte
	copy(account[:], "0123456789abcdef0123456789abcdef")
	return body, account
}

// full_only: false
func TestParseIntentPreservesCanonicalPublicMeaning(t *testing.T) {
	body, account := intentFixture(t)
	intent, err := profile.ParseIntent(body, account)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Account != account || string(intent.Name) != "edge-\"token\\one" || intent.NotBefore != "2024-01-01T00:00:00Z" || intent.ExpiresOn != "2025-01-01T00:00:00Z" {
		t.Fatal("public intent fields differ")
	}
	if got := hex.EncodeToString(intent.Digest[:]); got != "4a016c4d412aee55a988f9cc9058e3257755a1f6c395ba02c2019950cfedcb14" {
		t.Fatalf("intent digest = %s", got)
	}
	policy := bytes.Clone(body[55:158])
	if intent.PolicyCount() != 1 || !intent.MatchesPolicies([][]byte{policy}) || intent.MatchesPolicies(nil) {
		t.Fatal("complete policy rows differ")
	}
	policy[0] = 2
	if intent.MatchesPolicies([][]byte{policy}) {
		t.Fatal("different policy matched")
	}
	in, notIn := intent.IPConditions()
	if len(in) != 1 || len(notIn) != 1 || in[0] != "192.0.2.0/24" || notIn[0] != "2001:db8::/32" {
		t.Fatal("IP condition rows differ")
	}
	in[0], notIn[0] = "changed", "changed"
	in, notIn = intent.IPConditions()
	if in[0] != "192.0.2.0/24" || notIn[0] != "2001:db8::/32" {
		t.Fatal("returned condition mutation changed intent")
	}
	clear(body)
	request, err := intent.RequestJSON()
	if err != nil || string(request) != requestJSON {
		t.Fatalf("request differs after input release: %s, %v", request, err)
	}
	clear(request)
	request, err = intent.RequestJSON()
	if err != nil || string(request) != requestJSON {
		t.Fatalf("request differs after returned bytes change: %s, %v", request, err)
	}
}

// full_only: false
func TestParseIntentRejectsIncompleteAndNoncanonicalPublicInput(t *testing.T) {
	body, account := intentFixture(t)
	for length := 0; length < len(body); length++ {
		if _, err := profile.ParseIntent(body[:length], account); !errors.Is(err, profile.ErrProfile) {
			t.Fatalf("truncated length %d: %v", length, err)
		}
	}
	tests := map[string]func([]byte) []byte{
		"schema":               func(v []byte) []byte { v[1] = 2; return v },
		"account mismatch":     func(v []byte) []byte { v[2] = 'f'; return v },
		"invalid name Unicode": func(v []byte) []byte { v[38] = 0xff; return v },
		"name control":         func(v []byte) []byte { v[38] = '\n'; return v },
		"effect":               func(v []byte) []byte { v[55] = 3; return v },
		"policy count":         func(v []byte) []byte { binary.BigEndian.PutUint16(v[53:55], 33); return v },
		"permission count":     func(v []byte) []byte { binary.BigEndian.PutUint16(v[56:58], 65); return v },
		"permission tag":       func(v []byte) []byte { v[58] = 'G'; return v },
		"resource count":       func(v []byte) []byte { binary.BigEndian.PutUint16(v[90:92], 257); return v },
		"resource kind":        func(v []byte) []byte { v[92] = 4; return v },
		"resource account":     func(v []byte) []byte { v[93] = 'f'; return v },
		"prefix count":         func(v []byte) []byte { binary.BigEndian.PutUint16(v[158:160], 129); return v },
		"prefix family":        func(v []byte) []byte { v[160] = 5; return v },
		"IPv4 padding":         func(v []byte) []byte { v[161] = 1; return v },
		"IPv4 host bits":       func(v []byte) []byte { v[176] = 1; return v },
		"IPv4 mask":            func(v []byte) []byte { v[177] = 33; return v },
		"IPv6 host bits":       func(v []byte) []byte { v[196] = 1; return v },
		"IPv6 mask":            func(v []byte) []byte { v[197] = 129; return v },
		"time presence":        func(v []byte) []byte { v[198] = 2; return v },
		"time overflow":        func(v []byte) []byte { v[199] = 0xff; return v },
		"time order":           func(v []byte) []byte { copy(v[208:216], v[199:207]); return v },
		"trailing":             func(v []byte) []byte { return append(v, 0) },
		"duplicate policy": func(v []byte) []byte {
			binary.BigEndian.PutUint16(v[53:55], 2)
			return bytes.Join([][]byte{v[:158], v[55:158], v[158:]}, nil)
		},
		"duplicate permission": func(v []byte) []byte {
			binary.BigEndian.PutUint16(v[56:58], 2)
			return bytes.Join([][]byte{v[:90], v[58:90], v[90:]}, nil)
		},
		"duplicate resource": func(v []byte) []byte {
			binary.BigEndian.PutUint16(v[90:92], 3)
			return bytes.Join([][]byte{v[:125], v[92:125], v[125:]}, nil)
		},
		"duplicate prefix": func(v []byte) []byte {
			binary.BigEndian.PutUint16(v[158:160], 2)
			return bytes.Join([][]byte{v[:178], v[160:178], v[178:]}, nil)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := profile.ParseIntent(change(bytes.Clone(body)), account); !errors.Is(err, profile.ErrProfile) {
				t.Fatalf("invalid intent: %v", err)
			}
		})
	}
	for _, invalid := range [][32]byte{{}, [32]byte{'G'}} {
		if _, err := profile.ParseIntent(body, invalid); !errors.Is(err, profile.ErrProfile) {
			t.Fatalf("invalid account: %v", err)
		}
	}
}

// full_only: false
func TestParseIntentKeepsNameBoundaryAndAbsentConditionMeaning(t *testing.T) {
	body, account := intentFixture(t)
	for _, length := range []int{0, 120, 121} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			changed := bytes.Clone(body[:34])
			changed = binary.BigEndian.AppendUint32(changed, uint32(length))
			changed = append(changed, bytes.Repeat([]byte{'n'}, length)...)
			changed = append(changed, body[53:]...)
			_, err := profile.ParseIntent(changed, account)
			if (err == nil) != (length == 120) {
				t.Fatalf("name length %d: %v", length, err)
			}
		})
	}
	minimal := append(bytes.Clone(body[:158]), 0, 0, 0, 0, 0, 0)
	intent, err := profile.ParseIntent(minimal, account)
	if err != nil {
		t.Fatal(err)
	}
	request, err := intent.RequestJSON()
	if err != nil || bytes.Contains(request, []byte("condition")) || intent.NotBefore != "" || intent.ExpiresOn != "" {
		t.Fatalf("absent optional fields differ: %s, %v", request, err)
	}
}
