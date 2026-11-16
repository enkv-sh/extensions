package cloudflare

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

func testTag(value byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = "0123456789abcdef"[int(value+byte(i))%16]
	}
	return out
}

func testIntent(t *testing.T) ([]byte, [32]byte, string) {
	t.Helper()
	account := testTag(0)
	permission := testTag(1)
	zone := testTag(2)
	name := []byte("edge-\"token\\one")
	var body []byte
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, account[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(name)))
	body = append(body, name...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, profile.EffectAllow)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, permission[:]...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, profile.ResourceAccount)
	body = append(body, account[:]...)
	body = append(body, profile.ResourceZone)
	body = append(body, zone[:]...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 4)
	body = append(body, make([]byte, 12)...)
	body = append(body, 192, 0, 2, 0, 24)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 6)
	body = append(body, 0x20, 0x01, 0x0d, 0xb8)
	body = append(body, make([]byte, 12)...)
	body = append(body, 32)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint64(body, 1704067200)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint64(body, 1735689600)
	want := `{"name":"edge-\"token\\one","policies":[{"effect":"allow","permission_groups":[{"id":"` + string(permission[:]) + `"}],"resources":{"com.cloudflare.api.account.` + string(account[:]) + `":"*","com.cloudflare.api.account.zone.` + string(zone[:]) + `":"*"}}],"condition":{"request.ip":{"in":["192.0.2.0/24"],"not_in":["2001:db8::/32"]}},"not_before":"2024-01-01T00:00:00Z","expires_on":"2025-01-01T00:00:00Z"}`
	return body, account, want
}

// full_only: false
func TestParseIntentBuildsExactCanonicalRequest(t *testing.T) {
	body, account, want := testIntent(t)
	intent, err := profile.ParseIntent(body, account)
	if err != nil {
		t.Fatal(err)
	}
	got, err := intent.RequestJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("request differs\n got: %s\nwant: %s", got, want)
	}
	if got := hex.EncodeToString(intent.Digest[:]); got != "4a016c4d412aee55a988f9cc9058e3257755a1f6c395ba02c2019950cfedcb14" {
		t.Fatalf("intent digest = %s", got)
	}
}

// full_only: false
func TestParseIntentRejectsNoncanonicalAndInvalidValues(t *testing.T) {
	body, account, _ := testIntent(t)
	tests := map[string]func([]byte) []byte{
		"trailing":         func(v []byte) []byte { return append(v, 0) },
		"account mismatch": func(v []byte) []byte { v[2] ^= 1; return v },
		"invalid UTF-8":    func(v []byte) []byte { v[38] = 0xff; return v },
		"host bits":        func(v []byte) []byte { v[len(v)-29] = 1; return v },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := mutate(bytes.Clone(body))
			if _, err := profile.ParseIntent(changed, account); err == nil {
				t.Fatal("accepted invalid intent")
			}
		})
	}
}
