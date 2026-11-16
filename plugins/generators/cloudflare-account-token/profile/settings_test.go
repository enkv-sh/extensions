package profile_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

const cloudflareSource = `{"expires_on":"2025-01-01T00:00:00Z","request_ip":{"not_in":["2001:db8::/32"],"in":["192.0.2.0/24"]},"policies":[{"resources":[{"id":"23456789abcdef0123456789abcdef01","kind":"zone"},{"kind":"account","id":"0123456789abcdef0123456789abcdef"}],"permission_groups":["123456789abcdef0123456789abcdef0"],"effect":"allow"}],"name":"edge-\"token\\one","account":"0123456789abcdef0123456789abcdef","not_before":"2024-01-01T00:00:00Z"}`

// Independently specified binary schema 1: ASCII account, length-prefixed name,
// one allow policy, sorted permission/resource rows, two network rows, and UTC
// seconds 1704067200 and 1735689600. This literal uses no production encoder.
const cloudflareSourceIntent = "000130313233343536373839616263646566303132333435363738396162636465660000000f656467652d22746f6b656e5c6f6e65000101000131323334353637383961626364656630313233343536373839616263646566300002013031323334353637383961626364656630313233343536373839616263646566023233343536373839616263646566303132333435363738396162636465663031000104000000000000000000000000c00002001800010620010db800000000000000000000000020010000000065920080010000000067748580"

// full_only: false
func TestCloudflareSourceCanonicalIntent(t *testing.T) {
	want, err := hex.DecodeString(cloudflareSourceIntent)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := profile.Normalize([]byte(cloudflareSource), profile.ProductionOrigin)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := profile.ParseCanonical(normalized, profile.ProductionOrigin)
	if err != nil {
		t.Fatal(err)
	}
	body, err := profile.EncodeControls(parsed)
	if err != nil || !bytes.Equal(body, want) || string(parsed.Account[:]) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("complete canonical controls differ", err)
	}
	second, err := profile.Normalize(normalized.Settings, profile.ProductionOrigin)
	if err != nil || !reflect.DeepEqual(normalized, second) {
		t.Fatal("canonical settings are not stable")
	}

}

// full_only: false
func TestCloudflareSourceRefusesInvalidIntent(t *testing.T) {
	cases := map[string]string{
		"null time":            strings.Replace(cloudflareSource, `"not_before":"2024-01-01T00:00:00Z"`, `"not_before":null`, 1),
		"empty time":           strings.Replace(cloudflareSource, `"not_before":"2024-01-01T00:00:00Z"`, `"not_before":""`, 1),
		"null condition":       strings.Replace(cloudflareSource, `"request_ip":{"not_in":["2001:db8::/32"],"in":["192.0.2.0/24"]}`, `"request_ip":null`, 1),
		"null prefix list":     strings.Replace(cloudflareSource, `["192.0.2.0/24"]`, `null`, 1),
		"duplicate field":      strings.Replace(cloudflareSource, `"name":`, `"name":"first","name":`, 1),
		"uppercase tag":        strings.Replace(cloudflareSource, `"account":"0123456789abcdef0123456789abcdef"`, `"account":"0123456789Abcdef0123456789abcdef"`, 1),
		"account mismatch":     strings.Replace(cloudflareSource, `"account":"0123456789abcdef0123456789abcdef"`, `"account":"1123456789abcdef0123456789abcdef"`, 1),
		"empty name":           strings.Replace(cloudflareSource, `"name":"edge-\"token\\one"`, `"name":""`, 1),
		"control in name":      strings.Replace(cloudflareSource, `"name":"edge-\"token\\one"`, `"name":"bad\u007f"`, 1),
		"duplicate permission": strings.Replace(cloudflareSource, `"permission_groups":["123456789abcdef0123456789abcdef0"]`, `"permission_groups":["123456789abcdef0123456789abcdef0","123456789abcdef0123456789abcdef0"]`, 1),
		"host bits":            strings.Replace(cloudflareSource, "192.0.2.0/24", "192.0.2.1/24", 1),
		"noncanonical prefix":  strings.Replace(cloudflareSource, "2001:db8::/32", "2001:0db8::/32", 1),
		"mapped prefix":        strings.Replace(cloudflareSource, "2001:db8::/32", "::ffff:192.0.2.0/120", 1),
		"duplicate prefix":     strings.Replace(cloudflareSource, `["192.0.2.0/24"]`, `["192.0.2.0/24","192.0.2.0/24"]`, 1),
		"fractional time":      strings.Replace(cloudflareSource, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00.1Z", 1),
		"invalid date":         strings.Replace(cloudflareSource, "2024-01-01T00:00:00Z", "2024-02-30T00:00:00Z", 1),
		"reversed time":        strings.Replace(cloudflareSource, "2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1),
		"unknown field":        strings.Replace(cloudflareSource, `"name":`, `"credential":"hidden","name":`, 1),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if source == cloudflareSource {
				t.Fatal("damage did not change source")
			}
			if _, err := profile.Normalize([]byte(source), profile.ProductionOrigin); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
}

func cloudflareCollectionSource(policies, permissions, resources, prefixes int, excess string) string {
	var out strings.Builder
	out.WriteString(`{"account":"0123456789abcdef0123456789abcdef","name":"x","policies":[`)
	for i := range policies {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(`{"effect":"allow","permission_groups":[`)
		for j := range permissions {
			if j > 0 {
				out.WriteByte(',')
			}
			fmt.Fprintf(&out, `"%032x"`, 1+i*permissions+j)
		}
		if excess == "permissions" {
			out.WriteString(",false")
		}
		out.WriteString(`],"resources":[`)
		for j := range resources {
			if j > 0 {
				out.WriteByte(',')
			}
			fmt.Fprintf(&out, `{"kind":"zone","id":"%032x"}`, j+1)
		}
		if excess == "resources" {
			out.WriteString(",false")
		}
		out.WriteString("]}")
	}
	if excess == "policies" {
		out.WriteString(",false")
	}
	out.WriteString(`],"request_ip":{"in":[`)
	for i := range prefixes {
		if i > 0 {
			out.WriteByte(',')
		}
		fmt.Fprintf(&out, `"192.0.2.%d/32"`, i)
	}
	if excess == "prefixes" {
		out.WriteString(",false")
	}
	out.WriteString("]}}")
	return out.String()
}

// full_only: false
func TestCloudflareSourceCollectionBounds(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		policies, permissions, resources, prefixes int
	}{
		{"policies", 32, 1, 1, 1}, {"permissions", 1, 64, 1, 1}, {"resources", 1, 1, 256, 1}, {"prefixes", 1, 1, 1, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := cloudflareCollectionSource(tc.policies, tc.permissions, tc.resources, tc.prefixes, "")
			intent, err := profile.Normalize([]byte(source), profile.ProductionOrigin)
			if err != nil {
				t.Fatal("exact count refused", err)
			}
			controls, err := profile.ParseCanonical(intent, profile.ProductionOrigin)
			if err != nil {
				t.Fatal(err)
			}
			body, err := profile.EncodeControls(controls)
			if err != nil || len(body) != 47+tc.policies*(5+32*tc.permissions+33*tc.resources)+18*tc.prefixes {
				t.Fatal("complete count framing differs", err)
			}
			excess := cloudflareCollectionSource(tc.policies, tc.permissions, tc.resources, tc.prefixes, tc.name)
			if _, err := profile.Normalize([]byte(excess), profile.ProductionOrigin); err == nil {
				t.Fatal("first excess element accepted")
			}
		})
	}
	// The simultaneous provider count maxima fit private controls but exceed the
	// common ordinary-settings byte envelope. Neither limit increases for JSON.
	source := cloudflareCollectionSource(32, 64, 256, 128, "")
	if _, err := profile.Normalize([]byte(source), profile.ProductionOrigin); err == nil {
		t.Fatal("oversized settings accepted")
	}
}

// full_only: false
func TestProviderControlsPreserveCompleteCollectionMaximum(t *testing.T) {
	account := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, account[:]...)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, 'x')
	body = binary.BigEndian.AppendUint16(body, 32)
	for i := range 32 {
		body = append(body, 1)
		body = binary.BigEndian.AppendUint16(body, 64)
		for j := range 64 {
			body = append(body, fmt.Sprintf("%032x", 1+i*64+j)...)
		}
		body = binary.BigEndian.AppendUint16(body, 256)
		for j := range 256 {
			body = append(body, 2)
			body = append(body, fmt.Sprintf("%032x", j+1)...)
		}
	}
	body = binary.BigEndian.AppendUint16(body, 128)
	for i := range 128 {
		body = append(body, 4)
		body = append(body, make([]byte, 12)...)
		body = append(body, 192, 0, 2, byte(i), 32)
	}
	body = append(body, 0, 0, 0, 0)
	if len(body) != 47+32*(5+64*32+256*33)+128*18 {
		t.Fatal("independent complete length differs")
	}
	controls, err := profile.ParseIntent(body, account)
	if err != nil || controls.PolicyCount() != 32 {
		t.Fatal("complete provider controls refused", err)
	}
	encoded, err := profile.EncodeControls(controls)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatal("complete controls changed", err)
	}
}
