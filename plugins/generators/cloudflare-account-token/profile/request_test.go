package profile

import (
	"encoding/hex"
	"testing"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
)

// full_only: false
func TestHTTPRequestCommitmentUsesExactTargetAndBody(t *testing.T) {
	account := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	target := [32]byte([]byte("abcdef0123456789abcdef0123456789"))
	// Python hashlib/struct independently framed action, path, content type and
	// body with big-endian u32 lengths, then the labeled preimage and its length.
	for _, tc := range []struct {
		name, body, digest string
		action             uint8
		target             [32]byte
	}{
		{"create", `{"name":"token"}`, "1331b5ff2ecfcbe06290f4c80c8ab1fe57c82524b6749b73742db338f10fb9d1", provider.ActionCreate, [32]byte{}},
		{"delete", "", "8f7f9a7620f059266d42934ca060e0db8e1e0725b5d9b8cbbcbdbd9e7868c05f", provider.ActionDelete, target},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := HTTPRequestDigest(tc.action, account, tc.target, []byte(tc.body))
			if hex.EncodeToString(got[:]) != tc.digest {
				t.Fatal("request commitment differs from independent vector")
			}
		})
	}
	for _, tc := range []struct {
		name            string
		action          uint8
		account, target [32]byte
		body            []byte
	}{
		{"invalid account", provider.ActionCreate, [32]byte{}, [32]byte{}, []byte(`{}`)},
		{"create target", provider.ActionCreate, account, target, []byte(`{}`)},
		{"absent delete target", provider.ActionDelete, account, [32]byte{}, nil},
		{"delete body", provider.ActionDelete, account, target, []byte(`{}`)},
		{"empty create body", provider.ActionCreate, account, [32]byte{}, nil},
		{"oversized create body", provider.ActionCreate, account, [32]byte{}, make([]byte, provider.CloudflareMaxRequestBytes+1)},
		{"unknown action", 255, account, target, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if HTTPRequestDigest(tc.action, tc.account, tc.target, tc.body) != [32]byte{} {
				t.Fatal("invalid request received a commitment")
			}
		})
	}
}
