package profile_test

import (
	"encoding/hex"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
	"testing"
)

// full_only: false
func TestSemanticsPreservesExactOriginBoundIDs(t *testing.T) {
	// Independent hashlib.sha256(domain + NUL + exact origin), no codec.
	for _, v := range []struct{ origin, config, resource string }{
		{"https://api.cloudflare.com/client/v4", "7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1", "4f641119f62b8d53fb92438deaf48da59535ee284a5cc3d0b4868af88c7564d8"},
		{"http://127.0.0.1:1234/client/v4", "13968841c7b9ba1b3e88adffe96b454bf2e17bb6bb5f5dc21c17315e0aadf42a", "cae775605297dff3c7aef299f3b809583d6d4c5b51d5b12fb8d217ce1a56454e"},
	} {
		config, resource := profile.ConfigContractID(v.origin), profile.ResourceContractID(v.origin)
		if hex.EncodeToString(config[:]) != v.config || hex.EncodeToString(resource[:]) != v.resource || config == resource {
			t.Fatal("origin-bound contracts differ")
		}
	}
}

// full_only: false
func TestCanonicalContractRejectsChangedOriginAndSettings(t *testing.T) {
	intent, err := profile.Normalize([]byte(`{"account":"0123456789abcdef0123456789abcdef","name":"token","policies":[{"effect":"allow","permission_groups":["123456789abcdef0123456789abcdef0"],"resources":[{"kind":"account","id":"0123456789abcdef0123456789abcdef"}]}]}`), profile.ProductionOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.ParseCanonical(intent, "http://127.0.0.1:1234/client/v4"); err == nil {
		t.Fatal("changed origin accepted")
	}
	intent.Settings = append([]byte(" "), intent.Settings...)
	if _, err := profile.ParseCanonical(intent, profile.ProductionOrigin); err == nil {
		t.Fatal("noncanonical settings accepted")
	}
}
