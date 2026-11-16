package artifact

import (
	"bytes"
	"encoding/json"
	"testing"
)

// full_only: false
func TestFamilyArtifactDeclarationsCanonicalJSON(t *testing.T) {
	for _, role := range []string{"generator", "output", "manifest-generator"} {
		m := fixtureBoundMetadata(codecMetadata(), authorDescriptor(role))
		body, err := EncodeMetadata(m)
		if err != nil {
			t.Fatal(role, err)
		}
		decoded, err := DecodeMetadata(body)
		if err != nil {
			t.Fatal(role, err)
		}
		descriptor, err := decoded.Descriptor()
		if err != nil || descriptor.Role != role || descriptor.Name != "private-local-inventory" {
			t.Fatal("declaration changed", role, err)
		}
		for _, old := range []string{`"profile_kind"`, `"cloudflare"`, `"capability_bits"`, `"permission_contract_id"`} {
			if bytes.Contains(body, []byte(old)) {
				t.Fatal("provider-shaped family field retained", old)
			}
		}
		var fields familyFacts
		if json.Unmarshal(m.Family.Facts, &fields) != nil {
			t.Fatal("invalid family JSON")
		}
		fields.ExecutorID = Digest{99}
		bad := m
		bad.Family = &Family{Schema: FamilySchema, Facts: nil, Dependency: m.Family.Dependency}
		bad.Family.Facts, _ = json.Marshal(fields)
		if _, err := EncodeMetadata(bad); err == nil {
			t.Fatal("changed measured identity accepted")
		}
	}
}
