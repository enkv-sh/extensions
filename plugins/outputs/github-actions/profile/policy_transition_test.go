package profile

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	protocol "enkv.sh/sdk/protocols/output"
)

func fixedPolicyDigest(domain protocol.ID, contract string, data []byte) protocol.ID {
	preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domain[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(contract)))
	preimage = append(preimage, contract...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(data)))
	return sha256.Sum256(append(preimage, data...))
}

// full_only: false
func TestPolicyActionSelectionUsesPositiveKnownPolicyDigests(t *testing.T) {
	domain := protocol.ID{7}
	policies := map[string][]byte{
		"all":      {0, 1, 1, 0, 0},
		"private":  {0, 1, 2, 0, 0},
		"selected": {0, 1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 11},
	}
	for _, previous := range []string{"all", "private", "selected"} {
		for _, desired := range []string{"all", "private", "selected"} {
			if previous == desired {
				continue
			}
			t.Run(previous+"_to_"+desired, func(t *testing.T) {
				old := fixedPolicyDigest(domain, "github-actions/org-visibility/v1", policies[previous])
				got, err := SelectPolicyAction(domain, old, protocol.Policy{ContractID: "github-actions/org-visibility/v1", Data: policies[desired]})
				if err != nil || got != protocol.ActionWriteValue {
					t.Fatal("mode change did not select complete value write", got, err)
				}
			})
		}
	}
	selected := protocol.Policy{ContractID: "github-actions/org-visibility/v1", Data: policies["selected"]}
	for _, tc := range []struct {
		name  string
		prior protocol.ID
	}{
		{"absent", protocol.ID{}},
		{"selected_list", fixedPolicyDigest(domain, "github-actions/org-visibility/v1", []byte{0, 1, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12})},
		{"unknown", protocol.ID{90}},
		{"other_domain", fixedPolicyDigest(protocol.ID{8}, "github-actions/org-visibility/v1", policies["all"])},
		{"foreign_policy_contract", fixedPolicyDigest(domain, "private/org-policy/v2", policies["all"])},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectPolicyAction(domain, tc.prior, selected)
			if err != nil || got != protocol.ActionUpdatePolicy {
				t.Fatal("nonmatching evidence did not retain guarded metadata action", got, err)
			}
		})
	}
	for _, mode := range []string{"all", "private"} {
		for _, prior := range []protocol.ID{{}, {99}} {
			got, err := SelectPolicyAction(domain, prior, protocol.Policy{ContractID: "github-actions/org-visibility/v1", Data: policies[mode]})
			if err != nil || got != protocol.ActionWriteValue {
				t.Fatal("desired mode required unneeded prior evidence", got, err)
			}
		}
	}
	for _, policy := range []protocol.Policy{{}, {ContractID: "other-policy", Data: policies["all"]}, {ContractID: "github-actions/org-visibility/v1", Data: []byte{0, 1, 4, 0, 0}}} {
		if action, err := SelectPolicyAction(domain, protocol.ID{}, policy); err == nil || action != 0 {
			t.Fatal("invalid current policy accepted", action, err)
		}
	}
	if action, err := SelectPolicyAction(protocol.ID{}, protocol.ID{}, selected); err == nil || action != 0 {
		t.Fatal("absent domain accepted", action, err)
	}
}
