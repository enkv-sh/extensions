package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func policyActionRequest(t *testing.T) (PolicyActionRequest, Policy) {
	t.Helper()
	command, policy := testCommand(t)
	target := command.Target
	target.Capabilities |= CapabilityWriteSetsPolicy
	return PolicyActionRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, DomainID: command.DomainID, DescriptorID: command.DescriptorID, PolicyDigest: command.PolicyDigest, PolicyContractID: policy.ContractID, Target: target}, policy
}

// full_only: false
func TestPolicyActionRequestExactBytesAndOptionalEvidence(t *testing.T) {
	request, _ := policyActionRequest(t)
	for _, present := range []bool{false, true} {
		request.HasPreviousPolicyDigest = present
		if present {
			request.PreviousPolicyDigest = testID(23)
		} else {
			request.PreviousPolicyDigest = ID{}
		}
		body, err := EncodePolicyActionRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		wantPrefix := []byte{0, 1, 0, 0, 3, 187, 44, 195, 216, 0}
		if !bytes.Equal(body[:10], wantPrefix) {
			t.Fatalf("request header %x", body[:10])
		}
		if !bytes.Equal(body[10:42], request.DomainID[:]) || !bytes.Equal(body[42:74], request.DescriptorID[:]) || !bytes.Equal(body[74:106], request.PreviousPolicyDigest[:]) || !bytes.Equal(body[106:138], request.PolicyDigest[:]) || body[138] != byte(map[bool]int{false: 0, true: 1}[present]) {
			t.Fatal("request field order changed")
		}
		decoded, err := DecodePolicyActionRequest(body)
		if err != nil || !reflect.DeepEqual(decoded, request) {
			t.Fatal("request did not round trip", err)
		}
		for _, mutation := range []func([]byte){func(b []byte) { b[138] = 2 }, func(b []byte) { b[138] ^= 1 }} {
			damaged := bytes.Clone(body)
			mutation(damaged)
			if _, err := DecodePolicyActionRequest(damaged); err == nil {
				t.Fatal("noncanonical presence accepted")
			}
		}
		if _, err := DecodePolicyActionRequest(append(bytes.Clone(body), 0)); err == nil {
			t.Fatal("trailing byte accepted")
		}
		if _, err := DecodePolicyActionRequest(body[:len(body)-1]); err == nil {
			t.Fatal("truncated request accepted")
		}
	}
	request.HasPreviousPolicyDigest = false
	if _, err := EncodePolicyActionRequest(request); err == nil {
		t.Fatal("absent evidence retained a digest")
	}
	request.PreviousPolicyDigest = ID{}
	for name, change := range map[string]func(*PolicyActionRequest){
		"schema":           func(v *PolicyActionRequest) { v.Schema = 2 },
		"domain":           func(v *PolicyActionRequest) { v.DomainID = ID{} },
		"descriptor":       func(v *PolicyActionRequest) { v.DescriptorID = ID{} },
		"current-digest":   func(v *PolicyActionRequest) { v.PolicyDigest = ID{} },
		"current-contract": func(v *PolicyActionRequest) { v.PolicyContractID = "" },
		"absent-deadline":  func(v *PolicyActionRequest) { v.DeadlineUnixMillis = 0 },
		"excess-deadline":  func(v *PolicyActionRequest) { v.DeadlineUnixMillis = uint64(1) << 63 },
	} {
		t.Run(name, func(t *testing.T) {
			damaged := request
			change(&damaged)
			if _, err := EncodePolicyActionRequest(damaged); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

// full_only: false
func TestPolicyActionExactMaximumRequestAndPolicyFrame(t *testing.T) {
	request, _ := policyActionRequest(t)
	request.PolicyContractID = strings.Repeat("p", 256)
	request.Target = Target{ServiceContractID: strings.Repeat("s", 256), TargetContractID: strings.Repeat("t", 256), CanonicalTarget: strings.Repeat("c", 1024), ConsumerLocator: strings.Repeat("l", 1024), TargetData: bytes.Repeat([]byte{7}, 4096), PayloadEncoding: EncodingRaw, Capabilities: 255, CreateValueBounds: PayloadBounds{Maximum: 65536}, WriteValueBounds: PayloadBounds{Maximum: 65536}}
	policy := Policy{ContractID: request.PolicyContractID, Data: bytes.Repeat([]byte{9}, 524546)}
	var err error
	request.PolicyDigest, err = PolicyDigest(request.DomainID, policy)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodePolicyActionRequest(request)
	if err != nil || len(body) != 7094 || MaximumPolicyActionRequestBytes != 7094 || ValidatePolicyActionPolicy(request, policy) != nil {
		t.Fatal("maximum public request", len(body), err)
	}
	// Independent vectors: Python struct.pack encoded this fixed request and
	// policy preimage; hashlib.sha256 supplied the digests without Go encoders.
	if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != "b5aad358ac6dfded7dced7e1e6ab0a9a4a7ed777c3b79411203fc8aca1d91af5" {
		t.Fatalf("maximum request digest=%x", got)
	}
	if hex.EncodeToString(request.PolicyDigest[:]) != "2cbbab259b4095a6d4fe01469fd06f27e792e19b075adb58f480d7c6a7f626f6" {
		t.Fatalf("maximum policy digest=%x", request.PolicyDigest)
	}
	if _, err := DecodePolicyActionRequest(body); err != nil {
		t.Fatal(err)
	}
	request.Target.TargetData = append(request.Target.TargetData, 7)
	if _, err := EncodePolicyActionRequest(request); err == nil {
		t.Fatal("first excess target accepted")
	}
	if _, err := DecodePolicyActionRequest(append(body, 0)); err == nil {
		t.Fatal("first excess request accepted")
	}
	request.Target.TargetData = request.Target.TargetData[:4096]
	policy.Data = append(policy.Data, 9)
	if ValidatePolicyActionPolicy(request, policy) == nil {
		t.Fatal("first excess policy accepted")
	}
}

// full_only: false
func TestPolicyActionResponseBindsBothFramesAndClosedActions(t *testing.T) {
	request, policy := policyActionRequest(t)
	body, err := EncodePolicyActionRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	checkID := testID(29)
	preimage := append([]byte("ENKV/OUTPUT/PUBLIC-REQUEST/v1\x00"), checkID[:]...)
	preimage = append(preimage, 19)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
	preimage = append(preimage, body...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy.Data)))
	preimage = append(preimage, policy.Data...)
	digest := sha256.Sum256(preimage)
	for _, action := range []Action{ActionWriteValue, ActionUpdatePolicy} {
		result := PolicyActionResult{Schema: 1, RequestDigest: digest, Accepted: true, Action: action}
		encoded, err := EncodePolicyActionResult(result)
		if err != nil || len(encoded) != 36 || MaximumPolicyActionResultBytes != 36 || encoded[34] != 1 || encoded[35] != byte(action) {
			t.Fatal("closed result framing", err)
		}
		decoded, err := DecodePolicyActionResult(encoded)
		if err != nil || decoded != result || ValidatePolicyActionResponse(checkID, request, policy, result) != nil {
			t.Fatal("valid action refused", err)
		}
		if ValidatePolicyActionResponse(testID(30), request, policy, result) == nil {
			t.Fatal("wrong correlation accepted")
		}
		changed := policy
		changed.Data = append(bytes.Clone(policy.Data), 0)
		if ValidatePolicyActionResponse(checkID, request, changed, result) == nil {
			t.Fatal("changed policy bytes accepted")
		}
		changed = policy
		changed.ContractID += "/other"
		if ValidatePolicyActionResponse(checkID, request, changed, result) == nil {
			t.Fatal("changed policy contract accepted")
		}
		changedRequest := request
		changedRequest.PolicyDigest = testID(31)
		if ValidatePolicyActionResponse(checkID, changedRequest, policy, result) == nil {
			t.Fatal("wrong current digest accepted")
		}
		if _, err := DecodePolicyActionResult(append(encoded, 0)); err == nil {
			t.Fatal("trailing result accepted")
		}
		if _, err := DecodePolicyActionResult(encoded[:35]); err == nil {
			t.Fatal("truncated result accepted")
		}
		damaged := bytes.Clone(encoded)
		damaged[34] = 2
		if _, err := DecodePolicyActionResult(damaged); err == nil {
			t.Fatal("noncanonical acceptance byte accepted")
		}
		changedRequest = request
		changedRequest.HasPreviousPolicyDigest = true
		changedRequest.PreviousPolicyDigest = testID(32)
		if ValidatePolicyActionResponse(checkID, changedRequest, policy, result) == nil {
			t.Fatal("different previous evidence accepted")
		}
	}
	for _, action := range []Action{0, ActionCreateEmpty, ActionCreateWithValue, ActionDeleteOwned, ActionDeleteReservedSlot, 99} {
		if _, err := EncodePolicyActionResult(PolicyActionResult{Schema: 1, RequestDigest: digest, Accepted: true, Action: action}); err == nil {
			t.Fatalf("unsupported action %d accepted", action)
		}
	}
	refused := PolicyActionResult{Schema: 1, RequestDigest: digest}
	if ValidatePolicyActionResponse(checkID, request, policy, refused) != nil {
		t.Fatal("canonical refusal rejected")
	}
	refused.Action = ActionUpdatePolicy
	if _, err := EncodePolicyActionResult(refused); err == nil {
		t.Fatal("refusal retained action")
	}
	result := PolicyActionResult{Schema: 1, RequestDigest: digest, Accepted: true, Action: ActionWriteValue}
	request.Target.Capabilities &^= CapabilityWriteSetsPolicy
	if ValidatePolicyActionResult(request, result) == nil {
		t.Fatal("write without policy effect accepted")
	}
	result.Action = ActionUpdatePolicy
	request.Target.Capabilities &^= CapabilityUpdatePolicy
	if ValidatePolicyActionResult(request, result) == nil {
		t.Fatal("unadvertised policy action accepted")
	}
}

// full_only: false
func TestPolicyActionExcessPolicyWithMatchingDigestIsRefused(t *testing.T) {
	request, policy := policyActionRequest(t)
	policy.Data = bytes.Repeat([]byte{9}, 524547)
	preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), request.DomainID[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy.ContractID)))
	preimage = append(preimage, policy.ContractID...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy.Data)))
	preimage = append(preimage, policy.Data...)
	request.PolicyDigest = sha256.Sum256(preimage)
	if !request.Valid() || request.PolicyContractID != policy.ContractID {
		t.Fatal("invalid request hides policy size refusal")
	}
	if ValidatePolicyActionPolicy(request, policy) == nil {
		t.Fatal("first excess policy with matching digest accepted")
	}
}
