package output

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestActionCapabilitiesRetainPolicyApplicationFacts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value ActionCapabilities
		valid bool
	}{
		{"separate_policy_action", (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy), true},
		{"create_empty_sets_policy", CapabilityCreateEmpty | 64, true},
		{"create_with_value_sets_policy", CapabilityCreateWithValue | 64, true},
		{"write_sets_policy", CapabilityWriteValue | 128, true},
		{"both_set_policy", (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy) | 192, true},
		{"create_fact_without_action", 64, false},
		{"create_fact_with_write_only", CapabilityWriteValue | 64, false},
		{"write_fact_without_action", 128, false},
		{"write_fact_with_create_only", CapabilityCreateWithValue | 128, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.value.Valid(); got != tc.valid {
				t.Fatalf("capabilities %08b validity = %t, want %t", tc.value, got, tc.valid)
			}
		})
	}
}

// full_only: false
func TestCapabilitiesRejectInvalidActionsWithoutPolicy(t *testing.T) {
	for _, actions := range [][]Action{nil, {ActionCreateEmpty, ActionCreateWithValue, ActionWriteValue, ActionUpdatePolicy, ActionDeleteOwned, ActionDeleteReservedSlot}, {ActionWriteValue, ActionWriteValue}} {
		value, err := Capabilities(actions...)
		var want ActionCapabilities
		switch len(actions) {
		case 0:
			want = 0
		case 2:
			want = CapabilityWriteValue
		default:
			want = 63
		}
		if err != nil || value != want {
			t.Fatal("valid dynamic action capabilities changed", err)
		}
	}
	for _, invalid := range []Action{0, 7, 8, 255} {
		for _, actions := range [][]Action{{invalid, ActionWriteValue, ActionCreateEmpty}, {ActionWriteValue, invalid, ActionCreateEmpty}, {ActionWriteValue, ActionCreateEmpty, invalid}} {
			value, err := Capabilities(actions...)
			if !errors.Is(err, ErrProtocol) || value != 0 || (value | CapabilityWriteValue).WriteSetsPolicy() || !strings.Contains(err.Error(), "actions") {
				t.Fatal("invalid action produced capability or policy facts")
			}
		}
	}
}

// full_only: false
func TestPolicyCapabilityFactsKeepTheSixActionSet(t *testing.T) {
	base := (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy)
	combined := base | CapabilityCreateSetsPolicy | CapabilityWriteSetsPolicy
	if CapabilityCreateSetsPolicy != 64 || CapabilityWriteSetsPolicy != 128 || base.CreateSetsPolicy() || base.WriteSetsPolicy() ||
		!combined.CreateSetsPolicy() || !combined.WriteSetsPolicy() || !combined.Valid() || !ActionCapabilities(255).Valid() {
		t.Fatal("policy capability bits changed or were lost")
	}
	for action := ActionCreateEmpty; action <= ActionDeleteReservedSlot; action++ {
		if base.Has(action) != combined.Has(action) {
			t.Fatal("policy fact changed the supported action set", action)
		}
	}
	for _, action := range []Action{0, 7, 8, 255} {
		value, err := Capabilities(action)
		if combined.Has(action) || !errors.Is(err, ErrProtocol) || value != 0 {
			t.Fatal("policy capability became a family action", action)
		}
	}
}

// full_only: false
func TestPolicyCapabilityFactsUseExistingWireByte(t *testing.T) {
	capabilities := (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy) | CapabilityCreateSetsPolicy | CapabilityWriteSetsPolicy
	destination := Destination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: []byte(`{}`), Capabilities: capabilities}
	body, err := EncodeDestination(destination)
	if err != nil || body[len(body)-1] != 206 {
		t.Fatal("destination lost the policy capability byte", err)
	}
	decodedDestination, err := DecodeDestination(body)
	if err != nil || decodedDestination.Capabilities != capabilities {
		t.Fatal("destination policy capabilities did not round trip", err)
	}
	destination.Capabilities = (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy)
	withoutFacts, err := EncodeDestination(destination)
	if err != nil || len(body) != len(withoutFacts) || !bytes.Equal(body[:len(body)-1], withoutFacts[:len(withoutFacts)-1]) {
		t.Fatal("policy facts changed destination framing", err)
	}
	target := testTarget()
	target.Capabilities = capabilities
	body, err = EncodeTarget(target)
	if err != nil || body[len(body)-18] != 206 {
		t.Fatal("target lost the policy capability byte", err)
	}
	decodedTarget, err := DecodeTarget(body)
	if err != nil || decodedTarget.Capabilities != capabilities {
		t.Fatal("target policy capabilities did not round trip", err)
	}
	target.Capabilities = (CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy)
	withoutFacts, err = EncodeTarget(target)
	if err != nil || len(body) != len(withoutFacts) || !bytes.Equal(body[:len(body)-18], withoutFacts[:len(withoutFacts)-18]) || !bytes.Equal(body[len(body)-17:], withoutFacts[len(withoutFacts)-17:]) {
		t.Fatal("policy facts changed target framing", err)
	}
}

// full_only: false
func TestTargetValueBoundsIndependentBytes(t *testing.T) {
	target := Target{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "c", ConsumerLocator: "l", TargetData: []byte{0, 255}, PayloadEncoding: EncodingRaw,
		Capabilities: (CapabilityCreateWithValue | CapabilityWriteValue), CreateValueBounds: PayloadBounds{Minimum: 1, Maximum: 32}, WriteValueBounds: PayloadBounds{Minimum: 3, Maximum: 65536}}
	// Four one-byte blob32 strings, a two-byte blob32, encoding/action/locator
	// bytes, then create minimum/maximum and write minimum/maximum as u32.
	want, err := hex.DecodeString("000000017300000001740000000163000000016c0000000200ff01060000000001000000200000000300010000")
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeTarget(target)
	if err != nil || !bytes.Equal(got, want) || len(got) != 45 {
		t.Fatalf("target bytes = %x, want %x: %v", got, want, err)
	}
	decoded, err := DecodeTarget(want)
	if err != nil || !reflect.DeepEqual(decoded, target) {
		t.Fatal("target bounds did not round trip", err)
	}
	for _, damaged := range [][]byte{want[:len(want)-1], append(bytes.Clone(want), 0)} {
		if _, err := DecodeTarget(damaged); err == nil {
			t.Fatal("incomplete or trailing bounds accepted")
		}
	}
}

// full_only: false
func TestTargetValueBoundsFollowAdvertisedActions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Target)
		valid  bool
	}{
		{"different_action_intervals", func(v *Target) {
			v.CreateValueBounds = PayloadBounds{Minimum: 1, Maximum: 32}
			v.WriteValueBounds = PayloadBounds{Minimum: 4, Maximum: 65536}
		}, true},
		{"empty_only", func(v *Target) { v.CreateValueBounds = PayloadBounds{}; v.WriteValueBounds = PayloadBounds{} }, true},
		{"absent_actions_zero", func(v *Target) {
			v.Capabilities = CapabilityDeleteOwned
			v.CreateValueBounds = PayloadBounds{}
			v.WriteValueBounds = PayloadBounds{}
		}, true},
		{"absent_create_nonzero", func(v *Target) { v.Capabilities = CapabilityWriteValue; v.WriteValueBounds = PayloadBounds{} }, false},
		{"absent_write_nonzero", func(v *Target) {
			v.Capabilities = CapabilityCreateWithValue
			v.CreateValueBounds = PayloadBounds{}
		}, false},
		{"reversed_create", func(v *Target) { v.CreateValueBounds = PayloadBounds{Minimum: 2, Maximum: 1} }, false},
		{"reversed_write", func(v *Target) { v.WriteValueBounds = PayloadBounds{Minimum: 2, Maximum: 1} }, false},
		{"excess_create", func(v *Target) { v.CreateValueBounds = PayloadBounds{Maximum: 65537} }, false},
		{"excess_write", func(v *Target) { v.WriteValueBounds = PayloadBounds{Maximum: 65537} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := testTarget()
			tc.change(&target)
			if target.Valid() != tc.valid {
				t.Fatalf("target validity = %t, want %t", target.Valid(), tc.valid)
			}
		})
	}
	for _, target := range []Target{{CreateValueBounds: PayloadBounds{Maximum: 1}}, {WriteValueBounds: PayloadBounds{Maximum: 1}}} {
		if _, err := EncodeInterpretResult(InterpretResult{Schema: 1, RequestDigest: testID(1), Target: target}); err == nil {
			t.Fatal("refusal carried value bounds")
		}
	}
}
