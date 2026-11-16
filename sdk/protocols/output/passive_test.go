package output

import (
	"bytes"
	"testing"
)

// full_only: false
func TestPublicCanonicalBytesBoundsAndRefusalFacts(t *testing.T) {
	d := Destination{ConfigContractID: "private-config/v1", ServiceContractID: "private-service/v1", CanonicalSettings: []byte(`"` + string(bytes.Repeat([]byte{'x'}, 65534)) + `"`), Capabilities: CapabilityCreateEmpty | CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy | CapabilityDeleteOwned | CapabilityDeleteReservedSlot, Policy: Policy{ContractID: "private-policy", Data: bytes.Repeat([]byte{255}, 524546)}}
	request := CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Destination: d}
	body, err := EncodeCanonicalRequest(request)
	if err != nil || len(body) > MaximumPublicRequestBytes {
		t.Fatal("maximum canonical request", err)
	}
	decoded, err := DecodeCanonicalRequest(body)
	if err != nil || !bytes.Equal(decoded.Destination.CanonicalSettings, d.CanonicalSettings) || !bytes.Equal(decoded.Destination.Policy.Data, d.Policy.Data) {
		t.Fatal("canonical bytes changed", err)
	}
	d.CanonicalSettings = append(d.CanonicalSettings, ' ')
	request.Destination = d
	if _, err := EncodeCanonicalRequest(request); err == nil {
		t.Fatal("first excess canonical settings accepted")
	}
	if _, err := EncodeNormalizeResult(NormalizeResult{Schema: 1, RequestDigest: testID(1), Destination: Destination{ConfigContractID: "refused-facts"}}); err == nil {
		t.Fatal("refusal carried accepted destination")
	}
	if _, err := EncodeInterpretResult(InterpretResult{Schema: 1, RequestDigest: testID(1), Target: testTarget()}); err == nil {
		t.Fatal("refusal carried accepted target")
	}
}

// full_only: false
func TestActionCheckKeepsMetadataAndUnknownLengthDistinct(t *testing.T) {
	c, _ := testCommand(t)
	c.PolicyDigest = ID{}
	c.PolicyContractID = ""
	request := c.ActionCheck()
	request.PayloadLengthMode = LengthAbsent
	request.PayloadLength = 0
	request.Target.WriteValueBounds = PayloadBounds{Minimum: 10, Maximum: 65536}
	if !request.Valid() || ValidatePayloadBounds(request, PayloadBounds{Minimum: 10, Maximum: 65536}) != nil {
		t.Fatal("unknown selected value rejected provider bounds")
	}
	request.PayloadLengthMode = LengthExact
	request.PayloadLength = 9
	if ValidatePayloadBounds(request, PayloadBounds{Minimum: 10, Maximum: 65536}) == nil {
		t.Fatal("short selected value accepted")
	}
	c.Action = ActionDeleteOwned
	c.PayloadLengthMode = LengthAbsent
	c.PayloadLength = 0
	c.ValueBasisDigest = ID{}
	request = c.ActionCheck()
	if !request.Valid() || ValidateActionCheckResult(request, ActionCheckResult{Schema: 1, RequestDigest: testID(1), Accepted: true, PayloadBounds: PayloadBounds{Maximum: 1}}) == nil {
		t.Fatal("metadata accepted value bounds")
	}
	request.PayloadLengthMode = LengthExact
	if request.Valid() {
		t.Fatal("metadata accepted an exact value-length arm")
	}
}

// full_only: false
func TestValueActionBoundsApplyBeforePayloadAndRepeatExactly(t *testing.T) {
	command, _ := testCommand(t)
	command.Target.CreateValueBounds = PayloadBounds{Minimum: 9, Maximum: 12}
	command.Target.WriteValueBounds = PayloadBounds{Minimum: 2, Maximum: 8}
	for _, length := range []uint32{1, 2, 8, 9} {
		command.PayloadLength = length
		valid := length == 2 || length == 8
		if command.Valid() != valid || command.ActionCheck().Valid() != valid {
			t.Fatal("write interval did not constrain exact length", length)
		}
	}
	command.Action = ActionCreateWithValue
	command.OwnedInstance = ""
	command.OwnedBirthAttemptID = ID{}
	command.BirthTargetRowDigest = ID{}
	command.PayloadLength = 10
	if !command.Valid() || !command.ActionCheck().Valid() {
		t.Fatal("distinct create interval refused")
	}
	command.PayloadLength = 8
	if command.Valid() || command.ActionCheck().Valid() {
		t.Fatal("write interval authorized create length")
	}
	request := command.ActionCheck()
	request.PayloadLengthMode, request.PayloadLength = LengthAbsent, 0
	if !request.Valid() {
		t.Fatal("unknown length refused declared bounds")
	}
	for _, bounds := range []PayloadBounds{{Minimum: 9, Maximum: 12}, {Minimum: 10, Maximum: 12}, {Minimum: 9, Maximum: 11}, {Minimum: 8, Maximum: 12}} {
		err := ValidateActionCheckResult(request, ActionCheckResult{Schema: 1, RequestDigest: testID(1), Accepted: true, PayloadBounds: bounds})
		if (err == nil) != (bounds == (PayloadBounds{Minimum: 9, Maximum: 12})) {
			t.Fatal("action check did not repeat exact normalized bounds", bounds, err)
		}
	}
	command.Target.CreateValueBounds = PayloadBounds{}
	command.PayloadLength = 0
	if !command.Valid() || !command.ActionCheck().Valid() {
		t.Fatal("advertised empty-only action refused empty value")
	}
	command.PayloadLength = 1
	if command.Valid() || command.ActionCheck().Valid() {
		t.Fatal("empty-only action accepted nonempty value")
	}
	command.Action = ActionCreateEmpty
	command.PayloadLengthMode, command.PayloadLength = LengthAbsent, 0
	command.ValueBasisDigest = ID{}
	if !command.Valid() || ValidateActionCheckResult(command.ActionCheck(), ActionCheckResult{Schema: 1, RequestDigest: testID(1), Accepted: true}) != nil {
		t.Fatal("metadata action used an unscheduled value interval")
	}
}
