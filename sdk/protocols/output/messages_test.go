package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func testID(b byte) ID {
	var id ID
	for i := range id {
		id[i] = b
	}
	return id
}
func testTarget() Target {
	return Target{ServiceContractID: "private-service/v1", TargetContractID: "private-key/v1", CanonicalTarget: "local/account/key", ConsumerLocator: "local/account/key", TargetData: []byte{1, 2, 3}, PayloadEncoding: EncodingRaw, Capabilities: (CapabilityCreateEmpty | CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy | CapabilityDeleteOwned | CapabilityDeleteReservedSlot), CreateValueBounds: PayloadBounds{Maximum: MaximumPayloadBytes}, WriteValueBounds: PayloadBounds{Maximum: MaximumPayloadBytes}}
}
func testCommand(t *testing.T) (Command, Policy) {
	t.Helper()
	p := Policy{ContractID: "private-policy/v1", Data: []byte("opaque\x00policy")}
	digest, err := PolicyDigest(testID(1), p)
	if err != nil {
		t.Fatal(err)
	}
	return Command{Schema: 1, Action: ActionWriteValue, DomainID: testID(1), OperationID: testID(2), AttemptID: testID(3), CoordinateID: testID(4), ProjectionCommitment: testID(5), DispatchContextDigest: testID(6), RequestContractDigest: testID(7), ResponseContractDigest: testID(8), DescriptorID: testID(9), CredentialRouteID: testID(10), PolicyDigest: digest, BindingIncarnationID: testID(11), EntryIncarnationID: testID(12), TargetRowDigest: testID(13), BirthTargetRowDigest: testID(14), OwnedBirthAttemptID: testID(15), ValueBasisDigest: testID(16), DeadlineUnixMillis: 4102444800000, PayloadLengthMode: LengthExact, PayloadLength: 5, BindingDestinationID: "private", OwnedInstance: "owned", ConditionalToken: "token", PolicyContractID: p.ContractID, Target: testTarget()}, p
}

// full_only: false
func TestCommandAndOpaquePolicyIndependentEncoding(t *testing.T) {
	c, p := testCommand(t)
	got, err := EncodeCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 1, 3}
	for _, n := range []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, c.PolicyDigest[:]...)
	for _, n := range []byte{11, 12, 13, 14, 15, 0, 0, 16} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = binary.BigEndian.AppendUint64(want, 4102444800000)
	want = append(want, 1, 0, 0, 0, 5)
	for _, v := range []string{"private", "owned", "token", "private-policy/v1", "private-service/v1", "private-key/v1", "local/account/key", "local/account/key"} {
		want = binary.BigEndian.AppendUint32(want, uint32(len(v)))
		want = append(want, v...)
	}
	want = append(want, 0, 0, 0, 3, 1, 2, 3, 1, 63, 0,
		0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("command bytes differ\ngot=%x\nwant=%x", got, want)
	}
	decoded, err := DecodeCommand(want)
	if err != nil || !reflect.DeepEqual(decoded, c) {
		t.Fatal("command round trip", err)
	}
	policy, err := EncodePolicy(p)
	if err != nil || !bytes.Equal(policy, []byte("opaque\x00policy")) {
		t.Fatal("policy frame is not exact opaque bytes", err)
	}
	preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), bytes.Repeat([]byte{1}, 32)...)
	preimage = binary.BigEndian.AppendUint32(preimage, 17)
	preimage = append(preimage, "private-policy/v1"...)
	preimage = binary.BigEndian.AppendUint32(preimage, 13)
	preimage = append(preimage, "opaque\x00policy"...)
	if c.PolicyDigest != sha256.Sum256(preimage) {
		t.Fatal("policy identity has wrong contract/data preimage")
	}
	for _, bad := range [][]byte{got[:len(got)-1], append(bytes.Clone(got), 0)} {
		if _, err := DecodeCommand(bad); err == nil {
			t.Fatal("damaged command accepted")
		}
	}
}

// full_only: false
func TestCommandActionOwnershipAndBirthRules(t *testing.T) {
	c, p := testCommand(t)
	for _, change := range []func(*Command){func(v *Command) { v.BirthTargetRowDigest = ID{} }, func(v *Command) { v.OwnedBirthAttemptID = ID{} }, func(v *Command) { v.OwnedInstance = "" }, func(v *Command) { v.PayloadLengthMode = LengthAbsent }, func(v *Command) { v.DescriptorID = ID{} }, func(v *Command) { v.Target.Capabilities = 0 }} {
		bad := c
		change(&bad)
		if _, err := EncodeCommand(bad); err == nil {
			t.Fatal("invalid action ownership accepted")
		}
	}
	input := []byte("ENKV/PUBLICATION/OWNED-INSTANCE/v2\x00")
	for _, n := range []byte{1, 4, 11, 12, 14, 15} {
		input = append(input, bytes.Repeat([]byte{n}, 32)...)
	}
	input = append(input, 0, 0, 0, 5)
	input = append(input, "owned"...)
	if c.OwnedInstanceDigest() != sha256.Sum256(input) {
		t.Fatal("owned instance is not bound to birth row")
	}
	c.TargetRowDigest = testID(99)
	if c.OwnedInstanceDigest() != sha256.Sum256(input) {
		t.Fatal("target edit replaced original birth binding")
	}
	c.Action = ActionDeleteOwned
	c.ValueBasisDigest = ID{}
	c.PayloadLengthMode = LengthAbsent
	c.PayloadLength = 0
	c.PolicyDigest = ID{}
	c.PolicyContractID = ""
	if _, err := EncodeCommand(c); err != nil || ValidatePolicy(c, Policy{}) != nil {
		t.Fatal("absent deletion policy refused", err)
	}
	if ValidatePolicy(c, p) == nil {
		t.Fatal("deletion accepted policy data")
	}
	c.Action = ActionUpdatePolicy
	if _, err := EncodeCommand(c); err == nil {
		t.Fatal("policy update accepted absence")
	}
}

// full_only: false
func TestGenericDestinationTargetAndResultMaximumWidths(t *testing.T) {
	settings := []byte(`"` + strings.Repeat("x", 65534) + `"`)
	d := Destination{ConfigContractID: strings.Repeat("c", 256), ServiceContractID: strings.Repeat("s", 256), CanonicalSettings: settings, Policy: Policy{ContractID: strings.Repeat("p", 256), Data: bytes.Repeat([]byte{255}, 524546)}, Capabilities: CapabilityCreateEmpty | CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy | CapabilityDeleteOwned | CapabilityDeleteReservedSlot}
	body, err := EncodeDestination(d)
	if err != nil || len(body) != 590871 {
		t.Fatal("complete destination bound", len(body), err)
	}
	decoded, err := DecodeDestination(body)
	if err != nil || !reflect.DeepEqual(decoded, d) {
		t.Fatal("maximum destination did not round trip", err)
	}
	d.Policy.Data = append(d.Policy.Data, 0)
	if _, err := EncodeDestination(d); err == nil {
		t.Fatal("first excess policy byte accepted")
	}
	d.Policy.Data = d.Policy.Data[:524546]
	d.CanonicalSettings = append(settings, ' ')
	if _, err := EncodeDestination(d); err == nil {
		t.Fatal("first excess settings byte accepted")
	}
	c, _ := testCommand(t)
	c.Target = Target{ServiceContractID: strings.Repeat("s", 256), TargetContractID: strings.Repeat("t", 256), CanonicalTarget: strings.Repeat("c", 1024), ConsumerLocator: strings.Repeat("l", 1024), TargetData: bytes.Repeat([]byte{1}, 4096), PayloadEncoding: EncodingRaw, Capabilities: CapabilityCreateEmpty | CapabilityCreateWithValue | CapabilityWriteValue | CapabilityUpdatePolicy | CapabilityDeleteOwned | CapabilityDeleteReservedSlot, CreateValueBounds: PayloadBounds{Maximum: MaximumPayloadBytes}, WriteValueBounds: PayloadBounds{Maximum: MaximumPayloadBytes}}
	c.BindingDestinationID = strings.Repeat("d", 256)
	c.OwnedInstance = strings.Repeat("o", 1024)
	c.ConditionalToken = strings.Repeat("i", 1024)
	c.PolicyContractID = strings.Repeat("p", 256)
	b, err := EncodeCommand(c)
	if err != nil || len(b) != 9895 {
		t.Fatal("complete command bound", len(b), err)
	}
	c.Target.TargetData = append(c.Target.TargetData, 1)
	if _, err := EncodeCommand(c); err == nil {
		t.Fatal("first excess target data accepted")
	}
	c, _ = testCommand(t)
	r := c.NewResult()
	r.Entry, r.Class, r.NormalizedStatus = EntryMayHaveEntered, ClassAcknowledged, 200
	r.SafeRequestID = strings.Repeat("a", 1024)
	r.SafeResourceID = strings.Repeat("b", 1024)
	r.ConsumerLocator = strings.Repeat("c", 1024)
	b, err = EncodeResult(r)
	if err != nil || len(b) != 3314 {
		t.Fatal("complete result bound", len(b), err)
	}
	r.ConsumerLocator += "x"
	if _, err := EncodeResult(r); err == nil {
		t.Fatal("first excess locator accepted")
	}
}

// full_only: false
func TestQualifiedCreationLocatorAndResultIdentity(t *testing.T) {
	c, _ := testCommand(t)
	c.Action = ActionCreateWithValue
	c.OwnedInstance = ""
	c.OwnedBirthAttemptID = ID{}
	c.BirthTargetRowDigest = ID{}
	r := c.NewResult()
	r.Entry, r.Class, r.NormalizedStatus = EntryMayHaveEntered, ClassAcknowledged, 201
	r.SafeResourceID = "created-resource"
	r.ConsumerLocator = c.Target.ConsumerLocator
	if ValidateResult(c, r) != nil {
		t.Fatal("static creation locator refused")
	}
	r.ConsumerLocator = "different"
	if ValidateResult(c, r) == nil {
		t.Fatal("mismatched static locator accepted")
	}
	c.Target.ConsumerLocator = ""
	c.Target.LocatorRequiresCreation = true
	if ValidateResult(c, r) != nil {
		t.Fatal("assigned creation locator refused")
	}
	r.ConsumerLocator = ""
	if ValidateResult(c, r) == nil {
		t.Fatal("missing creation locator accepted")
	}
	r = c.NewResult()
	r.Entry, r.Class = EntryMayHaveEntered, ClassUnproved
	if ValidateResult(c, r) != nil {
		t.Fatal("unknown creation refused")
	}
	r.ConsumerLocator = "unproved"
	if ValidateResult(c, r) == nil {
		t.Fatal("unknown result assigned a locator")
	}
	r = c.NewResult()
	r.Entry, r.Class = EntryMayHaveEntered, ClassUnproved
	r.AttemptID = testID(77)
	if ValidateResult(c, r) == nil {
		t.Fatal("wrong result correlation accepted")
	}
}

// full_only: false
func TestAcknowledgedCreationRequiresResourceIdentity(t *testing.T) {
	for _, action := range []Action{ActionCreateEmpty, ActionCreateWithValue} {
		for _, assigned := range []bool{false, true} {
			c, _ := testCommand(t)
			c.Action, c.OwnedInstance = action, ""
			c.OwnedBirthAttemptID, c.BirthTargetRowDigest = ID{}, ID{}
			if action == ActionCreateEmpty {
				c.ValueBasisDigest, c.PayloadLengthMode, c.PayloadLength = ID{}, LengthAbsent, 0
			}
			if assigned {
				c.Target.ConsumerLocator, c.Target.LocatorRequiresCreation = "", true
			}
			r := c.NewResult()
			r.Entry, r.Class, r.NormalizedStatus = EntryMayHaveEntered, ClassAcknowledged, 201
			r.ConsumerLocator = "locator"
			if !assigned {
				r.ConsumerLocator = c.Target.ConsumerLocator
			}
			if !c.Valid() || !r.Valid() {
				t.Fatal("fixture failed before action-correlated resource check")
			}
			if ValidateResult(c, r) == nil {
				t.Errorf("create action %d assigned=%t accepted empty resource identity", action, assigned)
			}
			r.SafeResourceID = strings.Repeat("r", 1024)
			if err := ValidateResult(c, r); err != nil {
				t.Fatal("maximum resource identity refused", err)
			}
			wrong := r
			wrong.AttemptID = testID(77)
			if ValidateResult(c, wrong) == nil {
				t.Fatal("acknowledged create accepted wrong attempt")
			}
			if !assigned {
				wrong = r
				wrong.ConsumerLocator = "another/static/locator"
				if ValidateResult(c, wrong) == nil {
					t.Fatal("acknowledged create accepted wrong static locator")
				}
			}
			r.SafeResourceID += "r"
			if ValidateResult(c, r) == nil {
				t.Fatal("one-over resource identity accepted")
			}
			r.SafeResourceID = string([]byte{255})
			if ValidateResult(c, r) == nil {
				t.Fatal("invalid UTF-8 resource identity accepted")
			}
			r.SafeResourceID, r.ConsumerLocator = "", ""
			r.Class, r.NormalizedStatus = ClassQualifiedNoEffect, 0
			if err := ValidateResult(c, r); err != nil {
				t.Fatal("no-effect create requires unnecessary resource identity", err)
			}
		}
	}
	for _, action := range []Action{ActionWriteValue, ActionUpdatePolicy, ActionDeleteOwned, ActionDeleteReservedSlot} {
		c, _ := testCommand(t)
		c.Action = action
		if action != ActionWriteValue {
			c.ValueBasisDigest, c.PayloadLengthMode, c.PayloadLength = ID{}, LengthAbsent, 0
		}
		if action == ActionDeleteOwned || action == ActionDeleteReservedSlot {
			c.PolicyDigest, c.PolicyContractID = ID{}, ""
		}
		if action == ActionDeleteReservedSlot {
			c.OwnedBirthAttemptID, c.BirthTargetRowDigest, c.OwnedInstance = ID{}, ID{}, ""
			c.UncertainCreateAttemptID, c.ExclusiveNamespaceDigest = testID(20), testID(21)
		}
		r := c.NewResult()
		r.Entry, r.Class, r.NormalizedStatus = EntryMayHaveEntered, ClassAcknowledged, 204
		if err := ValidateResult(c, r); err != nil {
			t.Fatal("non-create acknowledgement requires unnecessary resource identity", action, err)
		}
	}
}

// full_only: false
func TestOutputDomainsKeepDistinctTypesAndExactBytes(t *testing.T) {
	command := reflect.TypeFor[Command]()
	result := reflect.TypeFor[Result]()
	action, _ := command.FieldByName("Action")
	entry, _ := result.FieldByName("Entry")
	class, _ := result.FieldByName("Class")
	if action.Type == entry.Type || action.Type == class.Type || entry.Type == class.Type {
		t.Fatal("action, entry state and outcome class share a domain")
	}
	if action.Type.Kind() != reflect.Uint8 || entry.Type.Kind() != reflect.Uint8 || class.Type.Kind() != reflect.Uint8 {
		t.Fatal("wire domain width changed")
	}

	values := []byte{byte(ActionCreateEmpty), byte(ActionCreateWithValue), byte(ActionWriteValue), byte(ActionUpdatePolicy), byte(ActionDeleteOwned), byte(ActionDeleteReservedSlot), byte(EntryNotEntered), byte(EntryMayHaveEntered), byte(ClassUnproved), byte(ClassAcknowledged), byte(ClassQualifiedNoEffect)}
	if !bytes.Equal(values, []byte{1, 2, 3, 4, 5, 6, 1, 2, 0, 1, 2}) {
		t.Fatal("wire numeric assignments changed")
	}
	c, _ := testCommand(t)
	body, err := EncodeCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []byte{0, 7, 255} {
		bad := bytes.Clone(body)
		bad[2] = invalid
		if _, err := DecodeCommand(bad); err == nil {
			t.Fatal("invalid action byte accepted", invalid)
		}
	}
	r := c.NewResult()
	r.Entry, r.Class = EntryMayHaveEntered, ClassUnproved
	body, err = EncodeResult(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []byte{0, 3, 255} {
		bad := bytes.Clone(body)
		bad[226] = invalid
		if _, err := DecodeResult(bad); err == nil {
			t.Fatal("invalid entry byte accepted", invalid)
		}
	}
	for _, invalid := range []byte{3, 255} {
		bad := bytes.Clone(body)
		bad[227] = invalid
		if _, err := DecodeResult(bad); err == nil {
			t.Fatal("invalid class byte accepted", invalid)
		}
	}
}
