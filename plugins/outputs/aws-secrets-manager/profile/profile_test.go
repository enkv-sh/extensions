package profile

import (
	"bytes"
	protocol "enkv.sh/sdk/protocols/output"
	"strings"
	"testing"
)

// full_only: false
func TestInterpretPublicTargetAndAbsentPolicy(t *testing.T) {
	d, err := Normalize([]byte(`{"account":"123456789012","region":"us-east-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.ConfigContractID != ConfigContractID || d.ServiceContractID != ServiceContractID || d.Policy.Present() || len(d.Policy.Data) != 0 || !bytes.Equal(d.CanonicalSettings, []byte(`{"account":"123456789012","region":"us-east-1"}`)) {
		t.Fatal("canonical destination facts", d)
	}
	for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
		target, err := Derive(d, "TOKEN", encoding)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseTarget(target)
		if err != nil || target.CanonicalTarget != "arn:aws:secretsmanager:us-east-1:123456789012:secret:TOKEN" || target.PayloadEncoding != encoding {
			t.Fatal("exact target meaning", target, err)
		}
	}
	for _, raw := range []string{"", `{}`, `null`, `{"unknown":"value"}`, `{"account":"123456789012","account":"123456789012","region":"us-east-1"}`} {
		if _, err := Normalize([]byte(raw)); err == nil {
			t.Fatalf("invalid settings accepted %q", raw)
		}
	}
}

// full_only: false
func TestInterpretIndependentPublicFieldRefusals(t *testing.T) {
	d, err := Normalize([]byte(`{"account":"123456789012","region":"us-east-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	target, err := Derive(d, "TOKEN", protocol.EncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*protocol.Target){
		func(v *protocol.Target) { v.ServiceContractID = "other" }, func(v *protocol.Target) { v.TargetContractID = "other" },
		func(v *protocol.Target) { v.CanonicalTarget = "wrong" }, func(v *protocol.Target) { v.ConsumerLocator = "wrong" },
		func(v *protocol.Target) { v.TargetData = []byte(`{"wrong":"data"}`) }, func(v *protocol.Target) { v.PayloadEncoding = 9 },
		func(v *protocol.Target) { v.Capabilities |= protocol.CapabilityUpdatePolicy }, func(v *protocol.Target) { v.WriteValueBounds.Maximum-- },
		func(v *protocol.Target) { v.CreateValueBounds.Maximum = 1 }, func(v *protocol.Target) { v.LocatorRequiresCreation = !v.LocatorRequiresCreation },
	} {
		bad := target
		change(&bad)
		_, err = ParseTarget(bad)
		if err == nil {
			t.Fatal("damaged target accepted", bad)
		}
	}
	for _, p := range []protocol.Policy{{ContractID: "cloud-iam", Data: []byte(`[]`)}, {ContractID: "cloud-iam", Data: []byte(`["principal"]`)}, {Data: []byte{1}}} {
		bad := d
		bad.Policy = p
		if ValidateDestination(bad) == nil {
			t.Fatal("plugin must not configure external IAM")
		}
	}
	if ValidateDestination(protocol.Destination{}) == nil {
		t.Fatal("missing canonical facts accepted")
	}
	for _, raw := range []string{strings.Repeat("x", 65537), `{"account":"012","region":"us-east-1"}`} {
		if _, err := Normalize([]byte(raw)); err == nil {
			t.Fatal("invalid enclosing settings accepted")
		}
	}
}
