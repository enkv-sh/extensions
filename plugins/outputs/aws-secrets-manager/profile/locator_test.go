package profile

import (
	protocol "enkv.sh/sdk/protocols/output"
	"strings"
	"testing"
)

// full_only: false
func TestDeriveAndResolveExactAssignedARN(t *testing.T) {
	d, err := Normalize([]byte(`{"account":"123456789012","region":"us-east-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TOKEN", "name-AbCd12", strings.Repeat("A", 512)} {
		for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
			target, err := Derive(d, name, encoding)
			if err != nil || target.ConsumerLocator != "" || !target.LocatorRequiresCreation {
				t.Fatal("creation must supply assigned locator", err)
			}
			slot := "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name
			if target.CanonicalTarget != slot {
				t.Fatal("planned target drift")
			}
			for _, resource := range []string{"", slot, slot + "-AbCd12", "arn:aws:secretsmanager:us-east-1:111111111111:secret:" + name + "-AbCd12", slot + "-bad!12"} {
				locator, err := ResolveConsumerLocator(target, resource)
				valid := resource == slot+"-AbCd12"
				if (err == nil) != valid || valid && locator != resource+"?stage=AWSCURRENT" {
					t.Fatal("exact qualified resource relation", resource, locator, err)
				}
			}
		}
	}
	for _, raw := range []string{`{"account":"012","region":"us-east-1"}`, `{"account":"123456789012","region":"us-gov-west-1"}`, `{"account":"123456789012"}`, `{"account":"123456789012","unknown":"us-east-1"}`} {
		if _, err := Normalize([]byte(raw)); err == nil {
			t.Fatal("invalid destination accepted", raw)
		}
	}
	for _, name := range []string{"", "bad:name", "bad name", strings.Repeat("A", 513)} {
		if _, err := Derive(d, name, protocol.EncodingRaw); err == nil {
			t.Fatal("invalid name accepted", name)
		}
	}
}
