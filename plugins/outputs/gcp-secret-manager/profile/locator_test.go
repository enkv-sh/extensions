package profile

import (
	protocol "enkv.sh/sdk/protocols/output"
	"strings"
	"testing"
)

// full_only: false
func TestDeriveAndResolveNamedLatestVersion(t *testing.T) {
	d, err := Normalize([]byte(`{"project_number":"123456789012"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TOKEN", "Enkv_output-1", strings.Repeat("A", 255)} {
		for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
			target, err := Derive(d, name, encoding)
			parent := "projects/123456789012/secrets/" + name
			if err != nil || target.CanonicalTarget != parent || target.ConsumerLocator != parent+"/versions/latest" || target.LocatorRequiresCreation {
				t.Fatal("named consumer", err)
			}
			for _, resource := range []string{"", parent, parent + "/versions/42"} {
				locator, err := ResolveConsumerLocator(target, resource)
				if err != nil || locator != parent+"/versions/latest" {
					t.Fatal("static locator drift", err)
				}
			}
		}
	}
	for _, number := range []string{"", "0", "01", "+1", "-1", "project-id", "9223372036854775808"} {
		if _, err := Normalize([]byte(`{"project_number":"` + number + `"}`)); err == nil {
			t.Fatal("noncanonical project accepted", number)
		}
	}
	for _, name := range []string{"", "bad/name", "bad name", strings.Repeat("A", 256)} {
		if _, err := Derive(d, name, protocol.EncodingRaw); err == nil {
			t.Fatal("invalid name accepted", name)
		}
	}
}
