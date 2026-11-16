package execution

import (
	"enkv.sh/sdk/artifact"
	"os"
	"testing"
)

// full_only: false
func TestImplementationRequiresDeclaredConfigAndFormat(t *testing.T) {
	body, err := os.ReadFile("../cmd/enkv-manifest-generic-json/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewImplementation(body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"config", "format"} {
		t.Run(field, func(t *testing.T) {
			descriptor, err := artifact.DecodeDescriptor(body)
			if err != nil {
				t.Fatal(err)
			}
			if field == "config" {
				descriptor.Manifest.ConfigContractID = "other/config"
			} else {
				descriptor.Manifest.FormatContractID = "other/format"
			}
			changed, err := artifact.EncodeDescriptor(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewImplementation(changed); err == nil {
				t.Fatal("unsupported semantic contract accepted")
			}
		})
	}
}
