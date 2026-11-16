package consumer

import (
	"strings"
	"testing"
)

// full_only: false
func TestConsumerRejectsDuplicateAndMalformedFields(t *testing.T) {
	for _, text := range []string{"", `x="y"`, "[app.manifest]\nformat=unquoted\n", "[app.manifest]\nformat=\"example/ini-reference/v1\"\nformat=\"other\"\n", "[app.manifest]\nformat=\"other\"\n"} {
		if _, err := Read(strings.NewReader(text)); err == nil {
			t.Fatal("malformed document accepted")
		}
	}
}
