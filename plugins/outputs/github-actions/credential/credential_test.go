package credential

import (
	"bytes"
	"testing"

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestCredentialBoundsAndHeaderSyntax(t *testing.T) {
	for _, value := range [][]byte{[]byte("synthetic-token_0123456789"), bytes.Repeat([]byte{'x'}, protocol.MaximumCredentialBytes-36)} {
		if !Valid(value) {
			t.Fatal("admitted token syntax was refused")
		}
	}
	for _, value := range [][]byte{nil, bytes.Repeat([]byte{'x'}, protocol.MaximumCredentialBytes-35), []byte("invalid token"), []byte("invalid\nvalue"), []byte("invalid:value"), []byte("invalid\\value"), []byte("invalid\"value"), {0x7f}, {0x80}, {0}} {
		if Valid(value) {
			t.Fatal("invalid header syntax was admitted")
		}
	}
}
