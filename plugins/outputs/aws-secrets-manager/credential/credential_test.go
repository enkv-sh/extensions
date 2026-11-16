package credential

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// full_only: false
func TestSnapshotExactWireAndRefusals(t *testing.T) {
	// Version 1, non-expiring static credentials, three BE-u16 length fields.
	want, err := hex.DecodeString("000100000000000000000010414b494141414141414141414141414100067365637265740003746f6b")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode("AKIAAAAAAAAAAAAA", "secret", "tok", time.Time{})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("wire differs: got=%x err=%v", got, err)
	}
	value, err := Decode(want, time.Now())
	if err != nil || string(value.AccessKeyID) != "AKIAAAAAAAAAAAAA" || string(value.SecretAccessKey) != "secret" || string(value.SessionToken) != "tok" || !value.Expiry.IsZero() {
		t.Fatal("snapshot meaning differs", err)
	}
	for _, condition := range []string{"version", "truncated", "trailing", "old-wire", "expired", "secret-header"} {
		t.Run(condition, func(t *testing.T) {
			body := bytes.Clone(want)
			now := time.Now()
			switch condition {
			case "version":
				body[1] = 2
			case "truncated":
				body = body[:len(body)-1]
			case "trailing":
				body = append(body, 0)
			case "old-wire":
				body = body[10:]
			case "expired":
				body[9] = 1
			case "secret-header":
				body[len(body)-1] = '\n'
			}
			if _, err := Decode(body, now); err == nil {
				t.Fatal("invalid snapshot admitted")
			}
		})
	}
}
