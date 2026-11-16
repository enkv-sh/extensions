package credential

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestSnapshotExactWireAndRefusals(t *testing.T) {
	// Version 1, expiry 2100-01-01 UTC (4102444800000 ms), token "token", quota "123".
	want, err := hex.DecodeString("0001000003bb2cc3d8000005746f6b656e0003313233")
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := Encode("token", expiry, "123")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("wire differs: got=%x err=%v", got, err)
	}
	value, err := Decode(want, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || string(value.Token) != "token" || value.QuotaProject != "123" || !value.Expiry.Equal(expiry) {
		t.Fatal("snapshot meaning differs", err)
	}
	for _, condition := range []string{"version", "truncated", "trailing", "expired", "raw-token", "quota-header"} {
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
			case "expired":
				now = expiry
			case "raw-token":
				body = []byte("token")
			case "quota-header":
				body[len(body)-1] = '\n'
			}
			if _, err := Decode(body, now); err == nil {
				t.Fatal("invalid snapshot admitted")
			}
		})
	}
}

// full_only: false
func TestSnapshotTokenAndQuotaBoundaries(t *testing.T) {
	expiry := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, token, quota string
		accepted           bool
	}{
		{"maximum", strings.Repeat("x", 16384), strings.Repeat("q", 253), true},
		{"token-one-over", strings.Repeat("x", 16385), "", false},
		{"quota-one-over", "token", strings.Repeat("q", 254), false},
		{"legacy-domain", "token", "example.com:project-123", true},
		{"quota-header", "token", "quota\r\nInjected: true", false},
		{"empty-token", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := Encode(tc.token, expiry, tc.quota)
			defer clear(body)
			if (err == nil) != tc.accepted {
				t.Fatal("snapshot boundary result differs", err)
			}
			if tc.accepted {
				value, err := Decode(body, time.Now())
				if err != nil || string(value.Token) != tc.token || value.QuotaProject != tc.quota {
					t.Fatal("complete snapshot differs", err)
				}
			}
		})
	}
}
