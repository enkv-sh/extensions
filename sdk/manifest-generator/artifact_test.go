package manifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestMeasureArtifactReportsOnlyExactBytes(t *testing.T) {
	b := []byte("this is deliberately not JSON\n")
	m, f := MeasureArtifact(t.Context(), b)
	if f != "" || m.Length != uint64(len(b)) || m.Digest != sha256.Sum256(b) {
		t.Fatal(m, f)
	}
	if _, f := MeasureArtifact(t.Context(), nil); f != InvalidResult {
		t.Fatal(f)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, f := MeasureArtifact(ctx, b); f != Cancelled {
		t.Fatal(f)
	}
}

// full_only: false
func TestResultFailureCombinations(t *testing.T) {
	for _, r := range []Result{{}, {Artifact: make([]byte, 1, 2)}, {Failure: "other"}, {Failure: InvalidInput, Artifact: []byte{1}}} {
		if ValidateResult(r) != InvalidResult {
			t.Fatal("malformed result", r.Failure)
		}
	}
	if ValidateResult(Result{Artifact: []byte("INI")}) != "" || ValidateResult(Result{Failure: InvalidInput}) != "" {
		t.Fatal("legal result refused")
	}
	for _, r := range []SettingsResult{{}, {Settings: []byte("{")}, {Settings: make([]byte, 1, 2)}, {Failure: InvalidInput, Settings: []byte("{}")}} {
		if ValidateSettingsResult(r) != InvalidResult {
			t.Fatal("bad settings result")
		}
	}
}

type cancelAfter struct {
	context.Context
	calls, at int
}

func (c *cancelAfter) Err() error {
	c.calls++
	if c.at > 0 && c.calls >= c.at {
		return context.Canceled
	}
	return c.Context.Err()
}

// full_only: false
func TestMeasureArtifactCancellationDuringTraversalAndCompletion(t *testing.T) {
	// 24,577 repetitions of 00 01 fe ff are 98,308 bytes: two full 49,152-byte
	// windows and four final bytes. SHA-256 was derived independently with Python
	// hashlib, rather than through the production measurement function.
	body := bytes.Repeat([]byte{0, 1, 254, 255}, 24577)
	tracker := &cancelAfter{Context: t.Context()}
	metadata, failure := MeasureArtifact(tracker, body)
	if failure != "" || metadata.Length != 98308 || hex.EncodeToString(metadata.Digest[:]) != "b03676dc0015dd5be4bdc8ad5da6d5b183b8f8bfab96dbbee49d22aa6b98e3a8" {
		t.Fatal(metadata, failure)
	}
	if tracker.calls < 4 {
		t.Fatal("bounded traversal did not check its context", tracker.calls)
	}
	for _, at := range []int{tracker.calls - 2, tracker.calls - 1, tracker.calls} {
		ctx := &cancelAfter{Context: t.Context(), at: at}
		if metadata, failure := MeasureArtifact(ctx, body); failure != Cancelled || metadata != (Metadata{}) {
			t.Fatal("partial or completed hash escaped cancellation", at, metadata, failure)
		}
	}
}
