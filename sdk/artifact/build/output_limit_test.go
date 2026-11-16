package build

import (
	"io"
	"strings"
	"testing"
)

// full_only: false
func TestGoCommandOutputCannotBypassBound(t *testing.T) {
	const limit = 64 << 20
	var output commandBuffer
	reader := io.LimitReader(strings.NewReader(strings.Repeat("x", limit+1)), limit+1)
	n, err := io.Copy(&output, reader)
	if err == nil || err.Error() != "go command output exceeds limit" || n != limit {
		t.Fatalf("command output bound differs: copied=%d error=%v", n, err)
	}
}
