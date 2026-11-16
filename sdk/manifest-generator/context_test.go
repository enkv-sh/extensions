package manifest

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type endedContext struct {
	context.Context
	cause error
}

func (c *endedContext) Err() error { return c.cause }

// full_only: false
func TestManifestContextMappingPreservesOriginalPolicy(t *testing.T) {
	var typedNil *endedContext
	expired, cancel := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer cancel()
	for _, row := range []struct {
		name string
		ctx  context.Context
		want Failure
	}{
		{"nil", nil, InvalidInput}, {"typed-nil", typedNil, InvalidInput}, {"valid", t.Context(), ""},
		{"cancelled", &endedContext{Context: t.Context(), cause: context.Canceled}, Cancelled},
		{"expired", expired, Expired},
		{"wrapped-expiry", &endedContext{Context: t.Context(), cause: fmt.Errorf("wrapped: %w", context.DeadlineExceeded)}, Cancelled},
	} {
		t.Run(row.name, func(t *testing.T) {
			metadata, failure := MeasureArtifact(row.ctx, []byte("{}"))
			if failure != row.want || failure != "" && metadata != (Metadata{}) {
				t.Fatal("context changed artifact result", failure, metadata)
			}
		})
	}
}
