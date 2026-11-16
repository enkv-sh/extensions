package artifact

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// full_only: false
func TestVerifyExecutablePreservesContextCancellation(t *testing.T) {
	metadata, path := publicationFixture(t, "cancellable opened executable input")
	healthy := &cancelArtifactAtCheck{Context: t.Context()}
	if err := VerifyExecutable(healthy, path, metadata); err != nil {
		t.Fatal("healthy executable refused before cancellation sweep", err)
	}
	if healthy.checks == 0 {
		t.Fatal("healthy verification performed no context check")
	}
	for ordinal := 1; ordinal <= healthy.checks; ordinal++ {
		t.Run(fmt.Sprintf("cancel_at_%d", ordinal), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			controlled := &cancelArtifactAtCheck{Context: ctx, cancel: cancel, at: ordinal}
			err := VerifyExecutable(controlled, path, metadata)
			if !controlled.fired {
				t.Fatal("verification did not reach the selected cancellation check", ordinal, controlled.checks)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("verification did not preserve context cancellation", err)
			}
		})
	}
	if err := VerifyExecutable(t.Context(), path, metadata); err != nil {
		t.Fatal("healthy unchanged executable refused after cancellation sweep", err)
	}
}

// full_only: false
func TestSourceCapturePreservesContextCancellation(t *testing.T) {
	_, pkg := sourceCaptureFixture(t, "")
	healthy := &cancelArtifactAtCheck{Context: t.Context()}
	if got, err := CaptureSources(healthy, "output", []SourcePackage{pkg}); err != nil || len(got) != 1 {
		t.Fatal("healthy source capture refused before cancellation sweep", got, err)
	}
	if healthy.checks == 0 {
		t.Fatal("source capture performed no context check")
	}
	for ordinal := 1; ordinal <= healthy.checks; ordinal++ {
		t.Run(fmt.Sprintf("cancel_at_%d", ordinal), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			controlled := &cancelArtifactAtCheck{Context: ctx, cancel: cancel, at: ordinal}
			got, err := CaptureSources(controlled, "output", []SourcePackage{pkg})
			if !controlled.fired || !errors.Is(err, context.Canceled) || len(got) != 0 {
				t.Fatal("source cancellation lost its cause or retained an incomplete digest", controlled.fired, got, err)
			}
		})
	}
	if got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg}); err != nil || len(got) != 1 {
		t.Fatal("unchanged source capture refused after cancellation sweep", got, err)
	}
}

type cancelArtifactAtCheck struct {
	context.Context
	cancel context.CancelFunc
	at     int
	checks int
	fired  bool
}

func (c *cancelArtifactAtCheck) Err() error {
	c.checks++
	if c.at != 0 && c.checks == c.at {
		c.fired = true
		c.cancel()
	}
	return c.Context.Err()
}
