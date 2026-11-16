package github

import (
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/artifact"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestImplementationPreservesDescriptorDiagnosis(t *testing.T) {
	_, err := New(profile.Repository, []byte(`{"SCHEMA":"private-supplied-value"}`))
	if !errors.Is(err, profile.ErrProfile) || !errors.Is(err, artifact.ErrRecord) || !strings.Contains(err.Error(), "record.schema") || strings.Contains(err.Error(), "private-supplied-value") || strings.Contains(err.Error(), "SCHEMA") {
		t.Fatal("constructor lost safe descriptor diagnosis", err)
	}
}
