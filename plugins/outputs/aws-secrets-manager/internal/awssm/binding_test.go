package awssm

import (
	"enkv.sh/plugins/outputs/aws-secrets-manager/profile"
	"enkv.sh/sdk/artifact"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestImplementationPreservesDescriptorDiagnosis(t *testing.T) {
	_, err := NewImplementation([]byte(`{"SCHEMA":"private-supplied-value"}`))
	if !errors.Is(err, profile.ErrProfile) || !errors.Is(err, artifact.ErrRecord) || !strings.Contains(err.Error(), "record.schema") || strings.Contains(err.Error(), "private-supplied-value") || strings.Contains(err.Error(), "SCHEMA") {
		t.Fatal("constructor lost safe descriptor diagnosis", err)
	}
}
