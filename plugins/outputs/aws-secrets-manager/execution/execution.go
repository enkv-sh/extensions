// Package execution supplies the official aws-secrets-manager output.
package execution

import (
	"enkv.sh/plugins/outputs/aws-secrets-manager/internal/awssm"
	"enkv.sh/sdk/output"
)

// NewImplementation binds the embedded descriptor to this plugin's public
// settings contract and SDK credential mode. It makes no credential lookup or
// service request. Use the returned implementation through output.Main; direct
// Prepare calls require the same declared inputs in the process environment.
// Constructor refusals wrap profile.ErrProfile and preserve output.Bind causes;
// credential discovery and later preparation can return different errors.
func NewImplementation(descriptor []byte) (output.Implementation, error) {
	return awssm.NewImplementation(descriptor)
}
