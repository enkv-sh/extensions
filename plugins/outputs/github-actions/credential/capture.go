package credential

import (
	"context"
	"enkv.sh/sdk/artifact/credentialroute"
	"errors"
	"os"
)

// ErrCredential reports absent, malformed or cancelled credential capture.
var ErrCredential = errors.New("GitHub credential refused")

// Capture copies one exact GITHUB_TOKEN value into owned bytes; the caller must
// clear them after use. A nil inputs slice reads the process environment; a
// nonnil slice must contain exactly the declared present input and has no
// environment fallback. GH_TOKEN is never used. Refusals return ErrCredential.
func Capture(ctx context.Context, inputs []credentialroute.Input) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCredential
	}
	var value []byte
	if inputs != nil {
		if len(inputs) != 1 || inputs[0].Name != "GITHUB_TOKEN" || !inputs[0].Present {
			return nil, ErrCredential
		}
		value = inputs[0].Value
	} else {
		token, present := os.LookupEnv("GITHUB_TOKEN")
		if !present || len(token) > MaximumTokenBytes {
			return nil, ErrCredential
		}
		value = []byte(token)
		defer clear(value)
	}
	if !Valid(value) {
		return nil, ErrCredential
	}
	owned := make([]byte, len(value))
	copy(owned, value)
	return owned, nil
}
