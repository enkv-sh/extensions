// Package credential validates the GitHub output profile's private token bytes.
package credential

import protocol "enkv.sh/sdk/protocols/output"

// MaximumTokenBytes is the private token limit after credential-route framing.
const MaximumTokenBytes = protocol.MaximumCredentialBytes - 36

// Valid checks the bounded header syntax admitted by the output profiles.
// It does not establish the token's permissions or service validity.
func Valid(value []byte) bool {
	if len(value) == 0 || len(value) > MaximumTokenBytes {
		return false
	}
	for _, b := range value {
		if b < 0x21 || b > 0x7e || b == ':' || b == '\\' || b == '"' {
			return false
		}
	}
	return true
}
