// Package profile owns the local random-secret settings and value format.
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	protocol "enkv.sh/sdk/protocols/generator"
)

// EntropyBytes is the number of random bytes acquired for each new value.
const EntropyBytes = 32

// ValueBytes is the unpadded base64url length of EntropyBytes.
const ValueBytes = 43

// ConfigContractID identifies the fixed empty-settings and value-format contract.
func ConfigContractID() protocol.ID {
	return sha256.Sum256([]byte("ENKV/local-random-secret/config/v1"))
}

// Normalize accepts only an empty JSON object and returns owned canonical {}
// settings with no resource lifecycle. Refusals return protocol.ErrProtocol.
func Normalize(settings []byte) (protocol.Intent, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(settings, &fields) != nil || fields == nil || len(fields) != 0 {
		return protocol.Intent{}, protocol.ErrProtocol
	}
	return protocol.Intent{Schema: protocol.Schema, ConfigContractID: ConfigContractID(), LifecycleMode: protocol.LifecycleNone, Settings: []byte(`{}`)}, nil
}

// ValidateCanonical requires the exact contract, no resource identity and {}
// settings. It borrows intent only for the call and returns protocol.ErrProtocol
// for a zero or noncanonical intent.
func ValidateCanonical(intent protocol.Intent) error {
	if intent.Schema != protocol.Schema || intent.ConfigContractID != ConfigContractID() || intent.LifecycleMode != protocol.LifecycleNone || !intent.ResourceContractID.IsZero() || !bytes.Equal(intent.Settings, []byte(`{}`)) {
		return protocol.ErrProtocol
	}
	return nil
}

// ValidateCommand checks this implementation's semantic input. The native host
// separately admits exact installed support and Core owns operation authority.
func ValidateCommand(command protocol.Command) error {
	if command.Action != protocol.ActionCreate {
		return protocol.ErrProtocol
	}
	if err := protocol.ValidateCommand(command); err != nil {
		return err
	}
	intent, err := protocol.DecodeIntent(command.Intent)
	if err != nil {
		return err
	}
	return ValidateCanonical(intent)
}
