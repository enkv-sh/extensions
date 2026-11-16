package genericjson

import (
	"bytes"
	"context"
	manifest "enkv.sh/sdk/manifest-generator"
)

// Schema identifies the exact artifact grammar.
const Schema = "ENKV/CONSUMPTION-MANIFEST/v3"

// FormatContractID identifies the format semantics and equals Schema.
const FormatContractID = Schema

// ConfigContractID identifies the empty-object settings contract.
const ConfigContractID = "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1"

// ValidateFormatSettings accepts only an empty JSON object and returns owned {}
// bytes. Canonical requests require exactly {}. It retains no request aliases;
// invalid input, cancellation and deadline expiry return their closed manifest
// failure. The caller clears successful settings bytes after use.
func ValidateFormatSettings(ctx context.Context, request manifest.SettingsRequest) manifest.SettingsResult {
	if ctx == nil || request.FormatContractID != FormatContractID || request.ConfigContractID != ConfigContractID {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return manifest.SettingsResult{Failure: manifest.Expired}
		}
		return manifest.SettingsResult{Failure: manifest.Cancelled}
	}
	if failure := manifest.ValidateSettingsRequest(request); failure != "" {
		return manifest.SettingsResult{Failure: failure}
	}
	object := bytes.TrimSpace(request.Settings)
	if len(object) < 2 || object[0] != '{' || object[len(object)-1] != '}' || len(bytes.TrimSpace(object[1:len(object)-1])) != 0 || request.Canonical && !bytes.Equal(request.Settings, []byte("{}")) {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	canonical := [2]byte{'{', '}'}
	defer clear(canonical[:])
	return manifest.CopySettingsResult(ctx, canonical[:])
}
