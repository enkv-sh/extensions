package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	manifest "enkv.sh/sdk/manifest-generator"
)

const formatContract = "example/ini-reference/v1"
const configContract = "example/ini-reference-settings/v1"

type settings struct {
	SectionPrefix string `json:"section_prefix"`
}

func prefixValid(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 32 {
		return false
	}
	for i, c := range []byte(prefix) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func parseSettings(input []byte) (settings, bool) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return settings{}, false
	}
	value := settings{SectionPrefix: "enkv"}
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "section_prefix" || seen {
			return settings{}, false
		}
		seen = true
		prefix, err := decoder.Token()
		text, ok := prefix.(string)
		if err != nil || !ok {
			return settings{}, false
		}
		value.SectionPrefix = text
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return settings{}, false
	}
	if decoder.Decode(new(any)) != io.EOF || !prefixValid(value.SectionPrefix) {
		return settings{}, false
	}
	return value, true
}
func validateSettings(ctx context.Context, input manifest.SettingsRequest) manifest.SettingsResult {
	if ctx == nil || input.FormatContractID != formatContract || input.ConfigContractID != configContract || manifest.ValidateSettingsRequest(input) != "" {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return manifest.SettingsResult{Failure: manifest.Expired}
		}
		return manifest.SettingsResult{Failure: manifest.Cancelled}
	}
	value, ok := parseSettings(input.Settings)
	if !ok {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	defer clear(encoded[:cap(encoded)])
	// Canonical validation preserves stored bytes; applying defaults or changing
	// spelling here would silently change the meaning of a retained request.
	if input.Canonical && !bytes.Equal(encoded, input.Settings) {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	return manifest.CopySettingsResult(ctx, encoded)
}
