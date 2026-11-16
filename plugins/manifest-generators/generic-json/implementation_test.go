package genericjson

import (
	"bytes"
	"context"
	manifest "enkv.sh/sdk/manifest-generator"
	"testing"
)

// full_only: false
func TestFormatSettingsOwnCanonicalEmptyObject(t *testing.T) {
	for _, settings := range []string{`{}`, ` { } `} {
		input := []byte(settings)
		r := ValidateFormatSettings(t.Context(), manifest.SettingsRequest{FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: input})
		if r.Failure != "" || string(r.Settings) != "{}" || len(r.Settings) != cap(r.Settings) {
			t.Fatal("ordinary settings", r.Failure)
		}
		input[0] = '!'
		if string(r.Settings) != "{}" {
			t.Fatal("settings aliases request")
		}
		clear(r.Settings)
	}
	for _, settings := range []string{`null`, `[]`, `{"x":1}`, `{"x":1,"x":2}`, `{} {}`, `{ }`} {
		r := ValidateFormatSettings(t.Context(), manifest.SettingsRequest{FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Canonical: true, Settings: []byte(settings)})
		if r.Failure != manifest.InvalidInput || r.Settings != nil {
			t.Fatal("noncanonical settings admitted", settings, r.Failure)
		}
	}
	r := ValidateFormatSettings(t.Context(), manifest.SettingsRequest{FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Canonical: true, Settings: []byte(`{}`)})
	if !bytes.Equal(r.Settings, []byte(`{}`)) {
		t.Fatal("canonical settings")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if got := ValidateFormatSettings(cancelled, manifest.SettingsRequest{FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: []byte(`{}`)}); got.Failure != manifest.Cancelled {
		t.Fatal("cancelled settings", got.Failure)
	}
	t.Run("cancel-after-copy", func(t *testing.T) {
		ctx := &manifestCancelContext{Context: t.Context(), failAt: 3}
		input := []byte(`{}`)
		got := ValidateFormatSettings(ctx, manifest.SettingsRequest{FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: input})
		if got.Failure != manifest.Cancelled || got.Settings != nil || ctx.calls != 3 || string(input) != `{}` {
			t.Fatal("settings copy cancellation", got.Failure, ctx.calls)
		}
	})
}
