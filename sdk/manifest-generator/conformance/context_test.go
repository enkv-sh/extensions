package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/native"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

func checkRenderCallerContextDiagnosis(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "during-exchange", "violation-before-cancellation"} {
		t.Run("caller-context/"+condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := error(context.Canceled)
			if condition == "cancelled" {
				cancel()
			}
			if condition == "expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(0, 0))
				defer stop()
				want = context.DeadlineExceeded
			}
			calls := 0
			var returned []byte
			var received manifest.View
			impl := authorImplementation(t, func(ctx context.Context, view manifest.View) manifest.Result {
				calls++
				received = view
				result := authorRenderer(ctx, view)
				returned = result.Artifact
				if condition == "violation-before-cancellation" {
					result.Artifact[0] ^= 1
				}
				if condition == "during-exchange" || condition == "violation-before-cancellation" {
					cancel()
				}
				return result
			})
			err := CheckImplementation(ctx, native.Serve, impl, authorFixture())
			if condition == "violation-before-cancellation" {
				if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "callback.result") {
					t.Fatal("cancellation hid raw render violation", err)
				}
			} else if !errors.Is(err, want) || !errors.Is(err, protocol.ErrWire) || !strings.Contains(err.Error(), "caller.context:") {
				t.Fatal("render context diagnosis lost reason or cause", err)
			}
			expected := 0
			if condition == "during-exchange" || condition == "violation-before-cancellation" {
				expected = 1
			}
			if calls != expected || !allZeroArtifact(returned[:cap(returned)]) || calls == 1 && received.Header() != (manifest.Header{}) {
				t.Fatal("render cancellation skipped disposal or entry observations", calls)
			}
		})
	}
}

func checkSettingsCallerContextDiagnosis(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "during-exchange", "violation-before-cancellation", "expected-settings-field"} {
		t.Run("caller-context/"+condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := error(context.Canceled)
			if condition == "cancelled" {
				cancel()
			}
			if condition == "expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(0, 0))
				defer stop()
				want = context.DeadlineExceeded
			}
			fixture := SettingsFixture{Request: manifest.SettingsRequest{FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}")}, ExpectedSettings: []byte("{}")}
			if condition == "expected-settings-field" {
				fixture.ExpectedFailure = manifest.InvalidInput
			}
			impl := authorImplementation(t, authorRenderer)
			calls := 0
			var returned, borrowed []byte
			impl.ValidateFormatSettings = func(_ context.Context, r manifest.SettingsRequest) manifest.SettingsResult {
				calls++
				borrowed = r.Settings
				returned = []byte("{}")
				if condition == "violation-before-cancellation" {
					returned = []byte("[]")
				}
				if condition == "during-exchange" || condition == "violation-before-cancellation" {
					cancel()
				}
				return manifest.SettingsResult{Settings: returned}
			}
			err := CheckSettingsImplementation(ctx, native.Serve, impl, fixture)
			if condition == "violation-before-cancellation" {
				if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "callback.result") {
					t.Fatal("cancellation hid raw settings violation", err)
				}
			} else if condition == "expected-settings-field" {
				if err == nil || !errors.Is(err, protocol.ErrWire) || !strings.Contains(err.Error(), "fixture.expected_settings: conflicting failure expectation") {
					t.Fatal("settings fixture error names another field", err)
				}
			} else if !errors.Is(err, want) || !errors.Is(err, protocol.ErrWire) || !strings.Contains(err.Error(), "caller.context:") {
				t.Fatal("settings context diagnosis lost reason or cause", err)
			}
			expected := 0
			if condition == "during-exchange" || condition == "violation-before-cancellation" {
				expected = 1
			}
			if calls != expected || !allZeroArtifact(returned[:cap(returned)]) || !allZeroArtifact(borrowed[:cap(borrowed)]) {
				t.Fatal("settings cancellation skipped disposal or entry observations", calls)
			}
		})
	}
}
