package manifest

import "context"

// CopySettingsResult borrows settings and returns an independent exact-capacity
// copy. The caller retains ownership of the source, including its spare capacity,
// and must clear that backing after its last user returns. The result transfers
// to the receiver under SettingsResult rules. This helper checks common JSON
// validity, not plugin grammar or canonicalization; the author must do that work.
// Failure returns nil settings and clears any provisional copy. A nil context
// returns InvalidInput; cancellation and deadline expiry return Cancelled and Expired.
func CopySettingsResult(ctx context.Context, settings []byte) SettingsResult {
	if failure := contextFailure(ctx); failure != "" {
		return SettingsResult{Failure: failure}
	}
	if failure := ValidateSettings(settings); failure != "" {
		return SettingsResult{Failure: failure}
	}
	owned := make([]byte, len(settings))
	copy(owned, settings)
	return finishSettingsCopy(ctx, owned)
}

func finishSettingsCopy(ctx context.Context, owned []byte) SettingsResult {
	if failure := contextFailure(ctx); failure != "" {
		clear(owned[:cap(owned)])
		return SettingsResult{Failure: failure}
	}
	return SettingsResult{Settings: owned}
}
