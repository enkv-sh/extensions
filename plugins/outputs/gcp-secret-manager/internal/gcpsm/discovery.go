package gcpsm

import (
	"cloud.google.com/go/auth"
	authcredentials "cloud.google.com/go/auth/credentials"
	"context"
	outputcredential "enkv.sh/plugins/outputs/gcp-secret-manager/credential"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type credentialSource struct {
	credentials  *auth.Credentials
	quotaProject string
}

// Resolve only the public Google universe and capture one synchronous token.
// Credential refresh must not extend the mutation owner beyond this invocation.
func loadCredentialSource(ctx context.Context) (credentialSource, error) {
	if ctx == nil || ctx.Err() != nil {
		return credentialSource{}, outputcredential.ErrCredential
	}
	selected, err := authcredentials.DetectDefault(&authcredentials.DetectOptions{
		Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}, DisableAsyncRefresh: true,
		Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil || selected == nil {
		return credentialSource{}, outputcredential.ErrCredential
	}
	universe, err := selected.UniverseDomain(ctx)
	if err != nil || ctx.Err() != nil || universe != "googleapis.com" {
		return credentialSource{}, outputcredential.ErrCredential
	}
	quota, err := selected.QuotaProjectID(ctx)
	if err != nil || ctx.Err() != nil || len(quota) > 253 {
		return credentialSource{}, outputcredential.ErrCredential
	}
	for _, c := range []byte(quota) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != ':' {
			return credentialSource{}, outputcredential.ErrCredential
		}
	}
	return credentialSource{selected, quota}, nil
}
func captureCredentialSource(ctx context.Context, source credentialSource) ([]byte, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || source.credentials == nil || source.credentials.TokenProvider == nil {
		return nil, time.Time{}, outputcredential.ErrCredential
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	token, err := source.credentials.Token(ctx)
	if err != nil || ctx.Err() != nil || token == nil || !strings.EqualFold(token.Type, "Bearer") || token.Expiry.IsZero() || !time.Now().Before(token.Expiry) {
		return nil, time.Time{}, outputcredential.ErrCredential
	}
	wire, err := outputcredential.Encode(token.Value, token.Expiry, source.quotaProject)
	return wire, token.Expiry, err
}
func captureCredential(ctx context.Context) ([]byte, time.Time, error) {
	source, err := loadCredentialSource(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	return captureCredentialSource(ctx, source)
}
