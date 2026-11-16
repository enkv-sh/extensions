package credential

import (
	"bytes"
	"context"
	"enkv.sh/sdk/artifact/credentialroute"
	"strings"
	"testing"
)

// full_only: false
func TestGitHubCredentialCapturesOnlySelectedEnvironment(t *testing.T) {
	t.Setenv("GH_TOKEN", "alternate-token-must-not-be-used")
	for _, row := range []struct {
		name, token string
		valid       bool
	}{
		{"selected", "selected-action-token", true}, {"rotated", "rotated-action-token", true}, {"missing-no-fallback", "", false},
		{"space", "invalid token", false}, {"newline", "invalid\nvalue", false}, {"colon", "invalid:value", false}, {"backslash", "invalid\\value", false}, {"quote", "invalid\"value", false}, {"non-ascii", "invalid\u0080value", false}, {"maximum", strings.Repeat("x", MaximumTokenBytes), true}, {"first-over", strings.Repeat("x", MaximumTokenBytes+1), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", row.token)
			body, err := Capture(t.Context(), nil)
			defer clear(body)
			if !row.valid {
				if err != ErrCredential || body != nil {
					t.Fatal("credential refusal", err)
				}
				return
			}
			if err != nil || !bytes.Equal(body, []byte(row.token)) || cap(body) > MaximumTokenBytes+1 {
				t.Fatal("exact selected snapshot", err)
			}
			clear(body)
			if row.token != "" && body[0] != 0 {
				t.Fatal("snapshot is not owned")
			}
		})
	}
}

// full_only: false
func TestGitHubCredentialInputHasNoEnvironmentFallback(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "environment-must-not-be-read")
	for _, input := range [][]credentialroute.Input{{}, {{Name: "GH_TOKEN", Present: true, Value: []byte("other")}}, {{Name: "GITHUB_TOKEN", Present: false}}, {{Name: "GITHUB_TOKEN", Present: true, Value: []byte("bad token")}}} {
		if body, err := Capture(t.Context(), input); err != ErrCredential || body != nil {
			t.Fatal("invalid selected input acquired fallback")
		}
	}
	source := []byte("selected-private-input")
	body, err := Capture(t.Context(), []credentialroute.Input{{Name: "GITHUB_TOKEN", Present: true, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	clear(source)
	if string(body) != "selected-private-input" {
		t.Fatal("capture aliases caller")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if body, err := Capture(ctx, nil); err != ErrCredential || body != nil {
			t.Fatal("invalid context acquired credential")
		}
	}
}
