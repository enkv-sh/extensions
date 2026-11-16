package github

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// full_only: false
func TestGitHubCanonicalSettingsAndOpaquePolicy(t *testing.T) {
	for _, row := range []struct {
		scope                           profile.Scope
		settings, canonical, coordinate string
		policy                          []byte
	}{
		{profile.Repository, `{"repository":"repo","owner":"owner"}`, `{"owner":"owner","repository":"repo"}`, "repos/owner/repo/actions/secrets/TOKEN", nil},
		{profile.Organization, `{"owner":"owner","visibility":"selected","repositories":[7,11]}`, `{"owner":"owner"}`, "orgs/owner/actions/secrets/TOKEN", []byte{0, 1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 11}},
		{profile.Environment, `{"owner":"owner","repository":"repo","environment":"prod"}`, `{"owner":"owner","repository":"repo","environment":"prod"}`, "repos/owner/repo/environments/prod/secrets/TOKEN", nil},
	} {
		i := testImplementation(row.scope)
		d, err := i.NormalizeDestination(t.Context(), []byte(row.settings))
		if err != nil || string(d.CanonicalSettings) != row.canonical || !bytes.Equal(d.Policy.Data, row.policy) {
			t.Fatal("canonical settings or independent policy bytes", err, hex.EncodeToString(d.Policy.Data))
		}
		if err := i.ValidateCanonical(t.Context(), d); err != nil {
			t.Fatal(err)
		}
		target, err := i.InterpretTarget(t.Context(), output.TargetRequest{Destination: d, EntryName: "token", PayloadEncoding: protocol.EncodingBase64})
		if err != nil || target.CanonicalTarget != row.coordinate || target.ConsumerLocator != row.coordinate || target.CreateValueBounds.Maximum != 48000 || target.WriteValueBounds.Maximum != 48000 {
			t.Fatal("scope target", err)
		}
		changed := d
		changed.CanonicalSettings = append([]byte(" "), d.CanonicalSettings...)
		if i.ValidateCanonical(t.Context(), changed) == nil {
			t.Fatal("noncanonical settings accepted")
		}
		for _, settings := range []string{`null`, `{"owner":"owner","owner":"other"}`, `{"Owner":"owner"}`, `{"owner":"owner","unknown":true}`, `{"owner":"owner"} trailing`} {
			if _, err := i.NormalizeDestination(t.Context(), []byte(settings)); err == nil {
				t.Fatal("malformed settings accepted", settings)
			}
		}
	}
}

// full_only: false
func TestGitHubRetainedDeletionTargetIsSelfContained(t *testing.T) {
	for _, scope := range []profile.Scope{profile.Repository, profile.Organization, profile.Environment} {
		i := testImplementation(scope)
		c := testCommand(t, scope, protocol.ActionDeleteOwned, profile.Policy{}, nil)
		c.Target.Capabilities = protocol.CapabilityDeleteOwned
		c.Target.CreateValueBounds = protocol.PayloadBounds{}
		c.Target.WriteValueBounds = protocol.PayloadBounds{}
		bounds, err := i.CheckAction(t.Context(), actionForTest(c.ActionCheck()), protocol.Policy{})
		if err != nil || bounds != (protocol.PayloadBounds{}) {
			t.Fatal("retained delete requires old settings or payload", err)
		}
		c.Target.TargetData = targetDataForTest(scope, c.Target.CanonicalTarget+"_OTHER")
		if _, err := i.CheckAction(t.Context(), actionForTest(c.ActionCheck()), protocol.Policy{}); err == nil {
			t.Fatal("target data substitution accepted")
		}
	}
}

// full_only: false
func TestGitHubPreparationOwnsCredentialBeforeOneSend(t *testing.T) {
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reads, effects := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer selected-private-token" {
			t.Error("wrong captured token")
		}
		if r.Method == http.MethodGet {
			reads++
			if err := json.NewEncoder(w).Encode(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(public[:])}); err != nil {
				t.Error(err)
			}
			return
		}
		effects++
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	i := testTransportImplementation(profile.Repository, server.URL, server.Client().Transport)
	payload := []byte("one exact value")
	command := testCommand(t, profile.Repository, protocol.ActionCreateWithValue, profile.Policy{}, payload)
	token := []byte("selected-private-token")
	invocation, err := i.Prepare(t.Context(), preparationForTest(command), protocol.Policy{}, []credentialroute.Input{{Name: "GITHUB_TOKEN", Present: true, Value: token}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := invocation.Close(); err != nil {
			t.Error(err)
		}
	}()
	clear(token)
	if reads != 1 || effects != 0 {
		t.Fatal("preparation entered an effect", reads, effects)
	}
	result, err := invocation.Send(t.Context(), payload)
	if err != nil || result.Class != protocol.ClassAcknowledged || result.AssignedLocator != "" || effects != 1 {
		t.Fatal("single send result", result, err)
	}
	if _, err := invocation.Send(t.Context(), payload); err == nil || effects != 1 {
		t.Fatal("prepared invocation sent twice")
	}
	if err := invocation.Close(); err != nil {
		t.Fatal(err)
	}
	owned := invocation.(*prepared)
	if owned.token != nil || owned.guard.bearer != "" {
		t.Fatal("private credential retained after close")
	}
}

// full_only: false
func TestGitHubPolicyActionSelectionIsPassiveAndScopeExact(t *testing.T) {
	policy := protocol.Policy{ContractID: "github-actions/org-visibility/v1", Data: []byte{0, 1, 1, 0, 0}}
	for _, scope := range []profile.Scope{profile.Organization, profile.Repository, profile.Environment} {
		t.Run(fmt.Sprint(scope), func(t *testing.T) {
			i := testImplementation(scope)
			command := testCommand(t, scope, protocol.ActionWriteValue, testPolicy(scope), []byte("same value"))
			request := output.PolicyActionSelection{DomainID: protocol.ID{7}, Target: command.Target}
			action, err := i.SelectPolicyAction(t.Context(), request, policy)
			if scope == profile.Organization {
				if err != nil || action != protocol.ActionWriteValue {
					t.Fatal("organization mode action", action, err)
				}
				request.HasPreviousPolicyDigest = true
				if action, err := i.SelectPolicyAction(t.Context(), request, policy); err == nil || action != 0 {
					t.Fatal("noncanonical prior evidence accepted")
				}
				request.HasPreviousPolicyDigest = false
				request.Target.TargetData = []byte("wrong target")
				if action, err := i.SelectPolicyAction(t.Context(), request, policy); err == nil || action != 0 {
					t.Fatal("target substitution accepted")
				}
			} else if err == nil || action != 0 {
				t.Fatal("organization policy accepted by another scope")
			}
		})
	}
}
