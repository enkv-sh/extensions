package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"enkv.sh/plugins/outputs/github-actions/profile"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/crypto/nacl/box"
)

// full_only: false
func TestGitHubAllScopesPreserveRawAndBase64ApplicationBytes(t *testing.T) {
	for _, scope := range []profile.Scope{profile.Repository, profile.Organization, profile.Environment} {
		for _, encoding := range []string{"raw", "base64"} {
			t.Run(strconv.Itoa(int(scope))+"/"+encoding, func(t *testing.T) {
				payload := []byte{0, 1, 2, 255}
				if encoding == "base64" {
					payload = []byte("AAEC/w==")
				}
				policy := testPolicy(scope)
				command := testCommand(t, scope, protocol.ActionCreateWithValue, policy, payload)
				command.Target.PayloadEncoding = map[string]uint8{"raw": protocol.EncodingRaw, "base64": protocol.EncodingBase64}[encoding]
				public, private, err := box.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				reads, writes := 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						reads++
						_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "test-key", "key": base64.StdEncoding.EncodeToString(public[:])})
						return
					}
					writes++
					var body map[string]json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid JSON")
						w.WriteHeader(400)
						return
					}
					var encrypted string
					if json.Unmarshal(body["encrypted_value"], &encrypted) != nil {
						t.Error("missing encrypted value")
					}
					sealed, decodeErr := base64.StdEncoding.Strict().DecodeString(encrypted)
					opened, ok := box.OpenAnonymous(nil, sealed, public, private)
					if decodeErr != nil || !ok || !bytes.Equal(opened, payload) {
						t.Error("sealed transport changed application bytes")
					}
					clear(opened)
					if scope == profile.Organization {
						var visibility string
						var ids []uint64
						_ = json.Unmarshal(body["visibility"], &visibility)
						_ = json.Unmarshal(body["selected_repository_ids"], &ids)
						if len(body) != 4 || visibility != "selected" || !reflect.DeepEqual(ids, []uint64{7, 11}) {
							t.Error("organization visibility changed")
						}
					} else if len(body) != 2 {
						t.Error("inherited scope sent permission fields")
					}
					w.WriteHeader(http.StatusCreated)
				}))
				defer server.Close()
				i := testTransportImplementation(scope, server.URL, server.Client().Transport)
				got, err := i.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
				if err != nil || got.Class != protocol.ClassAcknowledged || reads != 1 || writes != 1 {
					t.Fatalf("encoding result=%#v err=%v reads=%d writes=%d", got, err, reads, writes)
				}
			})
		}
	}
}
