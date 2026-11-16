package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/plugins/outputs/github-actions/credential"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/crypto/nacl/box"
)

type cancelledSendImplementation struct{ Implementation }

func (i cancelledSendImplementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	p, err := i.Implementation.Prepare(ctx, c, policy, inputs)
	if p == nil {
		return nil, err
	}
	return cancelledSendPrepared{Prepared: p}, err
}

type cancelledSendPrepared struct{ output.Prepared }

func (p cancelledSendPrepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	return p.Prepared.Send(stopped, payload)
}

// full_only: false
func TestGitHubServingPreservesProvedNoSend(t *testing.T) {
	for _, scope := range []profile.Scope{profile.Repository, profile.Organization, profile.Environment} {
		t.Run(strconv.Itoa(int(scope)), func(t *testing.T) {
			var sends atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			i := testTransportImplementation(scope, server.URL, server.Client().Transport)
			c := testCommand(t, scope, protocol.ActionDeleteOwned, testPolicy(scope), nil)
			got, err := runForTest(t.Context(), cancelledSendImplementation{i}, c, protocol.Policy{}, nil, []byte("github_pat_TEST"))
			if err != nil || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect || got.NormalizedStatus != 0 || sends.Load() != 0 {
				t.Fatal("checked no-send was lost by serving", got, err, sends.Load())
			}
		})
	}
}

const (
	orgPolicyClass = "github-actions/org-visibility"
)

func testID(s string) protocol.ID { return sha256.Sum256([]byte(s)) }

func testCoordinate(scope profile.Scope) string {
	switch scope {
	case profile.Repository:
		return "repos/owner/repo/actions/secrets/TOKEN"
	case profile.Organization:
		return "orgs/owner/actions/secrets/TOKEN"
	case profile.Environment:
		return "repos/owner/repo/environments/prod/secrets/TOKEN"
	}
	return ""
}

func testPolicy(scope profile.Scope) profile.Policy {
	if scope == profile.Organization {
		return profile.Policy{ClassID: orgPolicyClass, Mode: profile.PolicyExplicitSet,
			SubjectKind: profile.SubjectNumber, NumberSubjects: []uint64{7, 11}}
	}
	return profile.Policy{}
}

func testCommand(t *testing.T, scope profile.Scope, action protocol.Action, policy profile.Policy, payload []byte) protocol.Command {
	t.Helper()
	slot := testCoordinate(scope)
	implementation := testImplementation(scope)
	route, _ := credentialroute.Identity(implementation.CredentialRoute())
	data, _ := json.Marshal(struct {
		Scope      profile.Scope `json:"scope"`
		Coordinate string        `json:"coordinate"`
	}{scope, slot})
	command := protocol.Command{Schema: 1, Action: action, DomainID: testID("domain"), OperationID: testID("operation"), AttemptID: testID("attempt"), CoordinateID: testID("coordinate"), ProjectionCommitment: testID("projection"), DispatchContextDigest: testID("dispatch"), RequestContractDigest: testID("request"), ResponseContractDigest: testID("response"), DescriptorID: implementation.Identity().DescriptorID, CredentialRouteID: protocol.ID(route), BindingIncarnationID: testID("binding"), EntryIncarnationID: testID("entry"), TargetRowDigest: testID("target"), BindingDestinationID: "destination", DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), Target: protocol.Target{ServiceContractID: profile.ServiceContractID, TargetContractID: profile.TargetContractID, CanonicalTarget: slot, ConsumerLocator: slot, TargetData: data, PayloadEncoding: protocol.EncodingRaw, Capabilities: actions(scope), CreateValueBounds: protocol.PayloadBounds{Maximum: MaximumRawValueBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: MaximumRawValueBytes}}}
	if action < protocol.ActionDeleteOwned {
		wire := publicPolicyForTest(policy)
		command.PolicyContractID = wire.ContractID
		command.PolicyDigest, _ = protocol.PolicyDigest(command.DomainID, wire)
	}
	if action == protocol.ActionCreateWithValue || action == protocol.ActionWriteValue {
		command.PayloadLengthMode = protocol.LengthExact
		command.PayloadLength = uint32(len(payload))
		command.ValueBasisDigest = testID("value")
	}
	switch action {
	case protocol.ActionCreateWithValue:
	case protocol.ActionDeleteReservedSlot:
		command.UncertainCreateAttemptID = testID("uncertain-create")
		command.ExclusiveNamespaceDigest = testID("exclusive")
	default:
		command.OwnedInstance = slot
		command.OwnedBirthAttemptID = testID("birth")
		command.BirthTargetRowDigest = testID("birth-target")
	}
	// Negative provider-policy cases remain well-formed generic opaque commands.
	if _, err := protocol.EncodeCommand(command); err != nil {
		t.Fatal(err)
	}
	return command
}

// full_only: false
func TestGitHubPassiveProfileAndAliases(t *testing.T) {
	for _, scope := range []profile.Scope{profile.Repository, profile.Organization, profile.Environment} {
		i := testImplementation(scope)
		policy := testPolicy(scope)
		c := testCommand(t, scope, protocol.ActionCreateWithValue, policy, nil)
		request := c.ActionCheck()
		request.PayloadLengthMode = protocol.LengthAbsent
		if bounds, err := i.CheckAction(t.Context(), actionForTest(request), publicPolicyForTest(policy)); err != nil || bounds != (protocol.PayloadBounds{Maximum: 48000}) {
			t.Fatal("scope public action", scope, bounds, err)
		}
		request.PayloadLengthMode = protocol.LengthExact
		request.PayloadLength = 48000
		if _, err := i.CheckAction(t.Context(), actionForTest(request), publicPolicyForTest(policy)); err != nil {
			t.Fatal("exact payload bound", err)
		}
		request.PayloadLength++
		if _, err := i.CheckAction(t.Context(), actionForTest(request), publicPolicyForTest(policy)); err == nil {
			t.Fatal("first-over payload accepted")
		}
		request = c.ActionCheck()
		request.Target.CanonicalTarget = strings.Replace(c.Target.CanonicalTarget, "/owner/", "/OWNER/", 1)
		request.Target.ConsumerLocator = request.Target.CanonicalTarget
		request.Target.TargetData = targetDataForTest(scope, request.Target.CanonicalTarget)
		if _, err := i.CheckAction(t.Context(), actionForTest(request), publicPolicyForTest(policy)); err == nil {
			t.Fatal("owner alias accepted")
		}
	}
	for _, path := range []string{"repos/Owner/repo/actions/secrets/TOKEN", "repos/owner/Repo/actions/secrets/TOKEN", "repos/owner/repo/actions/secrets/token", "repos/owner/repo.git/actions/secrets/TOKEN", "repos/owner/repo./actions/secrets/TOKEN", "repos/owner/repo-/actions/secrets/TOKEN", "repos/owner/repo/actions/secrets/TOKEN%2FOTHER", "repos/owner//repo/actions/secrets/TOKEN", "repos/owner/repo/../actions/secrets/TOKEN", "repos/owner/repo/actions/secrets/GITHUB_TOKEN", "repos/owner/repo/actions/secrets/1TOKEN"} {
		if _, err := parseCanonicalTarget(profile.Repository, path); err == nil {
			t.Fatal("canonical path alias accepted", path)
		}
	}
}

// full_only: false
func TestGitHubPolicyClassesAndActions(t *testing.T) {
	for _, scope := range []profile.Scope{profile.Repository, profile.Organization, profile.Environment} {
		policy := testPolicy(scope)
		for _, action := range []protocol.Action{protocol.ActionCreateWithValue, protocol.ActionWriteValue,
			protocol.ActionUpdatePolicy, protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
			selectedPolicy := policy
			if action >= protocol.ActionDeleteOwned {
				selectedPolicy = profile.Policy{}
			}
			var payload []byte
			if action == protocol.ActionCreateWithValue || action == protocol.ActionWriteValue {
				payload = []byte("one secret value")
			}
			commandAction := action
			if scope != profile.Organization && action == protocol.ActionUpdatePolicy {
				commandAction = protocol.ActionWriteValue
			}
			command := testCommand(t, scope, commandAction, selectedPolicy, payload)
			command.Action = action
			request := command.ActionCheck()
			_, err := testImplementation(scope).CheckAction(context.Background(), actionForTest(request), publicPolicyForTest(selectedPolicy))
			wantAccepted := scope == profile.Organization || action != protocol.ActionUpdatePolicy
			if (err == nil) != wantAccepted {
				t.Errorf("scope=%d action=%d accepted=%v", scope, action, err == nil)
			}
		}
	}
	for _, mode := range []uint8{profile.PolicyWholeScope, profile.PolicyRestrictedScope} {
		policy := profile.Policy{ClassID: orgPolicyClass, Mode: mode, SubjectKind: profile.SubjectNone}
		command := testCommand(t, profile.Organization, protocol.ActionCreateWithValue, policy, nil)
		if _, err := testImplementation(profile.Organization).CheckAction(context.Background(), actionForTest(command.ActionCheck()), publicPolicyForTest(policy)); err != nil {
			t.Errorf("organization visibility %d refused: %v", mode, err)
		}
		command.Action = protocol.ActionUpdatePolicy
		command.OwnedInstance, command.OwnedBirthAttemptID = command.Target.CanonicalTarget, testID("birth")
		command.BirthTargetRowDigest = testID("birth-target")
		command.PayloadLengthMode, command.PayloadLength, command.ValueBasisDigest = protocol.LengthAbsent, 0, protocol.ID{}
		if _, err := testImplementation(profile.Organization).CheckAction(context.Background(), actionForTest(command.ActionCheck()), publicPolicyForTest(policy)); err == nil {
			t.Errorf("whole/private policy-only change admitted")
		}
	}
	emptySelected := profile.Policy{ClassID: orgPolicyClass, Mode: profile.PolicyExplicitSet, SubjectKind: profile.SubjectNumber}
	command := testCommand(t, profile.Organization, protocol.ActionUpdatePolicy, emptySelected, nil)
	if _, err := testImplementation(profile.Organization).CheckAction(context.Background(), actionForTest(command.ActionCheck()), publicPolicyForTest(emptySelected)); err == nil {
		t.Fatal("unqualified selected-empty policy admitted")
	}
}

// full_only: false
func TestGitHubExactActionsAndOwnershipResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scope  profile.Scope
		action protocol.Action
		status int
		ack    bool
	}{
		{"repo-create-201", profile.Repository, protocol.ActionCreateWithValue, 201, true},
		{"repo-create-204", profile.Repository, protocol.ActionCreateWithValue, 204, false},
		{"org-create-201", profile.Organization, protocol.ActionCreateWithValue, 201, true},
		{"env-create-201", profile.Environment, protocol.ActionCreateWithValue, 201, true},
		{"repo-write-204", profile.Repository, protocol.ActionWriteValue, 204, true},
		{"org-write-204", profile.Organization, protocol.ActionWriteValue, 204, true},
		{"repo-write-201", profile.Repository, protocol.ActionWriteValue, 201, false},
		{"org-policy-204", profile.Organization, protocol.ActionUpdatePolicy, 204, true},
		{"repo-delete-204", profile.Repository, protocol.ActionDeleteOwned, 204, true},
		{"org-reserved-delete-204", profile.Organization, protocol.ActionDeleteReservedSlot, 204, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := box.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			policy := testPolicy(tc.scope)
			if tc.action >= protocol.ActionDeleteOwned {
				policy = profile.Policy{}
			}
			var payload []byte
			if tc.action == protocol.ActionCreateWithValue || tc.action == protocol.ActionWriteValue {
				payload = []byte("one private value")
			}
			command := testCommand(t, tc.scope, tc.action, policy, payload)
			target, err := parseCanonicalTarget(tc.scope, command.Target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			var reads, effects, bad atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 1 || !r.Close || r.GetBody != nil || r.URL.RawQuery != "" ||
					r.Header.Get("Authorization") != "Bearer github_pat_TEST" ||
					r.Header.Get("X-GitHub-Api-Version") != apiVersion ||
					r.Header.Get("Accept") != "application/vnd.github+json" {
					bad.Add(1)
					w.WriteHeader(400)
					return
				}
				switch {
				case r.Method == http.MethodGet && r.URL.EscapedPath() == target.KeyPath &&
					(tc.action == protocol.ActionCreateWithValue || tc.action == protocol.ActionWriteValue):
					reads.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "test-key", "key": base64.StdEncoding.EncodeToString(public[:])})
				case r.Method == http.MethodGet && r.URL.EscapedPath() == target.SecretPath &&
					tc.action == protocol.ActionUpdatePolicy:
					reads.Add(1)
					_, _ = io.WriteString(w, `{"name":"TOKEN","visibility":"selected","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","selected_repositories_url":"https://api.github.com/orgs/team/actions/secrets/TOKEN/repositories"}`)
				case (r.Method == http.MethodPut && (r.URL.EscapedPath() == target.SecretPath ||
					r.URL.EscapedPath() == target.PolicyPath)) ||
					(r.Method == http.MethodDelete && r.URL.EscapedPath() == target.SecretPath):
					effects.Add(1)
					wire, err := io.ReadAll(io.LimitReader(r.Body, maximumPutBodyBytes+1))
					if err != nil || len(wire) > maximumPutBodyBytes {
						bad.Add(1)
						w.WriteHeader(400)
						return
					}
					if len(payload) != 0 && r.Method == http.MethodPut {
						var body struct {
							EncryptedValue string   `json:"encrypted_value"`
							KeyID          string   `json:"key_id"`
							Visibility     string   `json:"visibility"`
							Selected       []uint64 `json:"selected_repository_ids"`
						}
						if json.Unmarshal(wire, &body) != nil || body.KeyID != "test-key" {
							bad.Add(1)
						} else {
							sealed, decodeErr := base64.StdEncoding.Strict().DecodeString(body.EncryptedValue)
							plain, ok := box.OpenAnonymous(nil, sealed, public, private)
							if decodeErr != nil || !ok || !bytes.Equal(plain, payload) {
								bad.Add(1)
							}
							if tc.scope == profile.Organization && (body.Visibility != "selected" ||
								len(body.Selected) != 2 || body.Selected[0] != 7 || body.Selected[1] != 11) {
								bad.Add(1)
							}
						}
					} else if tc.action == protocol.ActionUpdatePolicy {
						if string(wire) != `{"selected_repository_ids":[7,11]}` {
							bad.Add(1)
						}
					} else if len(wire) != 0 {
						bad.Add(1)
					}
					w.WriteHeader(tc.status)
				default:
					bad.Add(1)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			implementation := testTransportImplementation(tc.scope, server.URL, server.Client().Transport)
			got, err := implementation.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
			wantClass := protocol.OutcomeClass(protocol.ClassUnproved)
			if tc.ack {
				wantClass = protocol.ClassAcknowledged
			}
			wantReads := int32(0)
			if tc.action == protocol.ActionCreateWithValue || tc.action == protocol.ActionWriteValue ||
				tc.action == protocol.ActionUpdatePolicy {
				wantReads = 1
			}
			if err != nil || got.Entry != protocol.EntryMayHaveEntered || got.Class != wantClass ||
				reads.Load() != wantReads || effects.Load() != 1 || bad.Load() != 0 {
				t.Fatalf("result=%#v err=%v reads=%d effects=%d bad=%d", got, err,
					reads.Load(), effects.Load(), bad.Load())
			}
		})
	}
	t.Run("response_bodies", func(t *testing.T) {
		public, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyBody, err := json.Marshal(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(public[:])})
		if err != nil {
			t.Fatal(err)
		}
		for _, scope := range []struct {
			name  string
			value profile.Scope
		}{{"repository", profile.Repository}, {"organization", profile.Organization}, {"environment", profile.Environment}} {
			for _, action := range []struct {
				name   string
				value  protocol.Action
				status int
			}{
				{"create_201", protocol.ActionCreateWithValue, http.StatusCreated},
				{"create_204", protocol.ActionCreateWithValue, http.StatusNoContent},
				{"write_204", protocol.ActionWriteValue, http.StatusNoContent},
				{"write_201", protocol.ActionWriteValue, http.StatusCreated},
				{"delete_owned_204", protocol.ActionDeleteOwned, http.StatusNoContent},
				{"delete_reserved_204", protocol.ActionDeleteReservedSlot, http.StatusNoContent},
				{"policy_204", protocol.ActionUpdatePolicy, http.StatusNoContent},
			} {
				if action.value == protocol.ActionUpdatePolicy && scope.value != profile.Organization {
					continue
				}
				for _, reply := range []struct {
					name              string
					body              string
					createAccepted    bool
					readErr, closeErr bool
				}{
					{name: "zero_bytes", createAccepted: true},
					{name: "empty_object", body: `{}`, createAccepted: true},
					{name: "json_whitespace", body: " \t\r\n{ \t\r\n}\r\n\t ", createAccepted: true},
					{name: "empty_object_4096", body: "{" + strings.Repeat(" ", 4094) + "}", createAccepted: true},
					{name: "empty_object_4097", body: "{" + strings.Repeat(" ", 4095) + "}"},
					{name: "nonempty_object", body: `{"name":"TOKEN"}`},
					{name: "nonempty_object_4096", body: `{"x":0}` + strings.Repeat(" ", 4089)},
					{name: "null", body: `null`},
					{name: "array", body: `[]`},
					{name: "string", body: `""`},
					{name: "number", body: `0`},
					{name: "boolean", body: `true`},
					{name: "whitespace_only", body: " \t\r\n"},
					{name: "whitespace_only_4096", body: strings.Repeat(" ", 4096)},
					{name: "incomplete_object", body: `{`},
					{name: "malformed_object", body: `{,}`},
					{name: "trailing_object", body: `{} {}`},
					{name: "trailing_null", body: `{} null`},
					{name: "trailing_garbage", body: `{}x`},
					{name: "leading_garbage", body: `x{}`},
					{name: "non_json_whitespace", body: "\v{}"},
					{name: "unicode_whitespace", body: "\u00a0{}"},
					{name: "bom", body: "\ufeff{}"},
					{name: "read_error_empty", readErr: true},
					{name: "read_error_object", body: `{}`, readErr: true},
					{name: "close_error_empty", closeErr: true},
					{name: "close_error_object", body: `{}`, closeErr: true},
				} {
					if (action.value != protocol.ActionCreateWithValue || action.status != http.StatusCreated) &&
						reply.name != "zero_bytes" && reply.name != "empty_object" {
						continue
					}
					t.Run(scope.name+"/"+action.name+"/"+reply.name, func(t *testing.T) {
						policy := testPolicy(scope.value)
						if action.value >= protocol.ActionDeleteOwned {
							policy = profile.Policy{}
						}
						var payload []byte
						if action.value == protocol.ActionCreateWithValue || action.value == protocol.ActionWriteValue {
							payload = []byte("private value")
						}
						command := testCommand(t, scope.value, action.value, policy, payload)
						target, err := parseCanonicalTarget(scope.value, command.Target.CanonicalTarget)
						if err != nil {
							t.Fatal(err)
						}
						body := &effectTestBody{Reader: strings.NewReader(reply.body), readErr: reply.readErr, closeErr: reply.closeErr}
						reads, effects := 0, 0
						transport := closeTestTransport(func(req *http.Request) (*http.Response, error) {
							if req.Method == http.MethodGet {
								reads++
								readBody := keyBody
								wantPath := target.KeyPath
								if action.value == protocol.ActionUpdatePolicy {
									wantPath = target.SecretPath
									readBody = []byte(`{"name":"TOKEN","visibility":"selected"}`)
								}
								if req.URL.EscapedPath() != wantPath {
									t.Errorf("read path=%q want=%q", req.URL.EscapedPath(), wantPath)
								}
								return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(readBody)),
									Header: make(http.Header), Request: req}, nil
							}
							effects++
							wantMethod, wantPath := http.MethodPut, target.SecretPath
							if action.value == protocol.ActionUpdatePolicy {
								wantPath = target.PolicyPath
							} else if action.value >= protocol.ActionDeleteOwned {
								wantMethod = http.MethodDelete
							}
							if req.Method != wantMethod || req.URL.EscapedPath() != wantPath {
								t.Errorf("effect=%s %q want=%s %q", req.Method, req.URL.EscapedPath(), wantMethod, wantPath)
							}
							if req.Body != nil {
								if _, err := io.Copy(io.Discard, req.Body); err != nil {
									t.Fatal(err)
								}
							}
							return &http.Response{StatusCode: action.status, Body: body, Header: make(http.Header), Request: req}, nil
						})
						implementation := testTransportImplementation(scope.value, "https://api.github.test", transport)
						got, err := implementation.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
						want := protocol.Result{Schema: 1, DomainID: command.DomainID, OperationID: command.OperationID,
							AttemptID: command.AttemptID, CoordinateID: command.CoordinateID,
							ProjectionCommitment: command.ProjectionCommitment, DispatchContextDigest: command.DispatchContextDigest,
							ResponseContractDigest: command.ResponseContractDigest, Entry: protocol.EntryMayHaveEntered,
							Class: protocol.ClassUnproved}
						accepted := !reply.readErr && !reply.closeErr && (action.value == protocol.ActionCreateWithValue &&
							action.status == http.StatusCreated && reply.createAccepted || action.value != protocol.ActionCreateWithValue &&
							action.status == http.StatusNoContent && reply.body == "")
						if accepted {
							want.Class, want.NormalizedStatus, want.SafeResourceID = protocol.ClassAcknowledged, uint16(action.status), command.Target.CanonicalTarget
							if command.Action == protocol.ActionCreateWithValue {
								want.ConsumerLocator = testCoordinate(scope.value)
							}
						}
						wantReads := 0
						if action.value < protocol.ActionDeleteOwned {
							wantReads = 1
						}
						if err != nil || got != want || reads != wantReads || effects != 1 || body.closes != 1 || body.bytesRead != len(reply.body) {
							t.Fatalf("result=%#v want=%#v err=%v reads=%d effects=%d closes=%d bytes=%d",
								got, want, err, reads, effects, body.closes, body.bytesRead)
						}
					})
				}
			}
		}
	})
}

// full_only: false
func TestGitHubValueAndPolicyBodyLimits(t *testing.T) {
	ids := make([]uint64, profile.MaximumSelectedRepositories)
	for n := range ids {
		ids[n] = uint64(n + 1)
	}
	policy := profile.Policy{ClassID: orgPolicyClass, Mode: profile.PolicyExplicitSet,
		SubjectKind: profile.SubjectNumber, NumberSubjects: ids}
	command := testCommand(t, profile.Organization, protocol.ActionCreateWithValue, policy, nil)
	if _, err := testImplementation(profile.Organization).CheckAction(context.Background(), actionForTest(command.ActionCheck()), publicPolicyForTest(policy)); err != nil {
		t.Fatalf("65,535 selected IDs refused: %v", err)
	}
	sealed := bytes.Repeat([]byte{0x5a}, MaximumRawValueBytes+box.AnonymousOverhead)
	// Canonical settings stay small while the opaque policy reaches its own maximum.
	wire, err := profile.PublicPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	destination := protocol.Destination{ConfigContractID: profile.ConfigContractID(profile.Organization), ServiceContractID: profile.ServiceContractID, CanonicalSettings: []byte(`{"owner":"owner"}`), Policy: wire, Capabilities: actions(profile.Organization)}
	if err := testImplementation(profile.Organization).ValidateCanonical(t.Context(), destination); err != nil || len(wire.Data) != 524285 {
		t.Fatal("complete canonical policy", err, len(wire.Data))
	}
	body, err := valueBody(sealed, "key", policy, profile.Organization)
	if err != nil || len(body) > maximumPutBodyBytes {
		t.Fatalf("complete value body bytes=%d err=%v", len(body), err)
	}
	var decoded struct {
		Selected []uint64 `json:"selected_repository_ids"`
	}
	if json.Unmarshal(body, &decoded) != nil || len(decoded.Selected) != len(ids) ||
		decoded.Selected[0] != 1 || decoded.Selected[len(decoded.Selected)-1] != uint64(len(ids)) {
		t.Fatal("complete selected policy body changed")
	}
	clear(body)
	body, err = selectedPolicyBody(ids)
	if err != nil || len(body) > maximumPutBodyBytes {
		t.Fatalf("complete policy-only body bytes=%d err=%v", len(body), err)
	}
	clear(body)
	if !credential.Valid(bytes.Repeat([]byte{'A'}, protocol.MaximumCredentialBytes-36)) ||
		credential.Valid(bytes.Repeat([]byte{'A'}, protocol.MaximumCredentialBytes-35)) ||
		credential.Valid([]byte("bad\r\nheader")) {
		t.Fatal("credential grammar/bound changed")
	}
}

// full_only: false
func TestGitHubOrganizationWholeVisibilityValueBodies(t *testing.T) {
	sealed := bytes.Repeat([]byte{0x5a}, box.AnonymousOverhead)
	for _, tc := range []struct {
		mode       uint8
		visibility string
	}{{profile.PolicyWholeScope, "all"}, {profile.PolicyRestrictedScope, "private"}} {
		policy := profile.Policy{ClassID: orgPolicyClass, Mode: tc.mode, SubjectKind: profile.SubjectNone}
		body, err := valueBody(sealed, "key", policy, profile.Organization)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil || len(fields) != 3 ||
			string(fields["visibility"]) != strconv.Quote(tc.visibility) ||
			fields["selected_repository_ids"] != nil {
			t.Fatalf("whole visibility body changed: %s", body)
		}
		clear(body)
	}
}

// full_only: false
func TestGitHubTransportExactBodyBoundAndFirstOver(t *testing.T) {
	for _, size := range []int{maximumPutBodyBytes, maximumPutBodyBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			calls := 0
			guard := &operationTransport{endpoint: "https://api.github.test", bearer: "Bearer token",
				effectPath: "/repos/owner/repo/actions/secrets/TOKEN", effectMethod: http.MethodPut,
				base: closeTestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					read, err := io.ReadAll(io.LimitReader(req.Body, maximumPutBodyBytes+1))
					if err != nil || len(read) != size {
						t.Errorf("request changed after guard: size=%d err=%v", len(read), err)
					}
					return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")),
						Header: make(http.Header), Request: req}, nil
				})}
			req, err := request(context.Background(), http.MethodPut,
				"https://api.github.test/repos/owner/repo/actions/secrets/TOKEN", []byte("token"),
				bytes.Repeat([]byte{'x'}, size))
			if err != nil {
				t.Fatal(err)
			}
			reply, err := guard.RoundTrip(req)
			if size == maximumPutBodyBytes {
				if err != nil || reply == nil || calls != 1 || !guard.didEnter() {
					t.Fatalf("exact body refused: reply=%v err=%v calls=%d entered=%v",
						reply != nil, err, calls, guard.didEnter())
				}
				if err := reply.Body.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || reply != nil || calls != 0 || guard.didEnter() {
				t.Fatalf("first-over body admitted: reply=%v err=%v calls=%d entered=%v",
					reply != nil, err, calls, guard.didEnter())
			}
		})
	}
}

// full_only: false
func TestGitHubCancellationAfterEffectDoesNotReplayOrReuse(t *testing.T) {
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target, err := parseCanonicalTarget(profile.Repository, testCoordinate(profile.Repository))
	if err != nil {
		t.Fatal(err)
	}
	var reads, effects atomic.Int32
	var readAddress, effectAddress string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.EscapedPath() == target.KeyPath:
			reads.Add(1)
			readAddress = r.RemoteAddr
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "key",
				"key": base64.StdEncoding.EncodeToString(public[:])})
		case r.Method == http.MethodPut && r.URL.EscapedPath() == target.SecretPath:
			effects.Add(1)
			effectAddress = r.RemoteAddr
			_, _ = io.Copy(io.Discard, r.Body)
			cancel() // The one effect request has entered.
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()
	implementation := testImplementation(profile.Repository)
	implementation.endpoint = server.URL
	transport, ok := implementation.transport.(*http.Transport)
	if !ok || !transport.DisableKeepAlives || transport.Proxy != nil {
		t.Fatal("production transport may reuse or proxy output requests")
	}
	defer transport.CloseIdleConnections()
	payload := []byte("private")
	policy := testPolicy(profile.Repository)
	command := testCommand(t, profile.Repository, protocol.ActionCreateWithValue, policy, payload)
	got, err := implementation.executeForTest(ctx, command, policy, payload, []byte("github_pat_TEST"))
	if err != nil || got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved ||
		reads.Load() != 1 || effects.Load() != 1 || readAddress == "" || effectAddress == "" ||
		readAddress == effectAddress {
		t.Fatalf("cancel result=%#v err=%v reads=%d effects=%d addresses=%q/%q",
			got, err, reads.Load(), effects.Load(), readAddress, effectAddress)
	}
}

// full_only: false
func TestGitHubZeroValueSealedAndFirstOverRefused(t *testing.T) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, MaximumRawValueBytes, MaximumRawValueBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var reads, effects atomic.Int32
			payload := bytes.Repeat([]byte{'x'}, size)
			policy := testPolicy(profile.Repository)
			command := testCommand(t, profile.Repository, protocol.ActionCreateWithValue, policy, nil)
			command.PayloadLength = uint32(len(payload))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					reads.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(public[:])})
					return
				}
				effects.Add(1)
				var body struct {
					EncryptedValue string `json:"encrypted_value"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("value request malformed")
					w.WriteHeader(400)
					return
				}
				sealed, err := base64.StdEncoding.Strict().DecodeString(body.EncryptedValue)
				opened, ok := box.OpenAnonymous(nil, sealed, public, private)
				if err != nil || !ok || !bytes.Equal(opened, payload) ||
					len(sealed) != size+box.AnonymousOverhead {
					t.Error("value request did not hold exactly one sealed entry")
					w.WriteHeader(400)
					return
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()
			implementation := testTransportImplementation(profile.Repository, server.URL, server.Client().Transport)
			got, err := implementation.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
			if size > MaximumRawValueBytes {
				if err == nil || got != (protocol.Result{}) || reads.Load() != 0 || effects.Load() != 0 {
					t.Fatalf("first-over value entered: result=%#v err=%v reads=%d effects=%d",
						got, err, reads.Load(), effects.Load())
				}
			} else if err != nil || got.Class != protocol.ClassAcknowledged ||
				reads.Load() != 1 || effects.Load() != 1 {
				t.Fatalf("bounded value result=%#v err=%v reads=%d effects=%d",
					got, err, reads.Load(), effects.Load())
			}
		})
	}
}

type closeErrorBody struct{ io.Reader }

func (closeErrorBody) Close() error { return errors.New("private response close failure") }

type effectTestBody struct {
	io.Reader
	readErr, closeErr bool
	closes, bytesRead int
}

func (b *effectTestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytesRead += n
	if err == io.EOF && b.readErr {
		err = errors.New("private response read failure")
	}
	return n, err
}

func (b *effectTestBody) Close() error {
	b.closes++
	if b.closeErr {
		return errors.New("private response close failure")
	}
	return nil
}

type closeTestTransport func(*http.Request) (*http.Response, error)

func (f closeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// full_only: false
func TestGitHubResponseCloseFailurePreservesEntry(t *testing.T) {
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBody, err := json.Marshal(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(public[:])})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(profile.Repository)
	payload := []byte("private value")
	command := testCommand(t, profile.Repository, protocol.ActionCreateWithValue, policy, payload)
	for _, failAt := range []string{"GET", "PUT"} {
		t.Run(failAt, func(t *testing.T) {
			gets, puts := 0, 0
			transport := closeTestTransport(func(req *http.Request) (*http.Response, error) {
				var body io.ReadCloser
				status := http.StatusOK
				if req.Method == http.MethodGet {
					gets++
					body = io.NopCloser(bytes.NewReader(keyBody))
					if failAt == "GET" {
						body = closeErrorBody{Reader: bytes.NewReader(keyBody)}
					}
				} else {
					puts++
					status = http.StatusCreated
					body = closeErrorBody{Reader: strings.NewReader("")}
				}
				return &http.Response{StatusCode: status, Body: body, Header: make(http.Header), Request: req}, nil
			})
			implementation := testTransportImplementation(profile.Repository, "https://api.github.test", transport)
			got, err := implementation.executeForTest(context.Background(), command, policy, payload, []byte("github_pat_TEST"))
			if err != nil || gets != 1 || failAt == "GET" && (puts != 0 || got.Entry != protocol.EntryNotEntered) ||
				failAt == "PUT" && (puts != 1 || got.Entry != protocol.EntryMayHaveEntered ||
					got.Class != protocol.ClassUnproved) {
				t.Fatalf("close result=%#v err=%v GET=%d PUT=%d", got, err, gets, puts)
			}
		})
	}
}

// full_only: false
func TestGitHubPreparationResponsesAreUnambiguous(t *testing.T) {
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(public[:])
	validKey := `{"key_id":"test-key","key":"` + key + `"}`
	validMetadata := `{"name":"TOKEN","visibility":"selected"}`
	type preparation struct {
		name     string
		scope    profile.Scope
		action   protocol.Action
		body     string
		accepted bool
	}
	cases := []preparation{
		{"metadata-duplicate-name", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"OTHER","name":"TOKEN","visibility":"selected"}`, false},
		{"metadata-duplicate-visibility", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"TOKEN","visibility":"all","visibility":"selected"}`, false},
		{"metadata-null-name", profile.Organization, protocol.ActionUpdatePolicy, validMetadata[:len(validMetadata)-1] + `,"name":null}`, false},
		{"metadata-null-visibility", profile.Organization, protocol.ActionUpdatePolicy, validMetadata[:len(validMetadata)-1] + `,"visibility":null}`, false},
		{"metadata-case-alias", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"OTHER","Name":"TOKEN","visibility":"selected"}`, false},
		{"metadata-alias-only", profile.Organization, protocol.ActionUpdatePolicy, `{"Name":"TOKEN","visibility":"selected"}`, false},
		{"metadata-unicode-alias", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"TOKEN","visibility":"all","viſibility":"selected"}`, false},
		{"metadata-null-only", profile.Organization, protocol.ActionUpdatePolicy, `{"name":null,"visibility":"selected"}`, false},
		{"metadata-wrong-type", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"TOKEN","visibility":[]}`, false},
		{"metadata-missing-visibility", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"TOKEN"}`, false},
		{"metadata-array", profile.Organization, protocol.ActionUpdatePolicy, `[` + validMetadata + `]`, false},
		{"metadata-trailing-object", profile.Organization, protocol.ActionUpdatePolicy, validMetadata + `{}`, false},
		{"metadata-invalid-utf8-extra", profile.Organization, protocol.ActionUpdatePolicy, validMetadata[:len(validMetadata)-1] + ",\"extra\":\"\xff\"}", false},
		{"metadata-documentation-extras", profile.Organization, protocol.ActionUpdatePolicy, `{"name":"TOKEN","created_at":"2019-08-10T14:59:22Z","updated_at":"2020-01-10T14:59:22Z","visibility":"selected","selected_repositories_url":"https://api.github.com/orgs/owner/actions/secrets/TOKEN/repositories"}`, true},
		{"metadata-exact-bound", profile.Organization, protocol.ActionUpdatePolicy, validMetadata + strings.Repeat(" ", maximumReadResponseBytes-len(validMetadata)), true},
		{"metadata-first-over", profile.Organization, protocol.ActionUpdatePolicy, validMetadata + strings.Repeat(" ", maximumReadResponseBytes+1-len(validMetadata)), false},
		{"key-null-after-valid", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"key":null}`, false},
		{"key-id-duplicate", profile.Repository, protocol.ActionCreateWithValue, `{"key_id":"first","key_id":"test-key","key":"` + key + `"}`, false},
		{"key-id-null-after-valid", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"key_id":null}`, false},
		{"key-case-alias", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"Key":null}`, false},
		{"key-alias-only", profile.Repository, protocol.ActionCreateWithValue, `{"key_id":"test-key","Key":"` + key + `"}`, false},
		{"key-unicode-alias", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"Key":null}`, false},
		{"key-escaped-duplicate", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"\u006bey":null}`, false},
		{"key-null-only", profile.Repository, protocol.ActionCreateWithValue, `{"key_id":"test-key","key":null}`, false},
		{"key-wrong-type", profile.Repository, protocol.ActionCreateWithValue, `{"key_id":7,"key":"` + key + `"}`, false},
		{"key-missing-id", profile.Repository, protocol.ActionCreateWithValue, `{"key":"` + key + `"}`, false},
		{"key-unknown-field", profile.Repository, protocol.ActionCreateWithValue, validKey[:len(validKey)-1] + `,"extra":null}`, false},
		{"key-array", profile.Repository, protocol.ActionCreateWithValue, `[` + validKey + `]`, false},
		{"key-trailing-object", profile.Repository, protocol.ActionCreateWithValue, validKey + `{}`, false},
		{"key-exact-bound", profile.Repository, protocol.ActionCreateWithValue, validKey + strings.Repeat(" ", maximumReadResponseBytes-len(validKey)), true},
		{"key-first-over", profile.Repository, protocol.ActionCreateWithValue, validKey + strings.Repeat(" ", maximumReadResponseBytes+1-len(validKey)), false},
	}
	for _, scope := range []struct {
		name  string
		value profile.Scope
	}{{"repository", profile.Repository}, {"organization", profile.Organization}, {"environment", profile.Environment}} {
		for _, action := range []struct {
			name  string
			value protocol.Action
		}{{"create", protocol.ActionCreateWithValue}, {"write", protocol.ActionWriteValue}} {
			cases = append(cases,
				preparation{scope.name + "-" + action.name + "-malformed-key", scope.value, action.value, validKey[:len(validKey)-1] + `,"key":null}`, false},
				preparation{scope.name + "-" + action.name + "-valid-key", scope.value, action.value, validKey, true})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := testPolicy(tc.scope)
			var payload []byte
			if tc.action != protocol.ActionUpdatePolicy {
				payload = []byte("private value")
			}
			command := testCommand(t, tc.scope, tc.action, policy, payload)
			target, err := parseCanonicalTarget(tc.scope, command.Target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			readPath, effectPath := target.KeyPath, target.SecretPath
			if tc.action == protocol.ActionUpdatePolicy {
				readPath, effectPath = target.SecretPath, target.PolicyPath
			}
			status := http.StatusNoContent
			if tc.action == protocol.ActionCreateWithValue {
				status = http.StatusCreated
			}
			var reads, effects atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.EscapedPath() == readPath {
					reads.Add(1)
					_, _ = io.WriteString(w, tc.body)
					return
				}
				effects.Add(1)
				if r.Method != http.MethodPut || r.URL.EscapedPath() != effectPath {
					t.Errorf("unexpected effect method=%s path=%q", r.Method, r.URL.EscapedPath())
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(status)
			}))
			defer server.Close()
			implementation := testTransportImplementation(tc.scope, server.URL, server.Client().Transport)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			got, err := implementation.executeForTest(ctx, command, policy, payload, []byte("github_pat_TEST"))
			want := protocol.Result{Schema: 1, DomainID: command.DomainID, OperationID: command.OperationID,
				AttemptID: command.AttemptID, CoordinateID: command.CoordinateID,
				ProjectionCommitment: command.ProjectionCommitment, DispatchContextDigest: command.DispatchContextDigest,
				ResponseContractDigest: command.ResponseContractDigest, Entry: protocol.EntryNotEntered,
				Class: protocol.ClassQualifiedNoEffect}
			wantEffects := int32(0)
			if tc.accepted {
				want.Entry, want.Class, want.NormalizedStatus, want.SafeResourceID =
					protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, uint16(status), command.Target.CanonicalTarget
				if command.Action == protocol.ActionCreateWithValue {
					want.ConsumerLocator = testCoordinate(tc.scope)
				}
				wantEffects = 1
			}
			if err != nil || got != want || reads.Load() != 1 || effects.Load() != wantEffects {
				t.Fatalf("result=%#v want=%#v err=%v GET=%d PUT=%d wantPUT=%d", got, want, err, reads.Load(), effects.Load(), wantEffects)
			}
		})
	}
}

// full_only: false
func TestGitHubSealedBoxIndependentLibsodiumVector(t *testing.T) {
	// libsodium 1.0.22: crypto_box_seed_keypair(seed=00..1f), then
	// crypto_scalarmult_base(ephemeral=20..3f), BLAKE2b-192(epk||pk),
	// crypto_box_easy, and epk||box. This fixture is built outside Go.
	decode := func(s string) []byte {
		t.Helper()
		v, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	publicBytes := decode("4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01")
	privateBytes := decode("3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f")
	message := decode("454e4b56206c6962736f6469756d20763100ff")
	want := decode("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254fb3bab6ff0f0f27543c33b42577352a7678a574ea3ed22bcc116e9957812925751b07a")
	random := decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	var public, private [32]byte
	copy(public[:], publicBytes)
	copy(private[:], privateBytes)
	got, err := box.SealAnonymous(nil, message, &public, bytes.NewReader(random))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("libsodium sealed-box vector differs: error=%v", err)
	}
	opened, ok := box.OpenAnonymous(nil, want, &public, &private)
	if !ok || !bytes.Equal(opened, message) {
		t.Fatal("libsodium sealed-box vector did not open")
	}
}

// full_only: false
func TestGitHubNoSendDoesNotGrantASecondSend(t *testing.T) {
	var sends atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sends.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	i := testTransportImplementation(profile.Repository, server.URL, server.Client().Transport)
	command := testCommand(t, profile.Repository, protocol.ActionDeleteOwned, testPolicy(profile.Repository), nil)
	owned, err := i.Prepare(t.Context(), preparationForTest(command), protocol.Policy{}, []credentialroute.Input{{Name: "GITHUB_TOKEN", Present: true, Value: []byte("github_pat_TEST")}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owned.Close(); err != nil {
			t.Error(err)
		}
	}()
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := owned.Send(stopped, nil); err != nil || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
		t.Fatal("original no-send evidence changed", got, err)
	}
	if _, err := owned.Send(t.Context(), nil); err == nil {
		t.Fatal("no-send permitted a second Send")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.Send(t.Context(), nil); err == nil {
		t.Fatal("closed operation permitted Send")
	}
	if sends.Load() != 0 {
		t.Fatal("refused callback made a physical request", sends.Load())
	}
}
