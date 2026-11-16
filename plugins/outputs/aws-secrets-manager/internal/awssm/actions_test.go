package awssm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

func actionCommand(t *testing.T, action protocol.Action) (protocol.Command, protocol.Policy, []byte) {
	t.Helper()
	payload := []byte("one selected value")
	command, policy := testCommand(t, payload)
	command.Action = action
	if action != protocol.ActionWriteValue {
		command.ValueBasisDigest = protocol.ID{}
		command.PayloadLengthMode = protocol.LengthAbsent
		command.PayloadLength = 0
		payload = nil
	}
	if action == protocol.ActionCreateEmpty || action == protocol.ActionDeleteReservedSlot {
		command.OwnedInstance = ""
		command.OwnedBirthAttemptID = protocol.ID{}
		command.BirthTargetRowDigest = protocol.ID{}
	}
	if action == protocol.ActionDeleteReservedSlot {
		command.UncertainCreateAttemptID = testID("uncertain-create")
		command.ExclusiveNamespaceDigest = testID("exclusive-namespace")
	}
	if action >= protocol.ActionDeleteOwned {
		policy = protocol.Policy{}
		command.PolicyDigest = protocol.ID{}
	}
	if err := protocol.ValidatePolicy(command, policy); err != nil {
		t.Fatalf("test action %d is not a valid wire request: %v", action, err)
	}
	return command, policy, payload
}

// full_only: false
func TestAWSOutputV2OneRequestPerAction(t *testing.T) {
	for _, tc := range []struct {
		name, operation, secretID, safeID string
		action                            protocol.Action
	}{
		{"create-empty", "CreateSecret", "", testARN, protocol.ActionCreateEmpty},
		{"write-value", "PutSecretValue", testARN, "", protocol.ActionWriteValue},
		{"delete-owned", "DeleteSecret", testARN, testARN, protocol.ActionDeleteOwned},
		{"delete-reserved", "DeleteSecret", "enkv-output", testARN, protocol.ActionDeleteReservedSlot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, policy, payload := actionCommand(t, tc.action)
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/" || r.Header.Get("X-Amz-Target") != "secretsmanager."+tc.operation {
					t.Errorf("request method, path or operation differed")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("request JSON: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if tc.secretID == "" {
					var name, token string
					_ = json.Unmarshal(body["Name"], &name)
					_ = json.Unmarshal(body["ClientRequestToken"], &token)
					if name != "enkv-output" || token != hex.EncodeToString(command.AttemptID[:]) || len(body) != 2 {
						t.Error("create must contain exact Name and one attempt token, without a value")
					}
				} else {
					var secretID string
					_ = json.Unmarshal(body["SecretId"], &secretID)
					if secretID != tc.secretID {
						t.Errorf("SecretId=%q, want %q", secretID, tc.secretID)
					}
				}
				switch tc.action {
				case protocol.ActionCreateEmpty:
					_, _ = w.Write([]byte(`{"ARN":"` + testARN + `","Name":"enkv-output"}`))
				case protocol.ActionWriteValue:
					_, _ = w.Write([]byte(`{"ARN":"` + testARN + `","Name":"enkv-output","VersionId":"` + hex.EncodeToString(command.AttemptID[:]) + `","VersionStages":["AWSCURRENT"]}`))
				default:
					var days int
					_ = json.Unmarshal(body["RecoveryWindowInDays"], &days)
					if days != 7 || len(body) != 2 {
						t.Error("delete must schedule a seven-day window and no other operation")
					}
					_, _ = w.Write([]byte(`{"ARN":"` + testARN + `","Name":"enkv-output","DeletionDate":1790467200}`))
				}
			}))
			defer server.Close()
			result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential(""))
			safeID := tc.safeID
			if tc.action == protocol.ActionWriteValue {
				safeID = hex.EncodeToString(command.AttemptID[:])
			}
			if err != nil || posts != 1 || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged || result.SafeResourceID != safeID {
				t.Fatalf("action=%d result=%#v err=%v requests=%d", tc.action, result, err, posts)
			}
		})
	}
}

// full_only: false
func TestAWSOutputV2PassiveActionBounds(t *testing.T) {
	implementation := testPublicImplementation(t)
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionWriteValue, protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		command, policy, _ := actionCommand(t, action)
		request := command.ActionCheck()
		request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
		bounds, err := implementation.CheckAction(t.Context(), actionForTest(request), policy)
		want := protocol.PayloadBounds{}
		if action == protocol.ActionWriteValue {
			want = command.Target.WriteValueBounds
		}
		if err != nil || bounds != want {
			t.Fatal("action bounds", action, bounds, err)
		}
		request.ConditionalTokenLength = 1
		if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err == nil {
			t.Fatal("caller conditional token accepted")
		}
	}
	command, policy := testCommand(t, []byte("value"))
	command.Action = protocol.ActionCreateWithValue
	command.OwnedInstance = ""
	command.OwnedBirthAttemptID = protocol.ID{}
	command.BirthTargetRowDigest = protocol.ID{}
	if _, err := implementation.CheckAction(t.Context(), actionForTest(command.ActionCheck()), policy); err == nil {
		t.Fatal("unsupported create-with-value accepted")
	}
}

// full_only: false
func TestAWSOutputV2UncertainEntryNeverQualifiesOwnershipOrDeletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action protocol.Action
		status int
		body   string
	}{
		{"create-conflict", protocol.ActionCreateEmpty, http.StatusBadRequest, `{"__type":"ResourceExistsException"}`},
		{"create-mismatched-name", protocol.ActionCreateEmpty, http.StatusOK, `{"ARN":"` + testARN + `","Name":"other"}`},
		{"create-mismatched-arn", protocol.ActionCreateEmpty, http.StatusOK, `{"ARN":"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:other-AbCd12","Name":"enkv-output"}`},
		{"create-overlong-reply", protocol.ActionCreateEmpty, http.StatusOK, strings.Repeat(" ", maximumReplyBytes+1)},
		{"write-mismatched-arn", protocol.ActionWriteValue, http.StatusOK, `{"ARN":"wrong"}`},
		{"write-trailing-response", protocol.ActionWriteValue, http.StatusOK, `{"ARN":"` + testARN + `","Name":"enkv-output","VersionId":"c7ce66d0fb14e3c2d4d920918cc6cc7e488668b08dddeb7b85e44de3b9f3eb01","VersionStages":["AWSCURRENT"]}{}`},
		{"delete-missing-date", protocol.ActionDeleteOwned, http.StatusOK, `{"ARN":"` + testARN + `","Name":"enkv-output"}`},
		{"reserved-delete-foreign-slot", protocol.ActionDeleteReservedSlot, http.StatusOK, `{"ARN":"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:other-AbCd12","Name":"other","DeletionDate":1790467200}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, policy, payload := actionCommand(t, tc.action)
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential(""))
			if err != nil || posts != 1 || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved || result.SafeResourceID != "" {
				t.Fatalf("result=%#v err=%v requests=%d", result, err, posts)
			}
		})
	}
}

// full_only: false
func TestPolicyActionSelectionRefusesUnsupportedPolicy(t *testing.T) {
	action, err := (Implementation{}).SelectPolicyAction(t.Context(), output.PolicyActionSelection{DomainID: protocol.ID{1}}, protocol.Policy{ContractID: "unsupported-policy", Data: []byte("policy")})
	if err == nil || action != 0 {
		t.Fatal("unsupported policy selected an action", action, err)
	}
}
