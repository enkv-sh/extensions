package awssm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

func identityResponse(req *http.Request, account string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
		Body: io.NopCloser(strings.NewReader(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::` + account + `:user/test</Arn><UserId>test-user</UserId><Account>` + account + `</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>`))}
}

// full_only: false
func TestAWSFullARNActionsAllowCrossAccountWithoutQualification(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionDeleteOwned} {
		t.Run(map[protocol.Action]string{protocol.ActionWriteValue: "write", protocol.ActionDeleteOwned: "owned-delete"}[action], func(t *testing.T) {
			command, policy, payload := actionCommand(t, action)
			calls := 0
			i := New()
			i.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				defer func() {
					if err := req.Body.Close(); err != nil {
						t.Error("close request body", err)
					}
				}()
				if req.URL.Host != "secretsmanager.ap-southeast-2.amazonaws.com" || req.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
					t.Error("full-ARN action attempted account qualification")
				}
				body := `{"ARN":"` + testARN + `","Name":"enkv-output","DeletionDate":1790467200}`
				if action == protocol.ActionWriteValue {
					body = `{"ARN":"` + testARN + `","Name":"enkv-output","VersionId":"` + hex.EncodeToString(command.AttemptID[:]) + `","VersionStages":["AWSCURRENT"]}`
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			got, err := i.execute(context.Background(), command, policy, payload, testCredential("foreign-account-session"))
			if err != nil || calls != 1 || got.Class != protocol.ClassAcknowledged {
				t.Fatalf("full-ARN action result=%#v err=%v calls=%d", got, err, calls)
			}
		})
	}
}

// full_only: false
func TestAWSNameScopedQualificationBindsSnapshotAndRefusesFailure(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionDeleteReservedSlot} {
		for _, outcome := range []string{"qualified", "denied", "malformed", "over-bound", "duplicate-account", "duplicate-result", "cancelled"} {
			t.Run(map[protocol.Action]string{protocol.ActionCreateEmpty: "create", protocol.ActionDeleteReservedSlot: "reserved-delete"}[action]+"/"+outcome, func(t *testing.T) {
				command, policy, payload := actionCommand(t, action)
				credentialBytes := testCredential("session-original")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				reads, mutations := 0, 0
				i := New()
				i.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					_ = req.Body.Close()
					if !strings.Contains(req.Header.Get("Authorization"), "Credential=AKIAEXAMPLEKEY00001/") || req.Header.Get("X-Amz-Security-Token") != "session-original" {
						t.Error("request did not use the captured credential snapshot")
					}
					if req.URL.Host == "sts.ap-southeast-2.amazonaws.com" {
						reads++
						clear(credentialBytes) // The caller's discovery storage changes after qualification starts.
						response := identityResponse(req, "123456789012")
						switch outcome {
						case "denied":
							response.StatusCode = http.StatusForbidden
						case "malformed":
							response.Body = io.NopCloser(strings.NewReader("not XML"))
						case "over-bound":
							response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maximumReplyBytes+1)))
						case "duplicate-account":
							response.Body = io.NopCloser(strings.NewReader(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>999999999999</Account><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`))
						case "duplicate-result":
							response.Body = io.NopCloser(strings.NewReader(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>999999999999</Account></GetCallerIdentityResult><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`))
						case "cancelled":
							cancel()
							return nil, context.Canceled
						}
						return response, nil
					}
					mutations++
					body := `{"ARN":"` + testARN + `","Name":"enkv-output"}`
					if action == protocol.ActionDeleteReservedSlot {
						body = `{"ARN":"` + testARN + `","Name":"enkv-output","DeletionDate":1790467200}`
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(body))}, nil
				})
				got, err := i.execute(ctx, command, policy, payload, credentialBytes)
				wantMutations, wantClass, wantEntry := 0, protocol.OutcomeClass(protocol.ClassQualifiedNoEffect), protocol.EntryState(protocol.EntryNotEntered)
				if outcome == "qualified" {
					wantMutations, wantClass, wantEntry = 1, protocol.ClassAcknowledged, protocol.EntryMayHaveEntered
				}
				if err != nil || reads != 1 || mutations != wantMutations || got.Class != wantClass || got.Entry != wantEntry {
					t.Fatalf("qualification result=%#v err=%v reads=%d mutations=%d", got, err, reads, mutations)
				}
			})
		}
	}
}

// full_only: false
func TestAWSOutputWireBodyCustodyOnResponseErrorAndCancellation(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		for _, outcome := range []string{"response", "error", "cancel"} {
			t.Run(encoding+"/"+outcome, func(t *testing.T) {
				payload, wirePayload := []byte{0, 1, 2, 255}, "AAEC/w=="
				if encoding == "base64" {
					payload, wirePayload = []byte("AAEC/w=="), "QUFFQy93PT0="
				}
				command, policy := testCommand(t, payload)
				command.Target.PayloadEncoding = testEncoding(encoding)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var owner io.ReadCloser
				readGate, closeGate, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
				readResult := make(chan struct {
					body []byte
					err  error
				}, 1)
				i := New()
				i.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					owner = req.Body
					go func() {
						<-readGate
						body, err := io.ReadAll(owner)
						readResult <- struct {
							body []byte
							err  error
						}{body, err}
						<-closeGate
						if err := owner.Close(); err != nil {
							t.Error(err)
						}
						close(joined)
					}()
					if outcome == "error" {
						return nil, errors.New("controlled transport failure")
					}
					if outcome == "cancel" {
						cancel()
						return nil, context.Canceled
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
						Body: io.NopCloser(strings.NewReader(`{"ARN":"` + testARN + `","Name":"enkv-output","VersionId":"` + hex.EncodeToString(command.AttemptID[:]) + `","VersionStages":["AWSCURRENT"]}`))}, nil
				})
				got, err := i.execute(ctx, command, policy, payload, testCredential(""))
				if owner == nil {
					t.Fatalf("request did not reach transport: result=%#v err=%v", got, err)
				}
				defer func() {
					select {
					case <-readGate:
					default:
						close(readGate)
					}
					select {
					case <-closeGate:
					default:
						close(closeGate)
					}
					select {
					case <-joined:
					case <-time.After(time.Second):
						t.Error("transport cleanup did not join")
					}
				}()
				wantClass := protocol.OutcomeClass(protocol.ClassAcknowledged)
				if outcome != "response" {
					wantClass = protocol.ClassUnproved
				}
				if err != nil || got.Class != wantClass || got.Entry != protocol.EntryMayHaveEntered {
					t.Fatalf("result=%#v err=%v", got, err)
				}
				clear(payload)
				close(readGate)
				var body []byte
				var readErr error
				select {
				case read := <-readResult:
					body, readErr = read.body, read.err
				case <-time.After(time.Second):
					t.Fatal("delayed transport reader did not settle")
				}
				want := `{"ClientRequestToken":"` + hex.EncodeToString(command.AttemptID[:]) + `","SecretBinary":"` + wirePayload + `","SecretId":"` + testARN + `","VersionStages":["AWSCURRENT"]}`
				if readErr != nil || string(body) != want {
					t.Fatalf("delayed body differs: read=%v bytes=%d", readErr, len(body))
				}
				close(closeGate)
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("delayed transport closer did not join")
				}
				if owner.Close() != nil {
					t.Fatal("repeated body Close failed")
				}
				if n, err := owner.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatal("closed body remained readable")
				}
			})
		}
	}
}

// full_only: false
func TestAWSCloudPolicyActionRefusesBeforeTransport(t *testing.T) {
	command, _, _ := actionCommand(t, protocol.ActionWriteValue)
	command.Action = protocol.ActionUpdatePolicy
	command.PayloadLengthMode, command.PayloadLength, command.ValueBasisDigest = protocol.LengthAbsent, 0, protocol.ID{}
	policy := protocol.Policy{ContractID: "aws-secrets-manager/get-secret-value", Data: testPolicyData([]string{"arn:aws:iam::123456789012:role/test-consumer"})}
	var digestErr error
	command.PolicyDigest, digestErr = protocol.PolicyDigest(command.DomainID, policy)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	command.PolicyContractID = policy.ContractID
	var payload []byte
	posts := 0
	implementation := New()
	implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
		posts++
		_ = req.Body.Close()
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
			Body: io.NopCloser(strings.NewReader(`{"ARN":"` + testARN + `","Name":"enkv-output"}`))}, nil
	})
	got, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
	if err != nil || posts != 0 || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
		t.Fatalf("cloud policy refusal: result=%#v err=%v mutation-sends=%d", got, err, posts)
	}
}

// full_only: false
func TestAWSNameScopedMutationRefusesWrongAccount(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionDeleteReservedSlot} {
		t.Run(map[protocol.Action]string{protocol.ActionCreateEmpty: "create", protocol.ActionDeleteReservedSlot: "reserved-delete"}[action], func(t *testing.T) {
			command, policy, payload := actionCommand(t, action)
			qualifications, mutations := 0, 0
			implementation := New()
			implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
				_ = req.Body.Close()
				body := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::999999999999:user/test</Arn><UserId>test-user</UserId><Account>999999999999</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>`
				if req.URL.Host == "sts.ap-southeast-2.amazonaws.com" {
					qualifications++
				} else {
					mutations++
					body = `{"ARN":"arn:aws:secretsmanager:ap-southeast-2:999999999999:secret:enkv-output-AbCd12","Name":"enkv-output","DeletionDate":1790467200}`
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
					Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			got, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
			if err != nil || qualifications != 1 || mutations != 0 || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
				t.Fatalf("wrong-account refusal: result=%#v err=%v qualification=%d mutation-sends=%d", got, err, qualifications, mutations)
			}
		})
	}
}

// full_only: false
func TestAWSDelayedRequestBodyReadAfterExecute(t *testing.T) {
	payload := []byte("private delayed transport payload")
	command, policy := testCommand(t, payload)
	var requestBody io.ReadCloser
	implementation := Implementation{signTime: time.Now, transport: closeTestTransport(func(req *http.Request) (*http.Response, error) {
		requestBody = req.Body
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
			Body: io.NopCloser(strings.NewReader(`{"ARN":"` + testARN + `","Name":"enkv-output","VersionId":"` + hex.EncodeToString(command.AttemptID[:]) + `","VersionStages":["AWSCURRENT"]}`))}, nil
	})}
	got, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
	if requestBody == nil {
		t.Fatalf("transport did not receive the body: result=%#v err=%v", got, err)
	}
	defer func() {
		if err := requestBody.Close(); err != nil {
			t.Error("close request body", err)
		}
	}()
	if err != nil || got.Class != protocol.ClassAcknowledged {
		t.Fatalf("Execute: result=%#v err=%v", got, err)
	}
	// Independently specified wire representation: the API's SecretBinary wraps
	// the application bytes in Base64; it does not change the selected encoding.
	want := []byte(`{"ClientRequestToken":"` + hex.EncodeToString(command.AttemptID[:]) + `","SecretBinary":"cHJpdmF0ZSBkZWxheWVkIHRyYW5zcG9ydCBwYXlsb2Fk","SecretId":"` + testARN + `","VersionStages":["AWSCURRENT"]}`)
	gotBody, readErr := io.ReadAll(requestBody)
	if readErr != nil || !bytes.Equal(gotBody, want) {
		t.Fatalf("delayed transport body changed: read=%v bytes=%d want=%d", readErr, len(gotBody), len(want))
	}
	if err := requestBody.Close(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestAWSLegacyCloudPolicyInputsRefuseValueRequests(t *testing.T) {
	for _, subjects := range [][]string{nil, {"arn:aws:iam::123456789012:role/test-consumer"}} {
		name := "empty"
		if len(subjects) != 0 {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			command, _, payload := actionCommand(t, protocol.ActionWriteValue)
			policy := protocol.Policy{ContractID: "aws-secrets-manager/get-secret-value", Data: testPolicyData(subjects)}
			var err error
			command.PolicyDigest, err = protocol.PolicyDigest(command.DomainID, policy)
			if err != nil {
				t.Fatal(err)
			}
			command.PolicyContractID = policy.ContractID
			calls := 0
			implementation := New()
			implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				_ = req.Body.Close()
				return nil, errors.New("cloud policy must refuse before provider request")
			})
			got, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
			if err != nil || calls != 0 || got.Entry != protocol.EntryNotEntered || got.Class != protocol.ClassQualifiedNoEffect {
				t.Fatalf("legacy policy admitted: result=%#v err=%v calls=%d", got, err, calls)
			}
		})
	}
}

// full_only: false
func TestAWSExecutionAccessDeniedNeverRepairsPermissions(t *testing.T) {
	for _, action := range []struct {
		name          string
		code          protocol.Action
		target        string
		qualification bool
	}{
		{"create", protocol.ActionCreateEmpty, "secretsmanager.CreateSecret", true},
		{"write", protocol.ActionWriteValue, "secretsmanager.PutSecretValue", false},
		{"owned-delete", protocol.ActionDeleteOwned, "secretsmanager.DeleteSecret", false},
		{"reserved-delete", protocol.ActionDeleteReservedSlot, "secretsmanager.DeleteSecret", true},
	} {
		for _, encoding := range []string{"raw", "base64"} {
			t.Run(action.name+"/"+encoding, func(t *testing.T) {
				command, policy, payload := actionCommand(t, action.code)
				command.Target.PayloadEncoding = testEncoding(encoding)
				if encoding == "base64" && action.code == protocol.ActionWriteValue {
					payload = []byte("b25lIGVudHJ5IHZhbHVl")
					command.PayloadLength = uint32(len(payload))
				}
				qualifications, effects, other := 0, 0, 0
				i := New()
				i.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					defer func() {
						if err := req.Body.Close(); err != nil {
							t.Error("close request body", err)
						}
					}()
					if req.URL.Host == "sts.ap-southeast-2.amazonaws.com" && action.qualification && qualifications == 0 && effects == 0 {
						qualifications++
						return identityResponse(req, "123456789012"), nil
					}
					if req.URL.Host != "secretsmanager.ap-southeast-2.amazonaws.com" || req.Method != http.MethodPost || req.Header.Get("X-Amz-Target") != action.target {
						other++
					}
					effects++
					return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}, Request: req,
						Body: io.NopCloser(strings.NewReader(`{"__type":"AccessDeniedException","message":"Execution access denied"}`))}, nil
				})
				got, err := i.execute(context.Background(), command, policy, payload, testCredential("denied-session"))
				wantQualifications := 0
				if action.qualification {
					wantQualifications = 1
				}
				if err != nil || qualifications != wantQualifications || effects != 1 || other != 0 || got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved || got.SafeResourceID != "" {
					t.Fatalf("access denial changed execution or repaired permissions: result=%#v err=%v qualifications=%d effects=%d other=%d", got, err, qualifications, effects, other)
				}
			})
		}
	}
}
