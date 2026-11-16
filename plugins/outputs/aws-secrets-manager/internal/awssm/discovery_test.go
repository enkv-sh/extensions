package awssm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	outputcredential "enkv.sh/plugins/outputs/aws-secrets-manager/credential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func awsCredentialEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "private-standard-secret")
}

// full_only: false
func TestDefaultOutputCapturesOneSDKSnapshot(t *testing.T) {
	awsCredentialEnvironment(t)
	source, err := loadCredentialSource(context.Background(), "us-east-1")
	if err != nil || source == nil {
		t.Fatal("standard output requires a credential file", err)
	}
	body, expiry, err := captureCredentialSource(context.Background(), source)
	defer clear(body)
	if err != nil || !expiry.IsZero() {
		t.Fatal("static standard source capture failed", err)
	}
	value, err := outputcredential.Decode(body, time.Now())
	if err != nil || string(value.AccessKeyID) != "AKIAAAAAAAAAAAAA" || string(value.SecretAccessKey) != "private-standard-secret" {
		t.Fatal("output snapshot differs", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if body, _, err := captureCredentialSource(ctx, source); err == nil || body != nil {
		t.Fatal("canceled capture returned credentials")
	}
}

// full_only: false
func TestStandardDiscoveryRejectsExpiredSnapshot(t *testing.T) {
	calls := 0
	source := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		calls++
		return aws.Credentials{AccessKeyID: "AKIAAAAAAAAAAAAA", SecretAccessKey: "secret", CanExpire: true, Expires: time.Now().Add(-time.Second)}, nil
	})
	if wire, _, err := captureCredentialSource(t.Context(), source); err == nil || wire != nil || calls != 1 {
		t.Fatal("expired capture accepted", err, calls)
	}
}

// full_only: false
func TestStandardDiscoveryInputsMatchAmbientWithoutMutation(t *testing.T) {
	t.Setenv("SELECTED_INPUT", "")
	i := Implementation{Binding: fixtureBinding(t, credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeSDK, Names: []string{"SELECTED_INPUT"}})}
	matching := []credentialroute.Input{{Name: "SELECTED_INPUT", Present: true, Value: []byte{}}}
	if err := i.checkEnvironment(matching); err != nil {
		t.Fatal("present empty input refused", err)
	}
	for _, input := range []credentialroute.Input{{Name: "SELECTED_INPUT"}, {Name: "SELECTED_INPUT", Present: true, Value: []byte("other")}} {
		if err := i.checkEnvironment([]credentialroute.Input{input}); err == nil {
			t.Fatal("mismatched route input accepted")
		}
		if value, present := os.LookupEnv("SELECTED_INPUT"); !present || value != "" {
			t.Fatal("global environment changed")
		}
	}
	if err := os.Unsetenv("SELECTED_INPUT"); err != nil {
		t.Fatal(err)
	}
	if err := i.checkEnvironment([]credentialroute.Input{{Name: "SELECTED_INPUT"}}); err != nil {
		t.Fatal("absent input refused", err)
	}
	if err := i.checkEnvironment(matching); err == nil {
		t.Fatal("empty input substituted for absent input")
	}
}

// full_only: false
func TestPrepareQualifiesAccountBeforePayloadAndOwnsSnapshot(t *testing.T) {
	for _, action := range []struct {
		name       string
		code       protocol.Action
		nameScoped bool
		operation  string
	}{
		{"create", protocol.ActionCreateEmpty, true, "CreateSecret"},
		{"write", protocol.ActionWriteValue, false, "PutSecretValue"},
		{"owned-delete", protocol.ActionDeleteOwned, false, "DeleteSecret"},
		{"reserved-delete", protocol.ActionDeleteReservedSlot, true, "DeleteSecret"},
	} {
		for _, account := range []string{"123456789012", "111111111111"} {
			t.Run(action.name+"/"+account, func(t *testing.T) {
				implementation, command, policy, payload, inputs := prepareActionFixture(t, action.code, account)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				reads, writes := 0, 0
				implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					defer func() {
						if err := req.Body.Close(); err != nil {
							t.Error("request close", err)
						}
					}()
					if !strings.Contains(req.Header.Get("Authorization"), "Credential=AKIAAAAAAAAAAAAA/") || req.Header.Get("X-Amz-Security-Token") != "controlled-account-"+account {
						t.Error("credential snapshot changed")
					}
					if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
						reads++
						return identityResponse(req, account), nil
					}
					writes++
					if req.URL.Host != "secretsmanager.ap-southeast-2.amazonaws.com" || req.Header.Get("X-Amz-Target") != "secretsmanager."+action.operation {
						t.Error("mutation target changed")
					}
					var body map[string]json.RawMessage
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Error("mutation body", err)
					}
					field, want := "SecretId", testARN
					switch action.code {
					case protocol.ActionCreateEmpty:
						field, want = "Name", "enkv-output"
					case protocol.ActionDeleteReservedSlot:
						want = "enkv-output"
					}
					var got string
					if json.Unmarshal(body[field], &got) != nil || got != want {
						t.Error("mutation resource changed")
					}
					return preparedActionResponse(req, command.Action, testARN, command.AttemptID), nil
				})
				preparedValue, err := implementation.Prepare(ctx, preparationForTest(command), policy, inputs)
				if preparedValue != nil {
					t.Cleanup(func() {
						if err := preparedValue.Close(); err != nil {
							t.Error("prepared close", err)
						}
					})
				}
				wantReads := 0
				if action.nameScoped {
					wantReads = 1
				}
				if reads != wantReads || writes != 0 {
					t.Fatal("preparation account rule or effect boundary changed", reads, wantReads, writes)
				}
				if action.nameScoped && account != "123456789012" {
					if err == nil || preparedValue != nil {
						t.Fatal("wrong account accepted")
					}
					return
				}
				if err != nil || preparedValue == nil {
					t.Fatal("preparation refused", err)
				}
				t.Setenv("AWS_ACCESS_KEY_ID", "AKIABBBBBBBBBBBB")
				t.Setenv("AWS_SESSION_TOKEN", "changed-after-preparation")
				command.Target.TargetData[0] = 'X'
				got, err := preparedValue.Send(ctx, payload)
				wantID, wantLocator := testARN, ""
				switch action.code {
				case protocol.ActionWriteValue:
					wantID = hex.EncodeToString(command.AttemptID[:])
				case protocol.ActionCreateEmpty:
					wantLocator = testARN + "?stage=AWSCURRENT"
				}
				if err != nil || got.Class != protocol.ClassAcknowledged || got.Entry != protocol.EntryMayHaveEntered || got.NormalizedStatus != http.StatusOK || got.SafeResourceID != wantID || got.AssignedLocator != wantLocator || reads != wantReads || writes != 1 {
					t.Fatal("captured send", got.Class, err, reads, writes)
				}
				if _, err := preparedValue.Send(ctx, payload); err == nil || writes != 1 || reads != wantReads {
					t.Fatal("prepared action resent")
				}
				owned := preparedValue.(*prepared)
				credential := owned.credential
				target := owned.command.Target.TargetData
				if err := preparedValue.Close(); err != nil {
					t.Fatal(err)
				}
				for _, body := range [][]byte{credential, target} {
					if !bytes.Equal(body, make([]byte, len(body))) {
						t.Fatal("private owner not cleared")
					}
				}
			})
		}
	}
}

func prepareActionFixture(t *testing.T, action protocol.Action, account string) (Implementation, protocol.Command, protocol.Policy, []byte, []credentialroute.Input) {
	t.Helper()
	awsCredentialEnvironment(t)
	t.Setenv("AWS_SESSION_TOKEN", "controlled-account-"+account)
	descriptor, err := os.ReadFile("../../cmd/enkv-output-aws-secrets-manager/plugin.json")
	if err != nil {
		t.Fatal("descriptor", err)
	}
	implementation, err := NewImplementation(descriptor)
	if err != nil {
		t.Fatal("binding", err)
	}
	command, policy, payload := actionCommand(t, action)
	command.DescriptorID = implementation.Identity().DescriptorID
	routeID, err := credentialroute.Identity(implementation.CredentialRoute())
	if err != nil {
		t.Fatal("route", err)
	}
	command.CredentialRouteID = protocol.ID(routeID)
	inputs := make([]credentialroute.Input, len(implementation.CredentialRoute().Names))
	for at, name := range implementation.CredentialRoute().Names {
		value, present := os.LookupEnv(name)
		inputs[at] = credentialroute.Input{Name: name, Present: present, Value: []byte(value)}
	}
	t.Cleanup(func() {
		clear(payload)
		for _, input := range inputs {
			clear(input.Value)
		}
	})
	return implementation, command, policy, payload, inputs
}

func preparedActionResponse(req *http.Request, action protocol.Action, arn string, attempt protocol.ID) *http.Response {
	body := `{"ARN":"` + arn + `","Name":"enkv-output"}`
	if action == protocol.ActionWriteValue {
		body = `{"ARN":"` + arn + `","Name":"enkv-output","VersionId":"` + hex.EncodeToString(attempt[:]) + `","VersionStages":["AWSCURRENT"]}`
	} else if action != protocol.ActionCreateEmpty {
		body = `{"ARN":"` + arn + `","Name":"enkv-output","DeletionDate":1790467200}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(body))}
}

// full_only: false
func TestPrepareFullARNActionsRetainRemoteUncertainty(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionDeleteOwned} {
		for _, condition := range []string{"denied", "other-instance", "cancelled"} {
			t.Run(fmt.Sprintf("action-%d/%s", action, condition), func(t *testing.T) {
				implementation, command, policy, payload, inputs := prepareActionFixture(t, action, "111111111111")
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				reads, writes := 0, 0
				implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					defer func() {
						if err := req.Body.Close(); err != nil {
							t.Error("request close", err)
						}
					}()
					if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
						reads++
						return identityResponse(req, "111111111111"), nil
					}
					writes++
					switch condition {
					case "denied":
						return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(`{"__type":"AccessDeniedException"}`))}, nil
					case "other-instance":
						return preparedActionResponse(req, action, "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output-ZyXw98", command.AttemptID), nil
					default:
						cancel()
						return nil, context.Canceled
					}
				})
				value, err := implementation.Prepare(ctx, preparationForTest(command), policy, inputs)
				if value != nil {
					t.Cleanup(func() {
						if err := value.Close(); err != nil {
							t.Error("prepared close", err)
						}
					})
				}
				if err != nil || value == nil || reads != 0 || writes != 0 {
					t.Fatal("full-ARN preparation did not retain the admitted request", err, reads, writes)
				}
				got, err := value.Send(ctx, payload)
				if err != nil || got.Class != protocol.ClassUnproved || got.Entry != protocol.EntryMayHaveEntered || got.SafeResourceID != "" || reads != 0 || writes != 1 {
					t.Fatal("remote failure changed exact uncertainty or request count", got.Class, got.Entry, err, reads, writes)
				}
				if _, err := value.Send(t.Context(), payload); err == nil || writes != 1 || reads != 0 {
					t.Fatal("remote failure granted a resend", err, reads, writes)
				}
			})
		}
	}
}

// full_only: false
func TestPrepareRefusesInvalidOwnedInstanceBeforeProviderAccess(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionDeleteOwned} {
		for _, arn := range []string{
			"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output-AbCd1",
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:enkv-output-AbCd12",
			"arn:aws:secretsmanager:ap-southeast-2:111111111111:secret:enkv-output-AbCd12",
		} {
			t.Run(fmt.Sprintf("action-%d/%s", action, arn), func(t *testing.T) {
				implementation, command, policy, _, inputs := prepareActionFixture(t, action, "123456789012")
				command.OwnedInstance = arn
				calls := 0
				implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if err := req.Body.Close(); err != nil {
						t.Error("request close", err)
					}
					return nil, errors.New("invalid ownership reached provider")
				})
				value, err := implementation.Prepare(t.Context(), preparationForTest(command), policy, inputs)
				if value != nil {
					t.Cleanup(func() {
						if err := value.Close(); err != nil {
							t.Error("prepared close", err)
						}
					})
				}
				if err == nil || value != nil || calls != 0 {
					t.Fatal("invalid owned instance reached provider", err, calls)
				}
			})
		}
	}
}

// full_only: false
func TestPrepareNameQualificationFailureReturnsNoOwnerOrEffect(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionCreateEmpty, protocol.ActionDeleteReservedSlot} {
		for _, condition := range []string{"denied", "cancelled"} {
			t.Run(fmt.Sprintf("action-%d/%s", action, condition), func(t *testing.T) {
				implementation, command, policy, _, inputs := prepareActionFixture(t, action, "123456789012")
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				reads, writes := 0, 0
				implementation.transport = closeTestTransport(func(req *http.Request) (*http.Response, error) {
					if err := req.Body.Close(); err != nil {
						t.Error("request close", err)
					}
					if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
						writes++
						return nil, errors.New("unqualified mutation")
					}
					reads++
					if condition == "cancelled" {
						cancel()
						return nil, context.Canceled
					}
					response := identityResponse(req, "123456789012")
					response.StatusCode = http.StatusForbidden
					return response, nil
				})
				value, err := implementation.Prepare(ctx, preparationForTest(command), policy, inputs)
				if value != nil {
					t.Cleanup(func() {
						if err := value.Close(); err != nil {
							t.Error("prepared close", err)
						}
					})
				}
				if err == nil || value != nil || reads != 1 || writes != 0 {
					t.Fatal("failed qualification produced an owner or mutation", err, reads, writes)
				}
			})
		}
	}
}

// full_only: false
func TestDefaultEC2RoleResponsesAreBounded(t *testing.T) {
	for _, kind := range []string{"token", "role-list", "credentials"} {
		for _, size := range []int{64 << 10, 64<<10 + 1} {
			t.Run(fmt.Sprintf("%s/%d", kind, size), func(t *testing.T) {
				defaultEC2RoleEnvironment(t)
				token, roles := "fixture-token", "fixture-role\n"
				credentials := fmt.Sprintf(`{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
				switch kind {
				case "token":
					token = strings.Repeat("t", size)
				case "role-list":
					remaining := size - len(roles)
					roles += strings.Repeat("x\n", remaining/2) + strings.Repeat("x", remaining%2)
				case "credentials":
					credentials += strings.Repeat(" ", size-len(credentials))
				}
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Connection", "close")
					switch r.URL.Path {
					case "/latest/api/token":
						w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
						_, _ = io.WriteString(w, token)
					case "/latest/meta-data/iam/security-credentials/":
						_, _ = io.WriteString(w, roles)
					case "/latest/meta-data/iam/security-credentials/fixture-role":
						_, _ = io.WriteString(w, credentials)
					default:
						t.Error("unexpected standard IMDS path")
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
				t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				source, err := loadCredentialSource(ctx, "us-east-1")
				if err != nil || source == nil {
					t.Fatal("standard EC2 role construction failed", err)
				}
				value, err := source.Retrieve(ctx)
				if size > 64<<10 {
					if err == nil || value.AccessKeyID != "" || value.SecretAccessKey != "" || value.SessionToken != "" {
						t.Fatal("oversized IMDS reply reached credential capture")
					}
				} else if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || !value.CanExpire || !value.Expires.After(time.Now()) || calls.Load() != 3 {
					t.Fatal("exact-limit standard IMDS credentials changed", err, calls.Load())
				}
			})
		}
	}
	t.Run("standard-v1-fallback", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			switch r.URL.Path {
			case "/latest/api/token":
				w.WriteHeader(http.StatusForbidden)
			case "/latest/meta-data/iam/security-credentials/":
				_, _ = io.WriteString(w, "fixture-role\n")
			case "/latest/meta-data/iam/security-credentials/fixture-role":
				_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			default:
				t.Error("unexpected standard fallback path")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "false")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := loadCredentialSource(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("standard fallback construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || calls.Load() != 3 {
			t.Fatal("standard IMDSv1 fallback changed", err, calls.Load())
		}
	})

	t.Run("configured-v1-disabled", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			if r.URL.Path != "/latest/api/token" {
				t.Error("configured IMDSv1 refusal reached metadata without a token")
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := loadCredentialSource(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("standard configured-v1-disabled construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err == nil || value.AccessKeyID != "" || value.SecretAccessKey != "" || value.SessionToken != "" || calls.Load() != 1 {
			t.Fatal("configured IMDSv1 refusal was lost", err, calls.Load())
		}
	})

	t.Run("bounded-token-refusal-preserves-v1-fallback", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			switch r.URL.Path {
			case "/latest/api/token":
				w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
				_, _ = io.WriteString(w, strings.Repeat("t", 64<<10+1))
			case "/latest/meta-data/iam/security-credentials/":
				if r.Header.Get("X-Aws-Ec2-Metadata-Token") != "" {
					t.Error("oversized token reached a metadata request")
				}
				_, _ = io.WriteString(w, "fixture-role\n")
			case "/latest/meta-data/iam/security-credentials/fixture-role":
				if r.Header.Get("X-Aws-Ec2-Metadata-Token") != "" {
					t.Error("oversized token reached a credential request")
				}
				_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			default:
				t.Error("unexpected bounded fallback path")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "false")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := loadCredentialSource(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("bounded token fallback construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || calls.Load() != 4 {
			t.Fatal("bounded token refusal changed configured fallback", err, calls.Load())
		}
	})
}

func defaultEC2RoleEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "AWS_CA_BUNDLE", "AWS_DEFAULTS_MODE"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "empty-config")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
}

// full_only: false
func TestEndpointCredentialUpgradeRefusesBeforeBodyRead(t *testing.T) {
	t.Run("endpoint", func(t *testing.T) {
		checkCredentialUpgrade(t, func(client *http.Client, request *http.Request) (*http.Response, error) {
			response, err := (endpointCredentialClient{client: client}).Do(request)
			if !errors.Is(err, outputcredential.ErrCredential) {
				t.Error("credential endpoint upgrade lost its local refusal cause")
			}
			return response, err
		})
	})
	t.Run("imds", func(t *testing.T) {
		checkCredentialUpgrade(t, func(client *http.Client, request *http.Request) (*http.Response, error) {
			var boundaryErrors []error
			observe := func(stack *middleware.Stack) error {
				return stack.Deserialize.Insert(middleware.DeserializeMiddlewareFunc("ObserveIMDSCredentialRefusal", func(ctx context.Context, input middleware.DeserializeInput, next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
					out, metadata, err := next.HandleDeserialize(ctx, input)
					boundaryErrors = append(boundaryErrors, err)
					return out, metadata, err
				}), "EnkvIMDSResponseBoundary", middleware.Before)
			}
			metadata := imds.New(imds.Options{Endpoint: request.URL.Scheme + "://" + request.URL.Host, HTTPClient: client, EnableFallback: aws.FalseTernary, Retryer: aws.NopRetryer{}, APIOptions: []func(*middleware.Stack) error{boundIMDSResponses, observe}})
			result, err := metadata.GetMetadata(request.Context(), &imds.GetMetadataInput{Path: "credentials"})
			if len(boundaryErrors) != 1 || !errors.Is(boundaryErrors[0], outputcredential.ErrCredential) || retry.NewStandard().IsErrorRetryable(&smithyhttp.RequestSendError{Err: boundaryErrors[0]}) {
				t.Error("IMDS production boundary lost its safe nonretryable refusal")
			}
			if result != nil {
				return &http.Response{Body: result.Content}, err
			}
			return nil, err
		})
	})
}

func checkCredentialUpgrade(t *testing.T, call func(*http.Client, *http.Request) (*http.Response, error)) {
	client, peer := net.Pipe()
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	defer transport.CloseIdleConnections()
	headersReady, peerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() {
			if err := peer.Close(); err != nil {
				t.Error("synthetic upgraded peer cleanup failed", err)
			}
		}()
		request, err := http.ReadRequest(bufio.NewReader(peer))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		if _, err := io.WriteString(peer, "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: synthetic\r\n\r\n"); err != nil {
			return
		}
		close(headersReady)
		_, _ = peer.Read(make([]byte, 1))
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://synthetic.invalid/credentials", nil)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := call(&http.Client{Transport: transport, Timeout: 20 * time.Millisecond}, request)
		done <- result{response, err}
	}()
	joined := false
	defer func() {
		_ = peer.Close()
		cancel()
		if !joined {
			select {
			case got := <-done:
				if got.response != nil && got.response.Body != nil {
					_ = got.response.Body.Close()
				}
			case <-time.After(time.Second):
				t.Error("credential wrapper did not join after synthetic peer closure")
			}
		}
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Error("synthetic upgraded peer did not join")
		}
	}()
	select {
	case <-headersReady:
	case <-time.After(time.Second):
		t.Fatal("synthetic upgrade was not delivered")
	}
	select {
	case got := <-done:
		joined = true
		if got.response != nil {
			if got.response.Body != nil {
				_ = got.response.Body.Close()
			}
			t.Error("upgraded credential response was returned to SDK")
		}
		if got.err == nil || retry.NewStandard().IsErrorRetryable(&smithyhttp.RequestSendError{Err: got.err}) {
			t.Error("credential upgrade lost its safe nonretryable refusal")
		}
		select {
		case <-peerDone:
		case <-time.After(150 * time.Millisecond):
			t.Error("credential refusal did not close the upgraded stream")
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("credential upgrade body outlived HTTP timeout")
	}
}

// full_only: false
func TestDefaultEC2RolePreservesCustomCABundle(t *testing.T) {
	defaultEC2RoleEnvironment(t)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Connection", "close")
		switch r.URL.Path {
		case "/latest/api/token":
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
			_, _ = io.WriteString(w, "fixture-token")
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, "fixture-role\n")
		case "/latest/meta-data/iam/security-credentials/fixture-role":
			_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			t.Error("unexpected configured HTTPS metadata path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "metadata-ca.pem")
	if err := os.WriteFile(path, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", path)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
	t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	source, err := loadCredentialSource(ctx, "us-east-1")
	if err != nil || source == nil {
		t.Fatal("configured HTTPS metadata construction failed", err)
	}
	value, err := source.Retrieve(ctx)
	if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || calls.Load() != 3 {
		t.Fatal("configured metadata CA policy was lost", err, calls.Load())
	}
}

// full_only: false
func TestDefaultAutoModeMetadataResponsesAreBounded(t *testing.T) {
	for _, size := range []int{64 << 10, 64<<10 + 1} {
		t.Run(fmt.Sprintf("token/%d", size), func(t *testing.T) {
			defaultEC2RoleEnvironment(t)
			t.Setenv("AWS_DEFAULTS_MODE", "auto")
			t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
			t.Setenv("AWS_SESSION_TOKEN", "synthetic-token")
			t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
			var calls, documents, tokenLength atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Connection", "close")
				switch r.URL.Path {
				case "/latest/api/token":
					w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
					_, _ = io.WriteString(w, strings.Repeat("t", size))
				case "/latest/dynamic/instance-identity/document":
					documents.Add(1)
					tokenLength.Store(int32(len(r.Header.Get("X-Aws-Ec2-Metadata-Token"))))
					_, _ = io.WriteString(w, `{"region":"us-east-1"}`)
				default:
					t.Error("automatic defaults made an unrelated metadata request")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			source, err := loadCredentialSource(ctx, "us-east-1")
			if err != nil || source == nil {
				t.Fatal("automatic metadata introspection prevented static credentials", err)
			}
			value, err := source.Retrieve(ctx)
			if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" {
				t.Fatal("automatic defaults changed independent static credentials", err)
			}
			if size > 64<<10 {
				if documents.Load() != 0 || tokenLength.Load() != 0 || calls.Load() != 1 {
					t.Fatal("automatic defaults forwarded an oversized IMDS token", documents.Load(), tokenLength.Load(), calls.Load())
				}
			} else if documents.Load() != 1 || tokenLength.Load() != int32(size) || calls.Load() != 2 {
				t.Fatal("exact-limit automatic metadata token was changed", documents.Load(), tokenLength.Load(), calls.Load())
			}
		})
	}
	t.Run("identity-document/stops-before-held-tail", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		t.Setenv("AWS_DEFAULTS_MODE", "auto")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
		t.Setenv("AWS_SESSION_TOKEN", "synthetic-token")
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
		prefixReady, bodyClosed, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseTail := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseTail) }) }
		var documents atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/api/token" {
				w.Header().Set("Connection", "close")
				w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
				_, _ = io.WriteString(w, "fixture-token")
				return
			}
			if r.URL.Path != "/latest/dynamic/instance-identity/document" || documents.Add(1) != 1 {
				t.Error("unexpected automatic identity-document request")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			defer close(handlerDone)
			connection, writer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("synthetic identity-document connection could not be owned", err)
				return
			}
			defer func() {
				// The held-tail release branch closes this same connection before joining its reader.
				if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error("synthetic identity-document connection cleanup failed", err)
				}
			}()
			const prefixLength, totalLength = 64<<10 + 1, 64<<10 + 4096
			prefix := `{"region":"us-east-1"}`
			prefix += strings.Repeat(" ", prefixLength-len(prefix))
			if _, err := fmt.Fprintf(writer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", totalLength, prefix); err != nil {
				t.Error("synthetic identity-document prefix failed", err)
				return
			}
			if err := writer.Flush(); err != nil {
				t.Error("synthetic identity-document prefix did not flush", err)
				return
			}
			close(prefixReady)
			peerDone := make(chan struct{})
			go func() {
				_, _ = connection.Read(make([]byte, 1))
				close(peerDone)
			}()
			select {
			case <-peerDone:
				close(bodyClosed)
			case <-releaseTail:
				_, _ = io.WriteString(connection, strings.Repeat(" ", totalLength-prefixLength))
				if err := connection.Close(); err != nil {
					t.Error("synthetic identity-document release failed", err)
				}
				<-peerDone
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		type outcome struct {
			source aws.CredentialsProvider
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			source, err := loadCredentialSource(ctx, "us-east-1")
			done <- outcome{source, err}
		}()
		joined := false
		defer func() {
			release()
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("automatic defaults did not join after synthetic release")
				}
			}
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Error("synthetic identity-document handler did not join")
			}
		}()
		select {
		case <-prefixReady:
		case <-time.After(time.Second):
			t.Fatal("synthetic identity-document prefix was not delivered")
		}
		select {
		case <-bodyClosed:
		case <-time.After(150 * time.Millisecond):
			t.Error("automatic defaults read beyond the bounded metadata prefix")
			release()
		}
		select {
		case got := <-done:
			joined = true
			if got.err != nil || got.source == nil {
				t.Fatal("nonfatal metadata introspection changed loader result", got.err)
			}
			value, err := got.source.Retrieve(ctx)
			if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" {
				t.Fatal("bounded identity-document failure changed static credentials", err)
			}
		case <-time.After(time.Second):
			t.Fatal("automatic defaults did not settle after bounded response handling")
		}
	})
}

// full_only: false
func TestDefaultCredentialChainKeepsWebIdentityResponseOutsideIMDSBoundary(t *testing.T) {
	defaultEC2RoleEnvironment(t)
	tokenPath := filepath.Join(t.TempDir(), "web-identity-token")
	if err := os.WriteFile(tokenPath, []byte("synthetic-web-identity-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenPath)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/fixture-role")
	t.Setenv("AWS_ROLE_SESSION_NAME", "fixture-session")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_DEFAULTS_MODE", "legacy")
	expiration := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	reply := `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>` + strings.Repeat(" ", 65<<10) + `<Credentials><AccessKeyId>ASIAAAAAAAAAAAAA</AccessKeyId><SecretAccessKey>assumed-synthetic-secret</SecretAccessKey><SessionToken>assumed-synthetic-token</SessionToken><Expiration>` + expiration + `</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>fixture:session</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/fixture-role/fixture-session</Arn></AssumedRoleUser><SubjectFromWebIdentityToken>synthetic-subject</SubjectFromWebIdentityToken><Audience>synthetic-audience</Audience><Provider>synthetic-provider</Provider></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/fixture-role" || r.Form.Get("RoleSessionName") != "fixture-session" || r.Form.Get("WebIdentityToken") != "synthetic-web-identity-token" {
			t.Error("unrelated SDK fixture received another operation")
		}
		_ = r.Body.Close()
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL", server.URL)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	source, err := loadCredentialSource(ctx, "us-east-1")
	if err != nil || source == nil {
		t.Fatal("standard web-identity construction failed", err)
	}
	value, err := source.Retrieve(ctx)
	if err != nil || value.AccessKeyID != "ASIAAAAAAAAAAAAA" || value.SecretAccessKey != "assumed-synthetic-secret" || value.SessionToken != "assumed-synthetic-token" || !value.CanExpire || !value.Expires.After(time.Now()) || calls.Load() != 1 {
		t.Fatal("IMDS boundary changed unrelated standard SDK response", err, calls.Load())
	}
}
