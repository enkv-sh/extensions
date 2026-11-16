package awssm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/plugins/outputs/aws-secrets-manager/profile"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

const testARN = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output-AbCd12"
const testSlot = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output"

type closeErrorBody struct{ io.Reader }

func (closeErrorBody) Close() error { return errors.New("private response close failure") }

type closeTestTransport func(*http.Request) (*http.Response, error)

func (f closeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// full_only: false
func TestAWSResponseCloseFailureKeepsPossibleEntryUnknown(t *testing.T) {
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	responseBytes, err := json.Marshal(map[string]any{"ARN": testARN, "Name": "enkv-output",
		"VersionId": hex.EncodeToString(command.AttemptID[:]), "VersionStages": []string{"AWSCURRENT"}})
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	implementation := Implementation{endpoint: "https://secretsmanager.ap-southeast-2.amazonaws.com",
		signTime: func() time.Time { return time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC) },
		transport: closeTestTransport(func(req *http.Request) (*http.Response, error) {
			posts++
			defer func() {
				if err := req.Body.Close(); err != nil {
					t.Error("close request body", err)
				}
			}()
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
				Body: closeErrorBody{Reader: bytes.NewReader(responseBytes)}}, nil
		})}
	result, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
	if err != nil || posts != 1 || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved {
		t.Fatalf("close failure result=%#v err=%v POST=%d", result, err, posts)
	}
}

func testID(label string) protocol.ID { return sha256.Sum256([]byte(label)) }

func testCredential(token string) []byte {
	fields := []string{"AKIAEXAMPLEKEY00001", "secret+access/key=example", token}
	body := []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
	for _, field := range fields {
		body = binary.BigEndian.AppendUint16(body, uint16(len(field)))
		body = append(body, field...)
	}
	return body
}

func testCommand(t *testing.T, payload []byte) (protocol.Command, protocol.Policy) {
	t.Helper()
	return protocol.Command{Schema: 1, Action: protocol.ActionWriteValue, DomainID: testID("domain"), OperationID: testID("operation"), AttemptID: testID("attempt"), CoordinateID: testID("coordinate"), ProjectionCommitment: testID("projection"), DispatchContextDigest: testID("dispatch"), RequestContractDigest: testID("request"), ResponseContractDigest: testID("response"), DescriptorID: fixtureBinding(t, fixtureRoute()).Identity().DescriptorID, CredentialRouteID: fixtureRouteID(t), BindingIncarnationID: testID("binding"), EntryIncarnationID: testID("entry"), TargetRowDigest: testID("row"), BirthTargetRowDigest: testID("birth-row"), OwnedBirthAttemptID: testID("birth"), ValueBasisDigest: testID("value-basis"), DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), PayloadLengthMode: protocol.LengthExact, PayloadLength: uint32(len(payload)), BindingDestinationID: "destination", OwnedInstance: testARN, Target: protocol.Target{ServiceContractID: profile.ServiceContractID, TargetContractID: profile.TargetContractID,
		CanonicalTarget: testSlot, TargetData: []byte(`{"account":"123456789012","region":"ap-southeast-2","name":"enkv-output"}`),
		PayloadEncoding: protocol.EncodingRaw, LocatorRequiresCreation: true, Capabilities: profile.Actions(), WriteValueBounds: protocol.PayloadBounds{Minimum: 1, Maximum: 65536}}}, protocol.Policy{}
}

func testImplementation(server *httptest.Server) Implementation {
	base := server.Client().Transport
	transport := closeTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			_ = req.Body.Close()
			return identityResponse(req, "123456789012"), nil
		}
		return base.RoundTrip(req)
	})
	return Implementation{transport: transport, endpoint: server.URL,
		signTime: func() time.Time { return time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC) }}
}

// full_only: false
func TestAWSPublicationRequestCompletePayload(t *testing.T) {
	for _, payload := range [][]byte{{0}, {0, 's', 'e', 'c', 'r', 'e', 't', 255}, bytes.Repeat([]byte{'x'}, MaximumRawValueBytes)} {
		t.Run(string(rune(len(payload)%10+'0')), func(t *testing.T) {
			command, policy := testCommand(t, payload)
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/" || r.GetBody != nil || !r.Close || r.ProtoMajor != 1 ||
					r.Header.Get("X-Amz-Target") != "secretsmanager.PutSecretValue" ||
					r.Header.Get("X-Amz-Security-Token") != "session+token" ||
					!strings.Contains(r.Header.Get("Authorization"), "AKIAEXAMPLEKEY00001/20260927/ap-southeast-2/secretsmanager/aws4_request") {
					t.Errorf("signed one-operation request differed")
					w.WriteHeader(400)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, maximumBodyBytes+1))
				if err != nil || len(body) > maximumBodyBytes {
					t.Error("body bound failed")
					w.WriteHeader(400)
					return
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(body, &fields) != nil || len(fields) != 4 {
					t.Error("AWS body fields differed")
					w.WriteHeader(400)
					return
				}
				var token, binaryValue, secretID string
				var stages []string
				_ = json.Unmarshal(fields["ClientRequestToken"], &token)
				_ = json.Unmarshal(fields["SecretBinary"], &binaryValue)
				_ = json.Unmarshal(fields["SecretId"], &secretID)
				_ = json.Unmarshal(fields["VersionStages"], &stages)
				decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(binaryValue)
				if token != hex.EncodeToString(command.AttemptID[:]) || secretID != testARN || decodeErr != nil ||
					!bytes.Equal(decoded, payload) || len(stages) != 1 || stages[0] != "AWSCURRENT" {
					t.Error("AWS payload/token/stage differed")
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"ARN": testARN, "Name": "enkv-output", "VersionId": token,
					"VersionStages": []string{"AWSCURRENT"}})
			}))
			defer server.Close()
			implementation := testImplementation(server)
			result, err := implementation.execute(context.Background(), command, policy, payload, testCredential("session+token"))
			if err != nil || result.Class != protocol.ClassAcknowledged || result.Entry != protocol.EntryMayHaveEntered ||
				result.SafeResourceID != hex.EncodeToString(command.AttemptID[:]) || posts != 1 {
				t.Fatalf("result=%#v err=%v POST=%d", result, err, posts)
			}
		})
	}
}

// full_only: false
func TestAWSPublicationResponseLostOneRequest(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	implementation := testImplementation(server)
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	result, err := implementation.execute(context.Background(), command, policy, payload, testCredential(""))
	if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved || posts.Load() != 1 {
		t.Fatalf("result=%#v err=%v POST=%d", result, err, posts.Load())
	}
}

// full_only: false
func TestAWSCancelAfterEntryWithPrewarmedTransportDoesNotReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var prewarms, posts atomic.Int32
	var prewarmAddress, postAddress string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/prewarm":
			prewarms.Add(1)
			prewarmAddress = r.RemoteAddr
		case "/":
			posts.Add(1)
			postAddress = r.RemoteAddr
			cancel() // Entry is observed before cancellation.
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	implementation := New()
	implementation.endpoint = server.URL
	transport, ok := implementation.transport.(*http.Transport)
	if !ok || !transport.DisableKeepAlives || transport.Proxy != nil {
		t.Fatal("production transport may reuse or proxy an output request")
	}
	defer transport.CloseIdleConnections()
	prewarm, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/prewarm", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(prewarm)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	result, err := implementation.execute(ctx, command, policy, payload, testCredential(""))
	if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved ||
		prewarms.Load() != 1 || posts.Load() != 1 || prewarmAddress == "" || postAddress == "" || prewarmAddress == postAddress {
		t.Fatalf("canceled prewarmed send result=%#v err=%v warm=%d POST=%d addresses=%q/%q",
			result, err, prewarms.Load(), posts.Load(), prewarmAddress, postAddress)
	}
}

// full_only: false
func TestAWSPublicationRedirectAndErrorRemainUnknown(t *testing.T) {
	for _, status := range []int{301, 400, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			posts, followed := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					followed++
					w.WriteHeader(204)
					return
				}
				posts++
				if status == 301 {
					http.Redirect(w, r, "/elsewhere", status)
					return
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			payload := []byte("private")
			command, policy := testCommand(t, payload)
			result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential(""))
			if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved || posts != 1 || followed != 0 {
				t.Fatalf("result=%#v err=%v POST=%d followed=%d", result, err, posts, followed)
			}
		})
	}
}

// full_only: false
func TestAWSPublicationLocalBoundsAndAliases(t *testing.T) {
	if _, err := profile.ParseOwnedInstance(testARN); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.ParseOwnedInstance(testSlot + "-A_b+12"); err != nil {
		t.Fatal("six-character ARN suffix must not be assumed hexadecimal", err)
	}
	for _, arn := range []string{
		"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-outpu",
		"arn:aws-cn:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output-AbCd12",
		"arn:aws:secretsmanager:ap-southeast-2:12345678901:secret:enkv-output-AbCd12",
		"arn:aws:secretsmanager:unknown-1:123456789012:secret:enkv-output-AbCd12",
		"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output%-AbCd12",
	} {
		if _, err := profile.ParseOwnedInstance(arn); err == nil {
			t.Errorf("ARN alias admitted: %s", arn)
		}
	}
	credential := testCredential(strings.Repeat("A", protocol.MaximumCredentialBytes-36-len(testCredential(""))))
	if _, err := parseCredential(credential); err != nil || len(credential) != protocol.MaximumCredentialBytes-36 {
		t.Fatalf("maximum credential refused: length=%d err=%v", len(credential), err)
	}
	if _, err := parseCredential(append(credential, 'A')); err == nil {
		t.Fatal("overlong credential admitted")
	}
	if _, err := parseCredential(testCredential("bad\nheader")); err == nil {
		t.Fatal("header control byte admitted")
	}
	attempt := testID("attempt")
	if body, err := putBody(testARN, attempt, bytes.Repeat([]byte{'x'}, MaximumRawValueBytes)); err != nil || len(body) > maximumBodyBytes {
		t.Fatalf("maximum body length=%d err=%v", len(body), err)
	}
	if _, err := putBody(testARN, attempt, nil); err == nil {
		t.Fatal("AWS SecretBinary zero-byte value admitted")
	}
	if _, err := putBody(testARN, attempt, make([]byte, MaximumRawValueBytes+1)); err == nil {
		t.Fatal("AWS overlong raw value admitted")
	}
}

// full_only: false
func TestAWSPassiveProfileBoundsAndExactCoordinate(t *testing.T) {
	command, policy := testCommand(t, []byte("x"))
	request := command.ActionCheck()
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
	implementation := testPublicImplementation(t)
	bounds, err := implementation.CheckAction(t.Context(), actionForTest(request), policy)
	if err != nil || bounds != (protocol.PayloadBounds{Minimum: 1, Maximum: MaximumRawValueBytes}) {
		t.Fatal("passive value bounds", bounds, err)
	}
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthExact, MaximumRawValueBytes
	if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err != nil {
		t.Fatal("maximum refused", err)
	}
	for _, n := range []uint32{0, MaximumRawValueBytes + 1} {
		request.PayloadLength = n
		if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err == nil {
			t.Fatal("invalid length accepted", n)
		}
	}
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
	for _, bad := range []string{"arn:aws-cn:secretsmanager:ap-southeast-2:123456789012:secret:enkv-output"} {
		request.Target.CanonicalTarget = bad
		if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err == nil {
			t.Fatal("noncanonical alias accepted", bad)
		}
	}
}
