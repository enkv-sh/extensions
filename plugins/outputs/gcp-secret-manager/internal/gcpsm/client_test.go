package gcpsm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"enkv.sh/plugins/outputs/gcp-secret-manager/profile"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

const testParent = "projects/123456789012/secrets/Enkv_output-1"

func testID(label string) protocol.ID { return sha256.Sum256([]byte(label)) }

func testCredential(token string) []byte {
	body := []byte{0, 1}
	// 2100-01-01 UTC in Unix milliseconds, independent of the production codec.
	body = binary.BigEndian.AppendUint64(body, 4102444800000)
	body = binary.BigEndian.AppendUint16(body, uint16(len(token)))
	body = append(body, token...)
	return append(body, 0, 0)
}

func testCommand(t *testing.T, payload []byte) (protocol.Command, protocol.Policy) {
	t.Helper()
	return protocol.Command{Schema: 1, Action: protocol.ActionWriteValue, DomainID: testID("domain"), OperationID: testID("operation"), AttemptID: testID("attempt"), CoordinateID: testID("coordinate"), ProjectionCommitment: testID("projection"), DispatchContextDigest: testID("dispatch"), RequestContractDigest: testID("request"), ResponseContractDigest: testID("response"), DescriptorID: fixtureBinding(t, fixtureRoute()).Identity().DescriptorID, CredentialRouteID: fixtureRouteID(t), BindingIncarnationID: testID("binding"), EntryIncarnationID: testID("entry"), TargetRowDigest: testID("row"), BirthTargetRowDigest: testID("birth-row"), OwnedBirthAttemptID: testID("birth"), ValueBasisDigest: testID("value-basis"), DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), PayloadLengthMode: protocol.LengthExact, PayloadLength: uint32(len(payload)), BindingDestinationID: "destination", OwnedInstance: testParent, Target: protocol.Target{ServiceContractID: profile.ServiceContractID, TargetContractID: profile.TargetContractID,
		CanonicalTarget: testParent, ConsumerLocator: testParent + "/versions/latest", TargetData: []byte(`{"project_number":"123456789012","name":"Enkv_output-1"}`),
		PayloadEncoding: protocol.EncodingRaw, Capabilities: profile.Actions(), WriteValueBounds: protocol.PayloadBounds{Minimum: 1, Maximum: 65536}}}, protocol.Policy{}
}

type checkingTransport struct {
	base  http.RoundTripper
	check func(*http.Request) error
}

type closeErrorBody struct{ io.ReadCloser }

func (b closeErrorBody) Close() error {
	if err := b.ReadCloser.Close(); err != nil {
		return err
	}
	return errors.New("private response close failure")
}

type closeErrorTransport struct{ base http.RoundTripper }

func (t closeErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if response != nil && response.Body != nil {
		response.Body = closeErrorBody{ReadCloser: response.Body}
	}
	return response, err
}

// full_only: false
func TestGCPResponseCloseFailureKeepsPossibleEntryUnknown(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
	}))
	defer server.Close()
	implementation := testImplementation(server)
	implementation.transport = closeErrorTransport{base: implementation.transport}
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	result, err := implementation.execute(context.Background(), command, policy, payload, testCredential("token-1"))
	if err != nil || posts != 1 || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved {
		t.Fatalf("close failure result=%#v err=%v POST=%d", result, err, posts)
	}
}

func (c checkingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := c.check(req); err != nil {
		return nil, err
	}
	return c.base.RoundTrip(req)
}

func testImplementation(server *httptest.Server) Implementation {
	return Implementation{transport: server.Client().Transport, endpoint: server.URL}
}

// full_only: false
func TestGCPPublicationExactAddVersionAndZeroCRC(t *testing.T) {
	for _, tc := range []struct {
		name, knownCRC string
		payload        []byte
	}{
		// Bitwise reflected Castagnoli (0x82f63b78), with initial/final
		// XOR 0xffffffff, independently solves these four bytes for CRC zero.
		{name: "nonempty-zero-crc", payload: []byte{0xab, 0x9b, 0xe0, 0x9b}, knownCRC: "0"},
		{name: "binary", payload: []byte{0, 1, 2, 255}},
		{name: "known-crc", payload: []byte("123456789"), knownCRC: "3808858755"},
		{name: "maximum", payload: bytes.Repeat([]byte{'x'}, MaximumRawValueBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/"+testParent+":addVersion" ||
					r.URL.RawQuery != "alt=json&prettyPrint=false" || r.Header.Get("Authorization") != "Bearer token-1" ||
					r.Header.Get("Content-Type") != "application/json" || r.ProtoMajor != 1 || !r.Close {
					t.Error("generated request differed")
					w.WriteHeader(400)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, maximumRequestBytes+1))
				if err != nil || len(body) > maximumRequestBytes {
					t.Error("request body exceeded bound")
					w.WriteHeader(400)
					return
				}
				var outer map[string]json.RawMessage
				var inner map[string]json.RawMessage
				if json.Unmarshal(body, &outer) != nil || len(outer) != 1 || json.Unmarshal(outer["payload"], &inner) != nil || len(inner) != 2 {
					t.Error("request fields differed")
					w.WriteHeader(400)
					return
				}
				var data, crc string
				_ = json.Unmarshal(inner["data"], &data)
				_ = json.Unmarshal(inner["dataCrc32c"], &crc)
				decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(data)
				if decodeErr != nil || !bytes.Equal(decoded, payload) || (tc.knownCRC != "" && crc != tc.knownCRC) || crc == "" {
					t.Errorf("data or CRC differed: crc=%q", crc)
					w.WriteHeader(400)
					return
				}
				_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
			}))
			defer server.Close()
			implementation := testImplementation(server)
			implementation.transport = checkingTransport{base: implementation.transport, check: func(r *http.Request) error {
				if r.GetBody != nil || !r.Close || r.ProtoMajor != 1 {
					t.Error("request replay path was available")
				}
				return nil
			}}
			command, policy := testCommand(t, payload)
			result, err := implementation.execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged ||
				result.SafeResourceID != testParent+"/versions/42" || posts != 1 {
				t.Fatalf("result=%#v err=%v POST=%d", result, err, posts)
			}
		})
	}
}

// full_only: false
func TestGCPPublicationValueBoundsBeforeTransport(t *testing.T) {
	for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
		maximum := 65536
		if encoding == protocol.EncodingBase64 {
			maximum = 49152 // Padded Base64 is exactly 65536 bytes; one more raw byte is 65540.
		}
		for _, length := range []int{0, 1, maximum, maximum + 1} {
			t.Run(fmt.Sprintf("encoding=%d/raw=%d", encoding, length), func(t *testing.T) {
				payload := bytes.Repeat([]byte{'x'}, length)
				if encoding == protocol.EncodingBase64 {
					payload = base64.StdEncoding.AppendEncode(nil, payload)
				}
				posts := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					posts++
					body, err := io.ReadAll(io.LimitReader(r.Body, maximumRequestBytes+1))
					if err != nil || len(body) > maximumRequestBytes {
						t.Errorf("request body unavailable or over limit: error=%t bytes=%d", err != nil, len(body))
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
				}))
				defer server.Close()
				command, policy := testCommand(t, payload)
				command.Target.PayloadEncoding = encoding
				result, err := testImplementation(server).execute(t.Context(), command, policy, payload, testCredential("token-1"))
				if length == 0 || length > maximum {
					if err != nil || result.Entry != protocol.EntryNotEntered || result.Class != protocol.ClassQualifiedNoEffect || posts != 0 {
						t.Fatalf("out-of-bounds entry=%d class=%d error=%t POST=%d", result.Entry, result.Class, err != nil, posts)
					}
					return
				}
				if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged || result.SafeResourceID != testParent+"/versions/42" || posts != 1 {
					t.Fatalf("admitted entry=%d class=%d error=%t POST=%d resource-equal=%t", result.Entry, result.Class, err != nil, posts, result.SafeResourceID == testParent+"/versions/42")
				}
			})
		}
	}
}

// full_only: false
func TestGCPPublicationResponseLostOneRequest(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	payload := []byte("private")
	command, policy := testCommand(t, payload)
	result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
	if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved || posts.Load() != 1 {
		t.Fatalf("result=%#v err=%v POST=%d", result, err, posts.Load())
	}
}

// full_only: false
func TestGCPCancelAfterEntryWithPrewarmedTransportDoesNotReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var prewarms, posts atomic.Int32
	var prewarmAddress, postAddress string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/prewarm":
			prewarms.Add(1)
			prewarmAddress = r.RemoteAddr
		case "/v1/" + testParent + ":addVersion":
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
	result, err := implementation.execute(ctx, command, policy, payload, testCredential("token-1"))
	if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved ||
		prewarms.Load() != 1 || posts.Load() != 1 || prewarmAddress == "" || postAddress == "" || prewarmAddress == postAddress {
		t.Fatalf("canceled prewarmed send result=%#v err=%v warm=%d POST=%d addresses=%q/%q",
			result, err, prewarms.Load(), posts.Load(), prewarmAddress, postAddress)
	}
}

// full_only: false
func TestGCPPublicationPossibleEntryEvidence(t *testing.T) {
	for _, variant := range []string{"wrong-parent", "noncanonical-version", "missing-crc", "oversize", "redirect", "error"} {
		t.Run(variant, func(t *testing.T) {
			posts, followed := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					followed++
					return
				}
				posts++
				switch variant {
				case "wrong-parent":
					_, _ = io.WriteString(w, `{"name":"projects/123456789013/secrets/Enkv_output-1/versions/1","clientSpecifiedPayloadChecksum":true}`)
				case "noncanonical-version":
					_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/01","clientSpecifiedPayloadChecksum":true}`)
				case "missing-crc":
					_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/1"}`)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("x", maximumReplyBytes+1))
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
				case "error":
					w.WriteHeader(429)
				}
			}))
			defer server.Close()
			payload := []byte("private")
			command, policy := testCommand(t, payload)
			result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassUnproved || posts != 1 || followed != 0 {
				t.Fatalf("result=%#v err=%v POST=%d followed=%d", result, err, posts, followed)
			}
		})
	}
}

// full_only: false
func TestGCPPublicationLocalBoundsAndAliases(t *testing.T) {
	if _, _, err := profile.ParseParent(testParent); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{
		"projects/example-project/secrets/Enkv_output-1", "projects/0123/secrets/Enkv_output-1",
		"projects/0/secrets/Enkv_output-1", "projects/9223372036854775808/secrets/Enkv_output-1",
		"projects/123456789012/locations/global/secrets/Enkv_output-1",
		"projects/123456789012/secrets/Enkv%5Foutput-1", "projects/123456789012/secrets/",
	} {
		if _, _, err := profile.ParseParent(parent); err == nil {
			t.Errorf("physical alias admitted: %s", parent)
		}
	}
	if _, _, err := profile.ParseParent("projects/9223372036854775807/secrets/" + strings.Repeat("A", 255)); err != nil {
		t.Fatal("project number or Secret ID exact maximum refused", err)
	}
	if _, _, err := profile.ParseParent("projects/1/secrets/" + strings.Repeat("A", 256)); err == nil {
		t.Fatal("overlong Secret ID admitted")
	}
	for _, token := range [][]byte{nil, []byte("bad\nheader"), []byte("bad:header"), bytes.Repeat([]byte{'x'}, protocol.MaximumCredentialBytes-35)} {
		if validateCredential(token) == nil {
			t.Errorf("credential admitted: length=%d", len(token))
		}
	}
	if validateCredential(testCredential(strings.Repeat("x", 16384))) != nil {
		t.Fatal("maximum credential refused")
	}
	for _, version := range []string{testParent + "/versions/0", testParent + "/versions/01", testParent + "/versions/latest",
		"projects/123456789013/secrets/Enkv_output-1/versions/1"} {
		if canonicalVersion(testParent, version) {
			t.Errorf("version alias admitted: %s", version)
		}
	}
	if !canonicalVersion(testParent, testParent+"/versions/9223372036854775807") {
		t.Fatal("maximum canonical version refused")
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("overlong value entered") }))
	defer server.Close()
	payload := make([]byte, MaximumRawValueBytes+1)
	command, policy := testCommand(t, payload)
	result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
	if err != nil || result.Entry != protocol.EntryNotEntered {
		t.Fatalf("overlong result=%#v err=%v", result, err)
	}
}

// full_only: false
func TestGCPPassiveProfileGlobalNumericBounds(t *testing.T) {
	command, policy := testCommand(t, []byte("x"))
	request := command.ActionCheck()
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
	implementation := testPublicImplementation(t)
	bounds, err := implementation.CheckAction(t.Context(), actionForTest(request), policy)
	if err != nil || bounds != (protocol.PayloadBounds{Minimum: 1, Maximum: MaximumRawValueBytes}) {
		t.Fatal("passive value bounds", bounds, err)
	}
	for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
		request.Target.PayloadEncoding = encoding
		request.PayloadLengthMode = protocol.LengthExact
		for _, n := range []uint32{1, MaximumRawValueBytes} {
			request.PayloadLength = n
			if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err != nil {
				t.Fatal("admitted length refused", encoding, n, err)
			}
		}
		for _, n := range []uint32{0, MaximumRawValueBytes + 1} {
			request.PayloadLength = n
			if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err == nil {
				t.Fatal("invalid length accepted", encoding, n)
			}
		}
	}
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
	for _, bad := range []string{"projects/project-id/secrets/Enkv_output-1", "projects/0123/secrets/Enkv_output-1", "projects/123456789012/locations/global/secrets/Enkv_output-1"} {
		request.Target.CanonicalTarget = bad
		if _, err := implementation.CheckAction(t.Context(), actionForTest(request), policy); err == nil {
			t.Fatal("noncanonical alias accepted", bad)
		}
	}
}

// full_only: false
func TestDeletionProjectsExactMetadataBeforeConditionalMutation(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		for _, mode := range []string{"large-unrelated-metadata", "wrong-name", "empty-etag", "long-etag", "oversized-projection", "malformed", "canceled-after-get"} {
			t.Run(fmt.Sprintf("%d/%s", action, mode), func(t *testing.T) {
				command, policy, payload := actionCommand(t, action)
				var gets, deletes atomic.Int32
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "GET":
						gets.Add(1)
						if r.URL.RawQuery != "alt=json&fields=name%2Cetag&prettyPrint=false" {
							t.Error("metadata GET lacks exact field projection")
						}
						body := `{"name":"` + testParent + `","etag":"etag-1"}`
						if r.URL.Query().Get("fields") != "name,etag" {
							body = `{"name":"` + testParent + `","etag":"etag-1","annotations":{"legal":"` + strings.Repeat("x", 5000) + `"}}`
						}
						switch mode {
						case "wrong-name":
							body = `{"name":"projects/123456789012/secrets/other","etag":"etag-1"}`
						case "empty-etag":
							body = `{"name":"` + testParent + `","etag":""}`
						case "long-etag":
							body = `{"name":"` + testParent + `","etag":"` + strings.Repeat("x", 1025) + `"}`
						case "canceled-after-get":
							cancel()
						case "oversized-projection":
							body = `{"name":"` + testParent + `","etag":"` + strings.Repeat("x", 4096) + `"}`
						case "malformed":
							body = `{"name":`
						}
						_, _ = io.WriteString(w, body)
					case "DELETE":
						deletes.Add(1)
						if r.URL.Query().Get("etag") != "etag-1" {
							t.Error("DELETE changed qualified etag")
						}
						_, _ = io.WriteString(w, `{}`)
					default:
						t.Error("unexpected method")
					}
				}))
				defer server.Close()
				got, err := testImplementation(server).execute(ctx, command, policy, payload, testCredential("token-1"))
				wantDeletes, wantEntry, wantClass := 0, protocol.EntryState(protocol.EntryNotEntered), protocol.OutcomeClass(protocol.ClassQualifiedNoEffect)
				if mode == "large-unrelated-metadata" {
					wantDeletes, wantEntry, wantClass = 1, protocol.EntryMayHaveEntered, protocol.ClassAcknowledged
				}
				if err != nil || gets.Load() != 1 || deletes.Load() != int32(wantDeletes) || got.Entry != wantEntry || got.Class != wantClass {
					t.Fatalf("result=%+v err=%v GET=%d DELETE=%d", got, err, gets.Load(), deletes.Load())
				}
			})
		}
	}
}

// full_only: false
func TestGCPSendEnforcesValueBoundsBeforeTransport(t *testing.T) {
	for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
		maximum := 65536
		if encoding == protocol.EncodingBase64 {
			maximum = 49152
		}
		for _, length := range []int{0, 1, maximum + 1} {
			t.Run(fmt.Sprintf("encoding=%d/bytes=%d", encoding, length), func(t *testing.T) {
				payload := bytes.Repeat([]byte{'x'}, length)
				if encoding == protocol.EncodingBase64 {
					payload = base64.StdEncoding.AppendEncode(nil, payload)
				}
				posts := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					posts++
					_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maximumRequestBytes+1))
					_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/42","clientSpecifiedPayloadChecksum":true}`)
				}))
				defer server.Close()
				command, policy := testCommand(t, payload)
				command.Target.PayloadEncoding = encoding
				preparation := preparationForTest(command)
				credential := testCredential("token-1")
				if validateConsumer(preparation, policy) != nil || validateCredential(credential) != nil || int(preparation.PayloadLength) != len(payload) {
					t.Fatal("invalid setup hides send value bounds")
				}
				result, err := testImplementation(server).send(t.Context(), preparation, policy, payload, credential)
				if length == 1 {
					if err != nil || result.Entry != protocol.EntryMayHaveEntered || result.Class != protocol.ClassAcknowledged || posts != 1 {
						t.Fatalf("admitted send entry=%d class=%d error=%t POST=%d", result.Entry, result.Class, err != nil, posts)
					}
				} else if err != nil || result.Entry != protocol.EntryNotEntered || result.Class != protocol.ClassQualifiedNoEffect || posts != 0 {
					t.Fatalf("out-of-bounds send entry=%d class=%d error=%t POST=%d", result.Entry, result.Class, err != nil, posts)
				}
			})
		}
	}
}
