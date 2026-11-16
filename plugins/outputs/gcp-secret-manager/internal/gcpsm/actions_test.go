package gcpsm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"google.golang.org/api/googleapi"
)

// full_only: false
func TestGCPCreateCollisionRequiresCompleteExactServiceStatus(t *testing.T) {
	const collision = `{"error":{"code":409,"status":"ALREADY_EXISTS"}}`
	for _, tc := range []struct {
		name, body string
		status     int
		qualified  bool
	}{
		{"minimal", collision, 409, true},
		{"field-order", ` { "error": { "status": "ALREADY_EXISTS", "code": 409 } } `, 409, true},
		{"message-and-details", `{"error":{"code":409,"message":"Synthetic secret already exists","status":"ALREADY_EXISTS","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ALREADY_EXISTS","domain":"secretmanager.googleapis.com","metadata":{"resource":"` + testParent + `"}}]}}`, 409, true},
		{"empty-details", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[]}}`, 409, true},
		{"paired-surrogate-message", `{"error":{"code":409,"status":"ALREADY_EXISTS","message":"Synthetic \ud83d\ude00 collision"}}`, 409, true},
		{"exact-bound", collision + strings.Repeat(" ", 4096-len(collision)), 409, true},
		{"bare-conflict", `{}`, 409, false},
		{"missing-code", `{"error":{"status":"ALREADY_EXISTS"}}`, 409, false},
		{"missing-status", `{"error":{"code":409}}`, 409, false},
		{"other-conflict", `{"error":{"code":409,"status":"ABORTED"}}`, 409, false},
		{"body-code-mismatch", `{"error":{"code":500,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"rpc-code-in-http-body", `{"error":{"code":6,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"http-code-mismatch", collision, 500, false},
		{"http-success", collision, 200, false},
		{"duplicate-code-last-conflict", `{"error":{"code":500,"code":409,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"duplicate-code-first-conflict", `{"error":{"code":409,"code":500,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"duplicate-status", `{"error":{"code":409,"status":"ABORTED","status":"ALREADY_EXISTS"}}`, 409, false},
		{"duplicate-error", `{"error":{"code":500,"status":"INTERNAL"},"error":{"code":409,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"error-alias", `{"Error":{"code":409,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"status-alias", `{"error":{"code":409,"Status":"ALREADY_EXISTS"}}`, 409, false},
		{"status-alias-with-canonical", `{"error":{"code":409,"status":"ALREADY_EXISTS","Status":"ABORTED"}}`, 409, false},
		{"success-and-error", `{"name":"` + testParent + `","error":{"code":409,"status":"ALREADY_EXISTS"}}`, 409, false},
		{"string-code", `{"error":{"code":"409","status":"ALREADY_EXISTS"}}`, 409, false},
		{"wrong-status-type", `{"error":{"code":409,"status":6}}`, 409, false},
		{"wrong-message-type", `{"error":{"code":409,"status":"ALREADY_EXISTS","message":false}}`, 409, false},
		{"invalid-utf8-message", `{"error":{"code":409,"status":"ALREADY_EXISTS","message":"` + string([]byte{0xff}) + `"}}`, 409, false},
		{"unpaired-high-surrogate", `{"error":{"code":409,"status":"ALREADY_EXISTS","message":"\ud800"}}`, 409, false},
		{"unpaired-low-surrogate", `{"error":{"code":409,"status":"ALREADY_EXISTS","message":"\udc00"}}`, 409, false},
		{"unpaired-surrogate-detail", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","metadata":{"message":"\ud800"}}]}}`, 409, false},
		{"wrong-details-type", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":{}}}`, 409, false},
		{"null-details", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":null}}`, 409, false},
		{"scalar-detail", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[1]}}`, 409, false},
		{"null-detail", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[null]}}`, 409, false},
		{"untyped-detail", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[{"reason":"ALREADY_EXISTS"}]}}`, 409, false},
		{"empty-detail-type", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[{"@type":""}]}}`, 409, false},
		{"wrong-detail-type", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[{"@type":1}]}}`, 409, false},
		{"duplicate-detail-type", `{"error":{"code":409,"status":"ALREADY_EXISTS","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","@type":"type.googleapis.com/google.rpc.LocalizedMessage"}]}}`, 409, false},
		{"trailing-document", collision + `{}`, 409, false},
		{"truncated", `{"error":{"code":409,"status":"ALREADY_EXISTS"}`, 409, false},
		{"over-bound", collision + strings.Repeat(" ", 4097-len(collision)), 409, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			command, policy, payload := actionCommand(t, protocol.ActionCreateEmpty)
			calls := 0
			responseBody := &collisionResponseBody{reader: strings.NewReader(tc.body)}
			implementation := New()
			implementation.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body, readErr := io.ReadAll(req.Body)
				closeErr := req.Body.Close()
				const wantBody = "{\"replication\":{\"automatic\":{}}}\n"
				methodOK := req.Method == http.MethodPost
				pathOK := req.URL.EscapedPath() == "/v1/projects/123456789012/secrets"
				queryOK := req.URL.RawQuery == "alt=json&prettyPrint=false&secretId=Enkv_output-1"
				bodyOK := string(body) == wantBody && req.ContentLength == int64(len(wantBody))
				if readErr != nil || closeErr != nil || !methodOK || !pathOK || !queryOK || !bodyOK || req.GetBody != nil || !req.Close {
					t.Errorf("exact admitted create request changed: method=%t path=%t query=%t body=%t body_bytes=%d content_length=%d read_failed=%t close_failed=%t replay_absent=%t close=%t", methodOK, pathOK, queryOK, bodyOK, len(body), req.ContentLength, readErr != nil, closeErr != nil, req.GetBody == nil, req.Close)
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: responseBody, Request: req}, nil
			})
			credential := testCredential("token-1")
			ownedTarget := bytes.Clone(command.Target.TargetData)
			preparation := preparationForTest(command)
			preparation.Target.TargetData = ownedTarget
			owner := &prepared{implementation: implementation, command: preparation, policy: policy, credential: credential}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			got, err := owner.Send(ctx, payload)
			wantClass, wantStatus := protocol.OutcomeClass(protocol.ClassUnproved), uint16(0)
			if tc.qualified {
				wantClass, wantStatus = protocol.ClassQualifiedNoEffect, http.StatusConflict
			}
			if err != nil || !got.Valid() || got.Entry != protocol.EntryMayHaveEntered || got.Class != wantClass || got.NormalizedStatus != wantStatus || got.SafeRequestID != "" || got.SafeResourceID != "" || got.AssignedLocator != "" || calls != 1 || responseBody.closes != 1 {
				t.Errorf("create response classification: class=%d status=%d entry=%d calls=%d closes=%d error=%t", got.Class, got.NormalizedStatus, got.Entry, calls, responseBody.closes, err != nil)
			}
			if _, err := owner.Send(ctx, payload); err == nil || calls != 1 {
				t.Error("collision or uncertainty restored the consumed send right", calls)
			}
			if err := owner.Close(); err != nil || !bytes.Equal(credential, make([]byte, len(credential))) || !bytes.Equal(ownedTarget, make([]byte, len(ownedTarget))) {
				t.Error("collision result lost prepared byte ownership")
			}
		})
	}
}

type collisionResponseBody struct {
	reader            io.Reader
	readErr, closeErr error
	cancel            context.CancelFunc
	closes            int
}

func (body *collisionResponseBody) Read(p []byte) (int, error) {
	n, err := body.reader.Read(p)
	if body.cancel != nil {
		body.cancel()
		body.cancel = nil
	}
	if err == io.EOF && body.readErr != nil {
		return n, body.readErr
	}
	return n, err
}

func (body *collisionResponseBody) Close() error {
	body.closes++
	return body.closeErr
}

// full_only: false
func TestGCPCreateCollisionIncompleteResponseRemainsUnknown(t *testing.T) {
	const collision = `{"error":{"code":409,"status":"ALREADY_EXISTS"}}`
	for _, mode := range []string{"read-error", "close-error", "cancel-during-read", "lost-response", "response-and-error", "missing-body", "synthesized-sdk-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			command, policy, payload := actionCommand(t, protocol.ActionCreateEmpty)
			responseBody := &collisionResponseBody{reader: strings.NewReader(collision)}
			calls, wantCloses := 0, 1
			implementation := New()
			implementation.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if err := req.Body.Close(); err != nil {
					t.Error("request body close failed")
				}
				reply := &http.Response{StatusCode: http.StatusConflict, Header: make(http.Header), Body: responseBody, Request: req}
				switch mode {
				case "read-error":
					responseBody.readErr = io.ErrUnexpectedEOF
				case "close-error":
					responseBody.closeErr = errors.New("controlled close failure")
				case "cancel-during-read":
					responseBody.cancel = cancel
				case "lost-response":
					wantCloses = 0
					return nil, errors.New("controlled lost response")
				case "response-and-error":
					return reply, errors.New("controlled response and error")
				case "missing-body":
					wantCloses = 0
					reply.Body = nil
				case "synthesized-sdk-error":
					wantCloses = 0
					return nil, &googleapi.Error{Code: http.StatusConflict, Body: collision}
				}
				return reply, nil
			})
			got, err := implementation.execute(ctx, command, policy, payload, testCredential("token-1"))
			if err != nil || got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved || got.NormalizedStatus != 0 || got.SafeResourceID != "" || calls != 1 || responseBody.closes != wantCloses {
				t.Errorf("incomplete response acquired no-effect meaning: class=%d status=%d calls=%d closes=%d error=%t", got.Class, got.NormalizedStatus, calls, responseBody.closes, err != nil)
			}
		})
	}
}

// full_only: false
func TestGCPCreateCollisionStatusDoesNotQualifyOtherActions(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		t.Run(strconv.Itoa(int(action)), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			command, policy, payload := actionCommand(t, action)
			reads, mutations, other := 0, 0, 0
			implementation := New()
			implementation.transport = bodyTransport(func(req *http.Request) (*http.Response, error) {
				if req.Body != nil {
					if err := req.Body.Close(); err != nil {
						t.Error("request body close failed")
					}
				}
				body, status := `{"error":{"code":409,"status":"ALREADY_EXISTS"}}`, http.StatusConflict
				if req.Method == http.MethodGet && action != protocol.ActionWriteValue {
					reads++
					body, status = `{"name":"`+testParent+`","etag":"etag-1"}`, http.StatusOK
				} else {
					mutations++
					if req.URL.EscapedPath() != "/v1/"+testParent && req.URL.EscapedPath() != "/v1/"+testParent+":addVersion" {
						other++
					}
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
			})
			got, err := implementation.execute(ctx, command, policy, payload, testCredential("token-1"))
			wantReads := 1
			if action == protocol.ActionWriteValue {
				wantReads = 0
			}
			if err != nil || got.Entry != protocol.EntryMayHaveEntered || got.Class != protocol.ClassUnproved || got.NormalizedStatus != 0 || mutations != 1 || reads != wantReads || other != 0 {
				t.Errorf("create-only evidence changed another action: action=%d class=%d reads=%d mutations=%d other=%d error=%t", action, got.Class, reads, mutations, other, err != nil)
			}
		})
	}
}

func actionCommand(t *testing.T, action protocol.Action) (protocol.Command, protocol.Policy, []byte) {
	t.Helper()
	payload := []byte(nil)
	if action == protocol.ActionWriteValue {
		payload = []byte("one entry value")
	}
	command, policy := testCommand(t, payload)
	command.Action = action
	if action != protocol.ActionWriteValue {
		command.PayloadLengthMode, command.PayloadLength = protocol.LengthAbsent, 0
		command.ValueBasisDigest = protocol.ID{}
	}
	if action == protocol.ActionCreateEmpty || action == protocol.ActionDeleteReservedSlot {
		command.OwnedInstance = ""
		command.OwnedBirthAttemptID = protocol.ID{}
		command.BirthTargetRowDigest = protocol.ID{}
	}
	if action == protocol.ActionDeleteReservedSlot {
		command.UncertainCreateAttemptID = testID("uncertain create")
		command.ExclusiveNamespaceDigest = testID("exclusive namespace")
	}
	if action >= protocol.ActionDeleteOwned {
		policy = protocol.Policy{}
		command.PolicyDigest = protocol.ID{}
		command.PolicyContractID = policy.ContractID
	}
	if _, err := protocol.EncodeCommand(command); err != nil {
		t.Fatal(err)
	}
	return command, policy, payload
}

// full_only: false
func TestGCPV2ActionRequestAndResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action protocol.Action
		want   []string
	}{
		{"create", protocol.ActionCreateEmpty, []string{"POST /v1/projects/123456789012/secrets"}},
		{"delete-owned", protocol.ActionDeleteOwned, []string{"GET /v1/" + testParent, "DELETE /v1/" + testParent}},
		{"delete-reserved", protocol.ActionDeleteReservedSlot, []string{"GET /v1/" + testParent, "DELETE /v1/" + testParent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, policy, payload := actionCommand(t, tc.action)
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.EscapedPath())
				if r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer token-1" || r.GetBody != nil {
					t.Errorf("request transport differed")
				}
				switch {
				case tc.action == protocol.ActionCreateEmpty:
					if r.URL.Query().Get("secretId") != "Enkv_output-1" || r.URL.Query().Get("alt") != "json" {
						t.Error("create query differed")
					}
					body, _ := io.ReadAll(r.Body)
					if !bytes.Contains(body, []byte(`"automatic":{}`)) {
						t.Errorf("automatic replication missing: %s", body)
					}
					_, _ = io.WriteString(w, `{"name":"`+testParent+`","replication":{"automatic":{}}}`)
				case r.Method == "GET":
					_, _ = io.WriteString(w, `{"name":"`+testParent+`","etag":"etag-1"}`)
				case r.Method == "DELETE":
					if r.URL.Query().Get("etag") != "etag-1" {
						t.Error("delete guard absent")
					}
					_, _ = io.WriteString(w, "{}")
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			result, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || result.Entry != protocol.EntryMayHaveEntered ||
				result.Class != protocol.ClassAcknowledged || !reflect.DeepEqual(calls, tc.want) {
				t.Fatalf("action result=%#v err=%v calls=%v want=%v", result, err, calls, tc.want)
			}
		})
	}
}

// full_only: false
func TestGCPV2BeforeEntryRefusalAndDebugSecrecy(t *testing.T) {
	var count int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		_, _ = io.WriteString(w, `{"name":"`+testParent+`/versions/1","clientSpecifiedPayloadChecksum":true}`)
	}))
	defer server.Close()
	implementation := testImplementation(server)
	command, policy, payload := actionCommand(t, protocol.ActionWriteValue)
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	for _, mutate := range []func(*protocol.Command){
		func(c *protocol.Command) { c.ConditionalToken = "caller-token" },
		func(c *protocol.Command) { c.Target.CanonicalTarget = "projects/project-id/secrets/Enkv_output-1" },
		func(c *protocol.Command) { c.OwnedInstance = "projects/123456789013/secrets/Enkv_output-1" },
		func(c *protocol.Command) { c.Action = protocol.ActionCreateWithValue },
	} {
		bad := command
		mutate(&bad)
		got, err := implementation.execute(context.Background(), bad, policy, payload, testCredential("token-1"))
		if err != nil || got.Entry != protocol.EntryNotEntered || count != 0 {
			t.Fatalf("pre-entry refusal=%#v err=%v count=%d", got, err, count)
		}
	}
	sentinel := []byte("private-should-not-appear-in-debug")
	command.PayloadLength = uint32(len(sentinel))
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	defer func() { os.Stderr = originalStderr }()
	got, err := implementation.execute(context.Background(), command, policy, sentinel, testCredential("token-1"))
	_ = writer.Close()
	logged, readErr := io.ReadAll(io.LimitReader(reader, 4097))
	_ = reader.Close()
	if err != nil || readErr != nil || got.Class != protocol.ClassAcknowledged || count != 1 ||
		bytes.Contains(logged, sentinel) || bytes.Contains(logged, []byte("cHJpdmF0ZS1zaG91bGQ")) {
		t.Fatalf("debug secrecy result=%#v err=%v read=%v count=%d diagnostic-length=%d", got, err, readErr, count, len(logged))
	}
}

// full_only: false
func TestGCPV2ReadOnlyGuardRefusesBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action protocol.Action
		body   string
		status int
	}{
		{"missing-etag", protocol.ActionDeleteOwned, `{"name":"` + testParent + `"}`, 200},
		{"reserved-missing", protocol.ActionDeleteReservedSlot, `{"error":{"code":404}}`, 404},
		{"wrong-secret", protocol.ActionDeleteOwned, `{"name":"projects/123456789012/secrets/other","etag":"etag-1"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, policy, payload := actionCommand(t, tc.action)
			count := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count++
				if count != 1 || r.Method != "GET" {
					t.Error("a mutation followed refused read")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			got, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || count != 1 || got.Entry != protocol.EntryNotEntered ||
				got.Class != protocol.ClassQualifiedNoEffect {
				t.Fatalf("read-only refusal result=%#v err=%v calls=%d", got, err, count)
			}
		})
	}
}

// full_only: false
func TestGCPV2MutationFailureNeverRetries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action protocol.Action
		status int
	}{
		{"delete-conflict", protocol.ActionDeleteOwned, 409},
		{"delete-rate-limit", protocol.ActionDeleteReservedSlot, 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, policy, payload := actionCommand(t, tc.action)
			reads, writes := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					_, _ = io.WriteString(w, `{"name":"`+testParent+`","etag":"etag-1"}`)
					return
				}
				writes++
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":{"code":`+strconv.Itoa(tc.status)+`}}`)
			}))
			defer server.Close()
			got, err := testImplementation(server).execute(context.Background(), command, policy, payload, testCredential("token-1"))
			if err != nil || reads != 1 || writes != 1 || got.Entry != protocol.EntryMayHaveEntered ||
				got.Class != protocol.ClassUnproved {
				t.Fatalf("uncertain mutation result=%#v err=%v reads=%d writes=%d", got, err, reads, writes)
			}
		})
	}
}

// full_only: false
func TestGCPV2PassiveActionAndPolicyBounds(t *testing.T) {
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

type bodyTransport func(*http.Request) (*http.Response, error)

func (f bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedBody struct {
	io.Reader
	closes int
}

func (b *observedBody) Close() error { b.closes++; return nil }

type failingRead struct{}

func (failingRead) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// full_only: false
func TestGCPV2TransportReadFailureRetainsEntryAndCloses(t *testing.T) {
	for _, mutation := range []bool{false, true} {
		t.Run(strconv.FormatBool(mutation), func(t *testing.T) {
			method, path, query, contentType := "GET", "/v1/"+testParent+"",
				"alt=json&prettyPrint=false", ""
			if mutation {
				method, path, query, contentType = "POST", "/v1/"+testParent+":addVersion",
					"alt=json&prettyPrint=false", "application/json"
			}
			body := &observedBody{Reader: io.MultiReader(strings.NewReader("partial"), failingRead{})}
			guard := &operationTransport{endpoint: "https://secretmanager.googleapis.com", bearer: "Bearer token-1",
				rules: []requestRule{{method: method, path: path, query: query, contentType: contentType,
					requestLimit: maximumRequestBytes, replyLimit: maximumReplyBytes, mutation: mutation}},
				base: bodyTransport(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: req}, nil
				})}
			var requestBody io.Reader
			if mutation {
				requestBody = strings.NewReader("{}")
			}
			req, err := http.NewRequest(method, "https://secretmanager.googleapis.com"+path+"?"+query, requestBody)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer token-1")
			if mutation {
				req.Header.Set("Content-Type", contentType)
			}
			reply, err := guard.RoundTrip(req)
			if err == nil || reply != nil || body.closes != 1 || guard.didEnter() != mutation {
				t.Fatalf("read failure lost entry/close: reply=%v err=%v closes=%d entered=%v",
					reply != nil, err, body.closes, guard.didEnter())
			}
		})
	}
}

// full_only: false
func TestGCPV2TransportRequestExactLimitAndFirstOver(t *testing.T) {
	for _, size := range []int{maximumRequestBytes, maximumRequestBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			calls := 0
			guard := &operationTransport{endpoint: "https://secretmanager.googleapis.com", bearer: "Bearer token-1",
				rules: []requestRule{{method: "POST", path: "/v1/" + testParent + ":addVersion",
					query: "alt=json&prettyPrint=false", contentType: "application/json",
					requestLimit: maximumRequestBytes, replyLimit: maximumReplyBytes, mutation: true}},
				base: bodyTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					body, err := io.ReadAll(io.LimitReader(req.Body, maximumRequestBytes+1))
					if err != nil || len(body) != size {
						t.Errorf("admitted request body changed: bytes=%d err=%v", len(body), err)
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")),
						Header: make(http.Header), Request: req}, nil
				})}
			req, err := http.NewRequest(http.MethodPost,
				"https://secretmanager.googleapis.com/v1/"+testParent+
					":addVersion?alt=json&prettyPrint=false", bytes.NewReader(bytes.Repeat([]byte{'x'}, size)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer token-1")
			req.Header.Set("Content-Type", "application/json")
			reply, err := guard.RoundTrip(req)
			if size == maximumRequestBytes {
				if err != nil || reply == nil || !guard.didEnter() || calls != 1 {
					t.Fatalf("exact request refused: reply=%v err=%v calls=%d entered=%v",
						reply != nil, err, calls, guard.didEnter())
				}
				if err := reply.Body.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || reply != nil || guard.didEnter() || calls != 0 {
				t.Fatalf("first-over request admitted: reply=%v err=%v calls=%d entered=%v",
					reply != nil, err, calls, guard.didEnter())
			}
		})
	}
}

// full_only: false
func TestGCPV2TransportReplyExactLimitAndFirstOver(t *testing.T) {
	for _, size := range []int{maximumReplyBytes, maximumReplyBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			body := &observedBody{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, size))}
			calls := 0
			guard := &operationTransport{endpoint: "https://secretmanager.googleapis.com", bearer: "Bearer token-1",
				rules: []requestRule{{method: "GET", path: "/v1/" + testParent + "",
					query: "alt=json&prettyPrint=false", replyLimit: maximumReplyBytes}},
				base: bodyTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: req}, nil
				})}
			req, err := http.NewRequest(http.MethodGet,
				"https://secretmanager.googleapis.com/v1/"+testParent+
					"?alt=json&prettyPrint=false", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer token-1")
			reply, err := guard.RoundTrip(req)
			if size == maximumReplyBytes {
				if err != nil || reply == nil {
					t.Fatalf("exact reply refused: %v", err)
				}
				got, readErr := io.ReadAll(reply.Body)
				if readErr != nil || len(got) != size || reply.Body.Close() != nil {
					t.Fatalf("exact reply changed: len=%d read=%v", len(got), readErr)
				}
			} else if err == nil || reply != nil {
				t.Fatal("first-over reply admitted")
			}
			if calls != 1 || body.closes != 1 || guard.didEnter() {
				t.Fatalf("reply ownership/entry changed: calls=%d closes=%d entered=%v",
					calls, body.closes, guard.didEnter())
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
