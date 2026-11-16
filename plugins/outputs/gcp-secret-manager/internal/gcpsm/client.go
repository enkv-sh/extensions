package gcpsm

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	outputcredential "enkv.sh/plugins/outputs/gcp-secret-manager/credential"
	"enkv.sh/plugins/outputs/gcp-secret-manager/profile"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"
)

// Implementation uses the pinned generated client for metadata and a direct
// value request, both through the bounded fixed-request transport. Preparation
// captures ADC before payload readiness. The zero value is invalid; use
// NewImplementation to bind production callbacks.
type Implementation struct {
	output.Binding
	transport http.RoundTripper
	endpoint  string // Empty in production; controlled local tests only.
}

// New creates a production transport without a descriptor binding. It is an
// internal construction step; NewImplementation supplies the usable binding.
func New() Implementation {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return Implementation{transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DisableCompression: true, Protocols: protocols, MaxConnsPerHost: 1}}
}

func (i Implementation) send(ctx context.Context, command output.Preparation, policy protocol.Policy, payload, credential []byte) (output.Outcome, error) {
	if ctx == nil || ctx.Err() != nil || !policy.Valid() ||
		validateConsumer(command, policy) != nil || validateCredential(credential) != nil ||
		int(command.PayloadLength) != len(payload) || i.transport == nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	if command.Action == protocol.ActionWriteValue {
		bounds := command.Target.WriteValueBounds
		if len(payload) < int(bounds.Minimum) || len(payload) > int(bounds.Maximum) {
			return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
		}
	} else if len(payload) != 0 {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	captured, err := outputcredential.Decode(credential, time.Now())
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	ctx, cancel := context.WithDeadline(ctx, captured.Expiry)
	defer cancel()
	project, secretID, err := profile.ParseParent(command.Target.CanonicalTarget)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	base := endpoint
	if i.endpoint != "" {
		base = i.endpoint
	}
	guard := &operationTransport{base: i.transport, endpoint: base, bearer: "Bearer " + string(captured.Token), quotaProject: captured.QuotaProject,
		rules: actionRules(command, project, secretID)}
	client := &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if command.Action == protocol.ActionWriteValue {
		return i.writeValue(ctx, command, payload, base, guard, client)
	}
	// Pinned generated calls log complete request bodies at DEBUG. This logger
	// overrides ambient GOOGLE_SDK_GO_LOGGING_LEVEL, including secret payloads.
	service, err := secretmanager.NewService(ctx, option.WithHTTPClient(client),
		option.WithEndpoint(base+"/"), option.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	switch command.Action {
	case protocol.ActionCreateEmpty:
		secret := &secretmanager.Secret{Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{}}}
		call := service.Projects.Secrets.Create("projects/"+project, secret).SecretId(secretID).Context(ctx)
		call.Header().Set("Authorization", guard.bearer)
		created, err := call.Do()
		if err != nil || created == nil {
			if ctx.Err() == nil && guard.rejectedCreate() {
				return output.QualifiedNoEffect(protocol.EntryMayHaveEntered, http.StatusConflict, "", "")
			}
			return guard.failure()
		}
		if created.HTTPStatusCode != http.StatusOK || created.Name != command.Target.CanonicalTarget ||
			created.Replication == nil || created.Replication.Automatic == nil {
			return output.Unknown(protocol.EntryMayHaveEntered)
		}
		return output.Acknowledged(http.StatusOK, "", created.Name, "")
	case protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		get := service.Projects.Secrets.Get(command.Target.CanonicalTarget).Fields("name", "etag").Context(ctx)
		get.Header().Set("Authorization", guard.bearer)
		current, err := get.Do()
		if err != nil || current == nil || current.HTTPStatusCode != http.StatusOK ||
			current.Name != command.Target.CanonicalTarget || len(current.Etag) == 0 || len(current.Etag) > 1024 {
			return guard.failure()
		}
		guard.setExpectedEtag(current.Etag)
		del := service.Projects.Secrets.Delete(command.Target.CanonicalTarget).Etag(current.Etag).Context(ctx)
		del.Header().Set("Authorization", guard.bearer)
		deleted, err := del.Do()
		if err != nil || deleted == nil {
			return guard.failure()
		}
		if deleted.HTTPStatusCode != http.StatusOK {
			return output.Unknown(protocol.EntryMayHaveEntered)
		}
		return output.Acknowledged(http.StatusOK, "", command.Target.CanonicalTarget, "")
	}
	return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
}

type requestRule struct {
	method, path, query, contentType string
	requestLimit, replyLimit         int64
	mutation, create                 bool
}

func actionRules(command output.Preparation, project, secretID string) []requestRule {
	slot := "/v1/" + command.Target.CanonicalTarget
	q := "alt=json&prettyPrint=false"
	switch command.Action {
	case protocol.ActionCreateEmpty:
		return []requestRule{{method: "POST", path: "/v1/projects/" + project + "/secrets",
			query: q + "&secretId=" + url.QueryEscape(secretID), contentType: "application/json",
			requestLimit: 4096, replyLimit: 4096, mutation: true, create: true}}
	case protocol.ActionWriteValue:
		return []requestRule{{method: "POST", path: slot + ":addVersion", query: q,
			contentType: "application/json", requestLimit: 96 << 10, replyLimit: 4096, mutation: true}}
	case protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		return []requestRule{{method: "GET", path: slot, query: "alt=json&fields=name%2Cetag&prettyPrint=false", replyLimit: 4096},
			{method: "DELETE", path: slot, query: "", replyLimit: 4096, mutation: true}}
	}
	return nil
}

// The guard advances before entering the base transport. Even a failed call
// can have reached the service; no subsequent request may repeat that mutation.
type operationTransport struct {
	mu                              sync.Mutex
	base                            http.RoundTripper
	endpoint, bearer                string
	quotaProject                    string
	rules                           []requestRule
	next                            int
	mutationEntered, createRejected bool
	expectedEtag                    string
}

func (o *operationTransport) rejectedCreate() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.createRejected
}

func (o *operationTransport) setExpectedEtag(etag string) {
	o.mu.Lock()
	o.expectedEtag = etag
	o.mu.Unlock()
}

func (o *operationTransport) didEnter() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.mutationEntered
}

func (o *operationTransport) failure() (output.Outcome, error) {
	if o.didEnter() {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
}

// RoundTrip admits only the next fixed request and marks mutation entry before
// the base call. It closes refused request bodies and never grants replay after
// entry, including when the base transport returns an error.
func (o *operationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o.mu.Lock()
	var rule requestRule
	allowed := req.Context().Err() == nil && o.next < len(o.rules)
	if allowed {
		rule = o.rules[o.next]
		queryOK := req.URL.RawQuery == rule.query
		if rule.method == "DELETE" {
			// The generated Etag option is an ephemeral guard from the exact
			// preceding metadata GET. Require that exact observed value.
			v := req.URL.Query()
			queryOK = len(v) == 3 && v.Get("alt") == "json" && v.Get("prettyPrint") == "false" &&
				len(v["etag"]) == 1 && o.expectedEtag != "" && v.Get("etag") == o.expectedEtag
		}
		allowed = req.Method == rule.method && req.URL.Scheme+"://"+req.URL.Host == o.endpoint &&
			req.URL.EscapedPath() == rule.path && queryOK && req.Header.Get("Authorization") == o.bearer &&
			req.Header.Get("Content-Type") == rule.contentType && req.ContentLength >= 0 &&
			req.ContentLength <= rule.requestLimit && req.ProtoMajor == 1
	}
	if allowed {
		o.next++
		if rule.mutation {
			o.mutationEntered = true
		}
		req.GetBody = nil
		req.Close = true
		req.Header = http.Header{"Authorization": {o.bearer}}
		if rule.contentType != "" {
			req.Header.Set("Content-Type", rule.contentType)
		}
		if o.quotaProject != "" {
			req.Header.Set("X-Goog-User-Project", o.quotaProject)
		}
	}
	o.mu.Unlock()
	if !allowed {
		if req.Body != nil {
			return nil, errors.Join(errors.New("unapproved GCP output request"), req.Body.Close())
		}
		return nil, errors.New("unapproved GCP output request")
	}
	response, err := o.base.RoundTrip(req)
	if err != nil {
		if response != nil && response.Body != nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("missing GCP response body")
	}
	// Bound every response before the generated client decodes or logs it.
	body, readErr := io.ReadAll(io.LimitReader(response.Body, rule.replyLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > rule.replyLimit {
		clear(body)
		return nil, errors.New("GCP output response unavailable")
	}
	if rule.create && response.StatusCode == http.StatusConflict && req.Context().Err() == nil && createCollisionResponse(body) {
		o.mu.Lock()
		o.createRejected = true
		o.mu.Unlock()
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func createCollisionResponse(body []byte) bool {
	if !jsontext.Value(body).IsValid() {
		return false
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 1 {
		return false
	}
	var status map[string]json.RawMessage
	if json.Unmarshal(envelope["error"], &status) != nil {
		return false
	}
	var code int
	var name string
	if json.Unmarshal(status["code"], &code) != nil || code != http.StatusConflict ||
		json.Unmarshal(status["status"], &name) != nil || name != "ALREADY_EXISTS" {
		return false
	}
	for field, value := range status {
		switch field {
		case "code", "status":
		case "message":
			if jsontext.Value(value).Kind() != '"' {
				return false
			}
		case "details":
			if jsontext.Value(value).Kind() != '[' {
				return false
			}
			var details []map[string]json.RawMessage
			if json.Unmarshal(value, &details) != nil {
				return false
			}
			for _, detail := range details {
				var kind string
				if jsontext.Value(detail["@type"]).Kind() != '"' || json.Unmarshal(detail["@type"], &kind) != nil || kind == "" {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
