package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/crypto/nacl/box"
)

const (
	apiHost                  = "https://api.github.com"
	apiVersion               = "2026-03-10"
	maximumReadResponseBytes = 4096
	maximumEffectReplyBytes  = 4096
	maximumKeyIDBytes        = 256
)

// Implementation has one static scope and one HTTP/1-only transport. Construct
// it with New; the zero value is invalid. Preparation owns per-invocation client
// state and credentials.
type Implementation struct {
	scope     profile.Scope
	endpoint  string // Empty override is never offered by the production constructor.
	transport http.RoundTripper
	output.Binding
}

func newTransport(scope profile.Scope) Implementation {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return Implementation{scope: scope, endpoint: apiHost, transport: &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		Protocols: protocols, MaxConnsPerHost: 1}}
}

// Send borrows payload until return, seals value bytes with the captured key and
// consumes one mutation attempt. Value actions require a nonnil slice, including
// for zero bytes; metadata actions require nil. Close remains required after any
// result, and an unknown acknowledgement never permits resend.
func (p *prepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	c := p.command
	if ctx == nil {
		return refused(profile.ErrProfile)
	}
	if p.closed || p.sent {
		return refused(profile.ErrProfile)
	}
	p.sent = true
	if ctx.Err() != nil {
		return notEntered()
	}
	value := c.Action == protocol.ActionCreateWithValue || c.Action == protocol.ActionWriteValue
	if value && payload == nil || !value && payload != nil || len(payload) != int(c.PayloadLength) || value && len(payload) > MaximumRawValueBytes {
		return notEntered()
	}
	var body []byte
	var err error
	if value {
		sealed, sealErr := box.SealAnonymous(nil, payload, &p.publicKey, rand.Reader)
		if sealErr != nil {
			return notEntered()
		}
		defer clear(sealed)
		body, err = valueBody(sealed, p.keyID, p.policy, p.implementation.scope)
	} else if c.Action == protocol.ActionUpdatePolicy {
		body, err = selectedPolicyBody(p.policy.NumberSubjects)
	}
	if err != nil {
		return notEntered()
	}
	req, err := request(ctx, p.guard.effectMethod, p.implementation.endpoint+p.guard.effectPath, p.token, body)
	if err != nil {
		return notEntered()
	}
	response, err := p.client.Do(req)
	if err != nil {
		return p.guard.failure()
	}
	reply, err := readBounded(response, maximumEffectReplyBytes)
	defer clear(reply)
	if err != nil {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	switch c.Action {
	case protocol.ActionCreateWithValue:
		if response.StatusCode == http.StatusCreated {
			if len(reply) != 0 {
				trimmed := bytes.Trim(reply, " \t\r\n")
				if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || len(bytes.Trim(trimmed[1:len(trimmed)-1], " \t\r\n")) != 0 {
					return output.Unknown(protocol.EntryMayHaveEntered)
				}
			}
			return output.Acknowledged(http.StatusCreated, "", c.Target.CanonicalTarget, "")
		}
	case protocol.ActionWriteValue, protocol.ActionUpdatePolicy, protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		if response.StatusCode == http.StatusNoContent && len(reply) == 0 {
			return output.Acknowledged(http.StatusNoContent, "", c.Target.CanonicalTarget, "")
		}
	}
	return output.Unknown(protocol.EntryMayHaveEntered)
}

func readBounded(response *http.Response, maximum int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, profile.ErrProfile
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > maximum {
		clear(body)
		return nil, profile.ErrProfile
	}
	return body, nil
}

// Preparation must not choose an identity or policy from ambiguous fields.
func responseObject(body []byte) (map[string]json.RawMessage, error) {
	if len(body) > maximumReadResponseBytes || !utf8.Valid(body) {
		return nil, profile.ErrProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, profile.ErrProfile
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, profile.ErrProfile
		}
		for prior := range fields {
			if strings.EqualFold(prior, name) {
				return nil, profile.ErrProfile
			}
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, profile.ErrProfile
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, profile.ErrProfile
	}
	return fields, nil
}

func (i Implementation) getKey(ctx context.Context, client *http.Client, path string,
	credential []byte) ([32]byte, string, error) {
	req, err := request(ctx, http.MethodGet, i.endpoint+path, credential, nil)
	if err != nil {
		return [32]byte{}, "", profile.ErrProfile
	}
	response, err := client.Do(req)
	if err != nil {
		return [32]byte{}, "", profile.ErrProfile
	}
	body, err := readBounded(response, maximumReadResponseBytes)
	defer clear(body)
	if err != nil || response.StatusCode != http.StatusOK {
		return [32]byte{}, "", profile.ErrProfile
	}
	fields, err := responseObject(body)
	if err != nil || len(fields) != 2 || fields["key_id"] == nil || fields["key"] == nil {
		return [32]byte{}, "", profile.ErrProfile
	}
	var reply struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if json.Unmarshal(body, &reply) != nil ||
		len(reply.KeyID) == 0 || len(reply.KeyID) > maximumKeyIDBytes {
		return [32]byte{}, "", profile.ErrProfile
	}
	for _, b := range []byte(reply.KeyID) {
		if b < '!' || b > '~' || b == '"' || b == '\\' {
			return [32]byte{}, "", profile.ErrProfile
		}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(reply.Key)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, "", profile.ErrProfile
	}
	var publicKey [32]byte
	copy(publicKey[:], decoded)
	return publicKey, reply.KeyID, nil
}

func (i Implementation) getSelectedMetadata(ctx context.Context, client *http.Client, path string,
	credential []byte, slot string) error {
	req, err := request(ctx, http.MethodGet, i.endpoint+path, credential, nil)
	if err != nil {
		return profile.ErrProfile
	}
	response, err := client.Do(req)
	if err != nil {
		return profile.ErrProfile
	}
	body, err := readBounded(response, maximumReadResponseBytes)
	defer clear(body)
	if err != nil || response.StatusCode != http.StatusOK {
		return profile.ErrProfile
	}
	fields, err := responseObject(body)
	if err != nil || fields["name"] == nil || fields["visibility"] == nil {
		return profile.ErrProfile
	}
	var reply struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	}
	if json.Unmarshal(body, &reply) != nil ||
		reply.Name != slot[strings.LastIndexByte(slot, '/')+1:] || reply.Visibility != "selected" {
		return profile.ErrProfile
	}
	return nil
}

func request(ctx context.Context, method, url string, credential, body []byte) (*http.Request, error) {
	var owner io.ReadCloser
	var reader io.Reader
	if len(body) != 0 {
		owner = output.TakeRequestBody(body)
		reader = owner
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		if owner != nil {
			_ = owner.Close()
		}
		return nil, err
	}
	req.ContentLength = int64(len(body))
	req.GetBody = nil
	req.Close = true
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Authorization", "Bearer "+string(credential))
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func selectedPolicyBody(ids []uint64) ([]byte, error) {
	if len(ids) > profile.MaximumSelectedRepositories {
		return nil, profile.ErrProfile
	}
	body := make([]byte, 0, 32+21*len(ids))
	body = append(body, `{"selected_repository_ids":[`...)
	for n, id := range ids {
		if n != 0 {
			body = append(body, ',')
		}
		body = strconv.AppendUint(body, id, 10)
		if len(body) > maximumPutBodyBytes {
			clear(body)
			return nil, profile.ErrProfile
		}
	}
	body = append(body, ']', '}')
	if len(body) > maximumPutBodyBytes {
		clear(body)
		return nil, profile.ErrProfile
	}
	return body, nil
}

func valueBody(sealed []byte, keyID string, policy profile.Policy, scope profile.Scope) ([]byte, error) {
	if len(sealed) > MaximumRawValueBytes+box.AnonymousOverhead || len(keyID) > maximumKeyIDBytes || len(policy.NumberSubjects) > profile.MaximumSelectedRepositories {
		return nil, profile.ErrProfile
	}
	encodedLength := base64.StdEncoding.EncodedLen(len(sealed))
	// Reserve all selected IDs so sensitive wire storage never moves to an
	// abandoned backing allocation while the JSON body grows.
	body := make([]byte, 0, encodedLength+maximumKeyIDBytes+128+21*len(policy.NumberSubjects))
	body = append(body, `{"encrypted_value":"`...)
	prefixLength := len(body)
	body = body[:prefixLength+encodedLength]
	base64.StdEncoding.Encode(body[prefixLength:], sealed)
	body = append(body, `","key_id":`...)
	body = strconv.AppendQuote(body, keyID)
	if scope == profile.Organization {
		var visibility string
		switch policy.Mode {
		case profile.PolicyWholeScope:
			visibility = "all"
		case profile.PolicyRestrictedScope:
			visibility = "private"
		case profile.PolicyExplicitSet:
			visibility = "selected"
		default:
			clear(body)
			return nil, profile.ErrProfile
		}
		body = append(body, `,"visibility":"`...)
		body = append(body, visibility...)
		body = append(body, '"')
		if policy.Mode == profile.PolicyExplicitSet {
			body = append(body, `,"selected_repository_ids":[`...)
			for n, id := range policy.NumberSubjects {
				if n != 0 {
					body = append(body, ',')
				}
				body = strconv.AppendUint(body, id, 10)
				if len(body) > maximumPutBodyBytes {
					clear(body)
					return nil, profile.ErrProfile
				}
			}
			body = append(body, ']')
		}
	}
	body = append(body, '}')
	if len(body) > maximumPutBodyBytes {
		clear(body)
		return nil, profile.ErrProfile
	}
	return body, nil
}

// Record entry before the base transport call: a transport error cannot prove
// that the mutation stayed local. The guard also prevents a second send.
type operationTransport struct {
	mu                                 sync.Mutex
	base                               http.RoundTripper
	endpoint, bearer                   string
	readPath, effectPath, effectMethod string
	readDone, entered                  bool
}

func (o *operationTransport) didEnter() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.entered
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
	allowed := req.URL.Scheme+"://"+req.URL.Host == o.endpoint && req.URL.RawQuery == "" &&
		req.GetBody == nil && req.Close && req.ProtoMajor == 1 &&
		req.Header.Get("Accept") == "application/vnd.github+json" &&
		req.Header.Get("X-GitHub-Api-Version") == apiVersion &&
		req.Header.Get("Authorization") == o.bearer && req.ContentLength >= 0
	if allowed {
		switch {
		case o.readPath != "" && !o.readDone && !o.entered && req.Method == http.MethodGet &&
			req.URL.EscapedPath() == o.readPath && req.ContentLength == 0 && req.Header.Get("Content-Type") == "":
			o.readDone = true
		case (o.readPath == "" || o.readDone) && !o.entered && req.Method == o.effectMethod &&
			req.URL.EscapedPath() == o.effectPath &&
			(req.Method == http.MethodPut && req.Header.Get("Content-Type") == "application/json" &&
				req.ContentLength <= maximumPutBodyBytes ||
				req.Method == http.MethodDelete && req.Header.Get("Content-Type") == "" && req.ContentLength == 0):
			o.entered = true
		default:
			allowed = false
		}
	}
	o.mu.Unlock()
	if !allowed {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("unapproved GitHub output request")
	}
	response, err := o.base.RoundTrip(req)
	if err != nil && response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
	}
	return response, err
}

func refused(cause error) (output.Outcome, error) {
	outcome, err := notEntered()
	return outcome, errors.Join(cause, err)
}

func notEntered() (output.Outcome, error) {
	return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
}
