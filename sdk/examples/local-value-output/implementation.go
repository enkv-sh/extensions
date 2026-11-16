package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

const configContract = "local-values-config/v1"
const serviceContract = "local-values-service/v1"
const targetContract = "local-values-target/v1"

var errLocalValue = errors.New("local value request refused")

const actions protocol.ActionCapabilities = protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityDeleteOwned

type settings struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
}
type targetData struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
}
type implementation struct{ output.Binding }

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errLocalValue
	}
	return nil
}
func namespaceValid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func endpoint(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return "", errLocalValue
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return "", errLocalValue
	}
	u.Path = ""
	return u.String(), nil
}
func canonicalSettings(raw []byte) (settings, []byte, error) {
	var v settings
	if decodeJSON(raw, &v) != nil {
		return settings{}, nil, errLocalValue
	}
	var err error
	v.Endpoint, err = endpoint(v.Endpoint)
	if err != nil {
		return settings{}, nil, err
	}
	if v.Namespace == "" {
		v.Namespace = "dev"
	}
	if !namespaceValid(v.Namespace) {
		return settings{}, nil, errLocalValue
	}
	encoded, err := json.Marshal(v)
	return v, encoded, err
}

// NormalizeDestination applies local defaults and returns independent canonical settings.
func (p *implementation) NormalizeDestination(ctx context.Context, settings []byte) (protocol.Destination, error) {
	if ctx.Err() != nil {
		return protocol.Destination{}, ctx.Err()
	}
	_, data, err := canonicalSettings(settings)
	if err != nil {
		return protocol.Destination{}, err
	}
	return protocol.Destination{ConfigContractID: configContract, ServiceContractID: serviceContract, CanonicalSettings: data, Capabilities: actions}, nil
}

// ValidateCanonical accepts only exact retained local settings and capabilities.
func (p *implementation) ValidateCanonical(ctx context.Context, destination protocol.Destination) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	v := destination
	_, data, err := canonicalSettings(v.CanonicalSettings)
	if err != nil || v.ConfigContractID != configContract || v.ServiceContractID != serviceContract || v.Capabilities != actions || v.Policy.Present() || len(v.Policy.Data) != 0 || !bytes.Equal(data, v.CanonicalSettings) {
		return errLocalValue
	}
	return nil
}

// InterpretTarget makes a stable physical URL and self-contained deletion facts.
func (p *implementation) InterpretTarget(ctx context.Context, r output.TargetRequest) (protocol.Target, error) {
	if p.ValidateCanonical(ctx, r.Destination) != nil {
		return protocol.Target{}, errLocalValue
	}
	var v settings
	if decodeJSON(r.Destination.CanonicalSettings, &v) != nil {
		return protocol.Target{}, errLocalValue
	}
	key := base64.RawURLEncoding.EncodeToString([]byte(r.EntryName))
	data, err := json.Marshal(targetData{v.Endpoint, v.Namespace, key})
	if err != nil {
		return protocol.Target{}, err
	}
	locator := v.Endpoint + "/values/" + v.Namespace + "/" + key
	return protocol.Target{ServiceContractID: serviceContract, TargetContractID: targetContract, CanonicalTarget: locator, ConsumerLocator: locator, TargetData: data, PayloadEncoding: r.PayloadEncoding, Capabilities: actions, CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}, nil
}
func actionBounds(capabilities protocol.ActionCapabilities, action protocol.Action) protocol.PayloadBounds {
	if capabilities.Has(action) {
		return protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}
	}
	return protocol.PayloadBounds{}
}
func readTarget(t protocol.Target) (targetData, error) {
	var v targetData
	if !t.Valid() || t.ServiceContractID != serviceContract || t.TargetContractID != targetContract || t.Capabilities & ^actions != 0 || t.CreateValueBounds != actionBounds(t.Capabilities, protocol.ActionCreateWithValue) || t.WriteValueBounds != actionBounds(t.Capabilities, protocol.ActionWriteValue) || t.LocatorRequiresCreation || decodeJSON(t.TargetData, &v) != nil || !namespaceValid(v.Namespace) {
		return targetData{}, errLocalValue
	}
	ep, err := endpoint(v.Endpoint)
	if err != nil || ep != v.Endpoint {
		return targetData{}, errLocalValue
	}
	key, err := base64.RawURLEncoding.DecodeString(v.Key)
	if err != nil || len(key) > 256 || base64.RawURLEncoding.EncodeToString(key) != v.Key {
		return targetData{}, errLocalValue
	}
	expected := v.Endpoint + "/values/" + v.Namespace + "/" + v.Key
	encoded, _ := json.Marshal(v)
	if !bytes.Equal(encoded, t.TargetData) || t.CanonicalTarget != expected || t.ConsumerLocator != expected {
		return targetData{}, errLocalValue
	}
	return v, nil
}

// CheckAction validates local target semantics and repeats the action's exact bounds.
func (p *implementation) CheckAction(ctx context.Context, r output.ActionCheck, policy protocol.Policy) (protocol.PayloadBounds, error) {
	if ctx.Err() != nil {
		return protocol.PayloadBounds{}, ctx.Err()
	}
	if protocol.ValidateActionPayload(r.Action, r.Target, r.PayloadLengthMode, r.PayloadLength) != nil || policy.Present() || len(policy.Data) != 0 {
		return protocol.PayloadBounds{}, errLocalValue
	}
	if _, err := readTarget(r.Target); err != nil {
		return protocol.PayloadBounds{}, err
	}
	switch r.Action {
	case protocol.ActionCreateWithValue, protocol.ActionWriteValue:
		return protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, nil
	case protocol.ActionDeleteOwned:
		return protocol.PayloadBounds{}, nil
	default:
		return protocol.PayloadBounds{}, errLocalValue
	}
}

// Prepare checks the credential namespace without mutation. The returned
// invocation owns a private token copy; output.Main supplies the native environment.
func (p *implementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, _ []credentialroute.Input) (output.Prepared, error) {
	if _, err := p.CheckAction(ctx, output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, ConditionalTokenLength: uint16(len(c.ConditionalToken)), PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}, policy); err != nil {
		return nil, err
	}
	target, err := readTarget(c.Target)
	if err != nil {
		return nil, err
	}
	token, found := os.LookupEnv("ENKV_EXAMPLE_TOKEN")
	if !found || len(token) == 0 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return nil, errLocalValue
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1}
	prepared := &prepared{command: c, token: []byte(token), transport: transport, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	transferred := false
	defer func() {
		if !transferred {
			prepared.dispose()
		}
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.Endpoint+"/session", nil)
	if err != nil {
		return nil, errLocalValue
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := prepared.client.Do(request)
	if err != nil {
		return nil, errLocalValue
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	var session struct {
		Namespace string `json:"namespace"`
	}
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(body) > 4096 || decodeJSON(body, &session) != nil || session.Namespace != target.Namespace {
		return nil, errLocalValue
	}
	transferred = true
	return prepared, nil
}

type prepared struct {
	command      output.Preparation
	token        []byte
	transport    *http.Transport
	client       *http.Client
	sent, closed bool
}

func resourceIDValid(s string) bool {
	if len(s) < 2 || len(s) > 20 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s[1] != '0'
}

// Send attempts one guarded mutation. The request body owns a copy so a
// transport may finish reading after this call returns; it must close that copy.
func (p *prepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	result := output.Outcome{}
	result.Entry = protocol.EntryNotEntered
	if p.sent || p.closed {
		return result, errLocalValue
	}
	p.sent = true
	method := http.MethodPost
	switch p.command.Action {
	case protocol.ActionWriteValue:
		method = http.MethodPut
	case protocol.ActionDeleteOwned:
		method = http.MethodDelete
	}
	value := method != http.MethodDelete
	if (payload != nil) != value || len(payload) != int(p.command.PayloadLength) {
		return result, errLocalValue
	}
	if method != http.MethodPost && !resourceIDValid(p.command.OwnedInstance) {
		return result, errLocalValue
	}
	var requestBody io.ReadCloser = http.NoBody
	if len(payload) != 0 {
		requestBody = output.CopyRequestBody(payload)
	}
	handed := false
	defer func() {
		if !handed {
			_ = requestBody.Close()
		}
	}()
	request, err := http.NewRequestWithContext(ctx, method, p.command.Target.CanonicalTarget, requestBody)
	if err != nil {
		return result, errLocalValue
	}
	request.ContentLength = int64(len(payload))
	// No replay body: a transport failure after entry cannot grant a resend.
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+string(p.token))
	request.Header.Set("Content-Type", "application/octet-stream")
	if method == http.MethodPost {
		request.Header.Set("If-None-Match", "*")
	} else {
		request.Header.Set("If-Match", strconv.Quote(p.command.OwnedInstance))
	}
	result.Entry = protocol.EntryMayHaveEntered
	handed = true
	response, err := p.client.Do(request)
	if err != nil {
		return result, errLocalValue
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > 4096 {
		return result, errLocalValue
	}
	if response.StatusCode == http.StatusPreconditionFailed {
		return output.QualifiedNoEffect(protocol.EntryMayHaveEntered, 412, "", "")
	}
	status := http.StatusNoContent
	if method == http.MethodPost {
		status = http.StatusCreated
	}
	id := response.Header.Get("X-Resource-ID")
	if method == http.MethodDelete {
		id = p.command.OwnedInstance
	}
	if response.StatusCode != status || len(body) != 0 || !resourceIDValid(id) || method != http.MethodDelete && response.Header.Get("ETag") != strconv.Quote(id) || method != http.MethodPost && id != p.command.OwnedInstance {
		return result, errLocalValue
	}
	return output.Acknowledged(uint16(status), "", id, "")
}

// Close clears the private token and closes idle connections. Transport-owned
// request bodies clear their separate copies when the transport closes them.
func (p *prepared) Close() error { p.dispose(); return nil }
func (p *prepared) dispose() {
	if p.closed {
		return
	}
	p.closed = true
	clear(p.token)
	p.transport.CloseIdleConnections()
}

// SelectPolicyAction refuses because local values have no publication policy.
func (p *implementation) SelectPolicyAction(context.Context, output.PolicyActionSelection, protocol.Policy) (protocol.Action, error) {
	return 0, errLocalValue
}
