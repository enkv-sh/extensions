package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

var errSettings = errors.New("local token settings invalid")

const tokenVariable = "ENKV_EXAMPLE_TOKEN"

type settings struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Subject   string `json:"subject"`
}
type target struct {
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
}
type resource struct {
	ID string `json:"id"`
}

func resourceContractID() protocol.ID {
	return protocol.ID(sha256.Sum256([]byte("example/local-token-resource/v1")))
}

func implementation() (generator.Implementation, error) {
	config := protocol.ID(sha256.Sum256([]byte("example/local-token-config/v1")))
	binding, err := generator.Bind(descriptorBytes, config)
	if err != nil {
		return generator.Implementation{}, fmt.Errorf("local token binding: descriptor: %w: %w", errSettings, err)
	}
	route := binding.CredentialRoute()
	if route.Mode != credentialroute.ModeEnvironment || len(route.Names) != 1 || route.Names[0] != tokenVariable || len(route.PublicData) != 0 {
		return generator.Implementation{}, errSettings
	}
	return generator.Implementation{Binding: binding,
		Normalize: func(_ context.Context, request protocol.NormalizeRequest) (protocol.Intent, error) {
			s, err := parseSettings(request.Settings, true)
			if err != nil {
				return protocol.Intent{}, err
			}
			canonical, err := json.Marshal(s)
			if err != nil {
				return protocol.Intent{}, err
			}
			return protocol.Intent{Schema: 1, ConfigContractID: config, LifecycleMode: protocol.LifecycleManaged, ResourceContractID: resourceContractID(), Settings: canonical}, nil
		},
		ValidateCanonical: func(_ context.Context, intent protocol.Intent) error {
			if intent.ConfigContractID != config || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID != resourceContractID() {
				return errSettings
			}
			_, err := parseSettings(intent.Settings, false)
			return err
		},
		CheckRetirementCompatibility: compatible, Create: createToken, Retire: retireToken}, nil
}

func parseSettings(body []byte, defaults bool) (settings, error) {
	var s settings
	if !utf8.Valid(body) {
		return s, errSettings
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || decoder.Decode(new(any)) != io.EOF {
		return settings{}, errSettings
	}
	if defaults {
		s.Endpoint = strings.TrimSuffix(s.Endpoint, "/")
		s.Namespace = strings.ToLower(strings.TrimSpace(s.Namespace))
		if s.Namespace == "" {
			s.Namespace = "example"
		}
		if s.Subject == "" {
			s.Subject = "token"
		}
	}
	u, err := url.Parse(s.Endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" {
		return settings{}, errSettings
	}
	address, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if err != nil || !address.IsLoopback() || portErr != nil || port < 1 || port > 65535 {
		return settings{}, errSettings
	}
	if len(s.Namespace) < 1 || len(s.Namespace) > 64 || len(s.Subject) < 1 || len(s.Subject) > 256 || !utf8.ValidString(s.Subject) {
		return settings{}, errSettings
	}
	for _, c := range s.Namespace {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return settings{}, errSettings
		}
	}
	canonical, err := json.Marshal(s)
	if err != nil || !defaults && !bytes.Equal(canonical, body) {
		return settings{}, errSettings
	}
	return s, nil
}
func intentSettings(command protocol.Command) (settings, error) {
	intent, err := protocol.DecodeIntent(command.Intent)
	if err != nil || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID != resourceContractID() {
		return settings{}, errSettings
	}
	return parseSettings(intent.Settings, false)
}
func targetBytes(s settings) []byte {
	body, _ := json.Marshal(target{Endpoint: s.Endpoint, Namespace: s.Namespace})
	return body
}
func resourceBytes(id string) []byte { body, _ := json.Marshal(resource{ID: id}); return body }
func parseResource(b []byte) (resource, error) {
	var r resource
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || !resourceIDValid(r.ID) {
		return resource{}, errSettings
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(canonical, b) {
		return resource{}, errSettings
	}
	return r, nil
}
func resourceIDValid(id string) bool {
	if len(id) < 2 || len(id) > 21 || id[0] != 't' {
		return false
	}
	n, err := strconv.ParseUint(id[1:], 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == id[1:]
}

func compatible(_ context.Context, request protocol.RetirementCompatibilityRequest) (bool, error) {
	intent, err := protocol.DecodeIntent(request.Intent)
	if err != nil || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID != resourceContractID() || request.CompletionClass != protocol.CompletionAcknowledged {
		return false, nil
	}
	s, err := parseSettings(intent.Settings, false)
	if err != nil {
		return false, nil
	}
	facts, err := protocol.DecodeSafeFacts(request.OriginalFacts)
	if err != nil || !bytes.Equal(facts.Target, targetBytes(s)) {
		return false, nil
	}
	_, err = parseResource(facts.ResourceData)
	return err == nil, nil
}

func createToken(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
	command := inv.Command
	s, err := intentSettings(command)
	if err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	client, token, err := effectClient()
	if err != nil {
		return command.NewFacts(protocol.DispositionConfirmedNoEffect, protocol.ReasonRejected), nil, nil
	}
	defer client.CloseIdleConnections()
	if err := checkSession(ctx, client, s, token); err != nil {
		return command.NewFacts(protocol.DispositionConfirmedNoEffect, protocol.ReasonRejected), nil, nil
	}
	requestBody, err := json.Marshal(struct {
		Namespace string `json:"namespace"`
		Subject   string `json:"subject"`
	}{s.Namespace, s.Subject})
	if err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	status, body, err := request(ctx, client, http.MethodPost, s.Endpoint+"/tokens", token, requestBody, 131072)
	defer clear(body)
	if err != nil {
		return command.NewFacts(protocol.DispositionUnknown, protocol.ReasonTransport), nil, nil
	}
	if status != http.StatusCreated {
		return command.NewFacts(protocol.DispositionUnknown, protocol.ReasonRejected), nil, nil
	}
	var response struct {
		ID    string `json:"id"`
		Value string `json:"value_base64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || !resourceIDValid(response.ID) {
		return command.NewFacts(protocol.DispositionUnknown, protocol.ReasonMalformed), nil, nil
	}
	facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	facts.Target, facts.ResourceData = targetBytes(s), resourceBytes(response.ID)
	value, decodeErr := base64.StdEncoding.Strict().DecodeString(response.Value)
	if decodeErr != nil || len(value) == 0 || len(value) > protocol.MaximumSecretLength {
		clear(value[:cap(value)])
		facts.Disposition, facts.Reason = protocol.DispositionOwnedUnusableCreate, protocol.ReasonInvalidValue
		return facts, nil, nil
	}
	return facts, value, nil
}

func retireToken(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, error) {
	command := inv.Command
	s, err := intentSettings(command)
	if err != nil {
		return protocol.SafeFacts{}, err
	}
	original, err := protocol.DecodeSafeFacts(command.OriginalFacts)
	if err != nil || !bytes.Equal(original.Target, targetBytes(s)) {
		return protocol.SafeFacts{}, errSettings
	}
	owned, err := parseResource(original.ResourceData)
	if err != nil {
		return protocol.SafeFacts{}, err
	}
	facts := command.NewFacts(protocol.DispositionUnknown, protocol.ReasonRejected)
	facts.Target, facts.ResourceData = bytes.Clone(original.Target), bytes.Clone(original.ResourceData)
	client, token, err := effectClient()
	if err != nil {
		return facts, nil
	}
	defer client.CloseIdleConnections()
	if checkSession(ctx, client, s, token) != nil {
		return facts, nil
	}
	status, body, err := request(ctx, client, http.MethodDelete, s.Endpoint+"/tokens/"+owned.ID, token, nil, 4096)
	clear(body)
	if err != nil {
		facts.Reason = protocol.ReasonTransport
		return facts, nil
	}
	if status == http.StatusNoContent {
		facts.Disposition, facts.Reason = protocol.DispositionRetirementAcknowledged, protocol.ReasonNone
	}
	return facts, nil
}

func effectClient() (*http.Client, string, error) {
	token := os.Getenv(tokenVariable)
	if token == "" || len(token) > 1024 || strings.ContainsAny(token, "\x00\r\n") {
		return nil, "", errSettings
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8192}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token, nil
}
func checkSession(ctx context.Context, client *http.Client, s settings, token string) error {
	status, body, err := request(ctx, client, http.MethodGet, s.Endpoint+"/session", token, nil, 4096)
	defer clear(body)
	if err != nil || status != http.StatusOK {
		return errSettings
	}
	var session struct {
		Namespace string `json:"namespace"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&session) != nil || decoder.Decode(new(any)) != io.EOF || session.Namespace != s.Namespace {
		return errSettings
	}
	return nil
}
func request(ctx context.Context, client *http.Client, method, location, token string, payload []byte, limit int) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, location, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	closeErr := response.Body.Close()
	if len(body) > limit {
		clear(body)
		return response.StatusCode, nil, errSettings
	}
	if err := errors.Join(readErr, closeErr); err != nil {
		clear(body)
		return response.StatusCode, nil, err
	}
	return response.StatusCode, body, nil
}
