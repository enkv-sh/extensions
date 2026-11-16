// Package github implements the three fixed GitHub Actions secret scopes.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"enkv.sh/plugins/outputs/github-actions/credential"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

type settings struct {
	Owner        string   `json:"owner"`
	Repository   string   `json:"repository,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Visibility   string   `json:"visibility,omitempty"`
	Repositories []uint64 `json:"repositories,omitempty"`
}

// New binds the descriptor to one scope and the exact GITHUB_TOKEN route, with
// a fixed production endpoint. It performs no discovery. Invalid scope or
// descriptor contracts return an error; local refusals include profile.ErrProfile.
func New(scope profile.Scope, descriptorBytes []byte) (Implementation, error) {
	binding, err := output.Bind(descriptorBytes, profile.ConfigContractID(scope))
	if err != nil {
		return Implementation{}, fmt.Errorf("GitHub binding: descriptor: %w: %w", profile.ErrProfile, err)
	}
	route := binding.CredentialRoute()
	expected, err := credentialroute.Encode(profile.CredentialRoute())
	if err != nil {
		return Implementation{}, err
	}
	actual, err := credentialroute.Encode(route)
	if err != nil {
		return Implementation{}, err
	}
	if !bytes.Equal(expected, actual) {
		return Implementation{}, fmt.Errorf("GitHub binding: descriptor.output.credential_route: unsupported route: %w", profile.ErrProfile)
	}
	implementation := newTransport(scope)
	implementation.Binding = binding
	return implementation, nil
}

func decodeSettings(body []byte) (settings, error) {
	var s settings
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if len(body) > protocol.MaximumSettingsBytes || decoder.Decode(&s) != nil || decoder.Decode(new(any)) != io.EOF {
		return settings{}, profile.ErrProfile
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return settings{}, profile.ErrProfile
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[strings.ToLower(key)] {
			return settings{}, profile.ErrProfile
		}
		switch key {
		case "owner", "repository", "environment", "visibility", "repositories":
		default:
			return settings{}, profile.ErrProfile
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return settings{}, profile.ErrProfile
		}
	}
	return s, nil
}
func (s settings) destination(scope profile.Scope) (profile.Destination, profile.Policy, error) {
	if scope != profile.Organization && (s.Visibility != "" || len(s.Repositories) != 0) {
		return profile.Destination{}, profile.Policy{}, profile.ErrProfile
	}
	var p profile.Policy
	if scope == profile.Organization {
		p.ClassID = "github-actions/org-visibility"
		p.NumberSubjects = s.Repositories
		switch s.Visibility {
		case "all":
			p.Mode = profile.PolicyWholeScope
		case "private":
			p.Mode = profile.PolicyRestrictedScope
		case "selected":
			p.Mode = profile.PolicyExplicitSet
			p.SubjectKind = profile.SubjectNumber
		default:
			return profile.Destination{}, profile.Policy{}, profile.ErrProfile
		}
	}
	v, err := canonicalValues(scope, s, p)
	return v, p, err
}
func actions(scope profile.Scope) protocol.ActionCapabilities {
	caps := (protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot)
	if scope == profile.Organization {
		caps |= protocol.CapabilityUpdatePolicy | protocol.CapabilityCreateSetsPolicy | protocol.CapabilityWriteSetsPolicy
	}
	return caps
}

// NormalizeDestination separates new canonical address bytes from owned
// organization policy bytes. It retains no settings aliases and performs no
// credential or service lookup. Required address and visibility fields have
// no defaults; malformed settings return profile.ErrProfile.
func (i Implementation) NormalizeDestination(ctx context.Context, settings []byte) (protocol.Destination, error) {
	if ctx == nil || ctx.Err() != nil {
		return protocol.Destination{}, profile.ErrProfile
	}
	s, err := decodeSettings(settings)
	if err != nil {
		return protocol.Destination{}, err
	}
	_, p, err := s.destination(i.scope)
	if err != nil {
		return protocol.Destination{}, err
	}
	s.Visibility = ""
	s.Repositories = nil
	canonical, err := json.Marshal(s)
	if err != nil {
		return protocol.Destination{}, err
	}
	policy, err := profile.PublicPolicy(p)
	if err != nil {
		return protocol.Destination{}, err
	}
	return protocol.Destination{ConfigContractID: profile.ConfigContractID(i.scope), ServiceContractID: profile.ServiceContractID, CanonicalSettings: canonical, Policy: policy, Capabilities: actions(i.scope)}, nil
}

// ValidateCanonical checks exact address bytes, scope capabilities and the
// separately retained organization policy without normalizing or service access.
func (i Implementation) ValidateCanonical(ctx context.Context, destination protocol.Destination) error {
	if ctx == nil || ctx.Err() != nil || !destination.Valid() || destination.ConfigContractID != profile.ConfigContractID(i.scope) || destination.ServiceContractID != profile.ServiceContractID || destination.Capabilities != actions(i.scope) {
		return profile.ErrProfile
	}
	s, err := decodeSettings(destination.CanonicalSettings)
	if err != nil || s.Visibility != "" || len(s.Repositories) != 0 {
		return profile.ErrProfile
	}
	p, err := profile.ParsePolicy(destination.Policy)
	if err != nil {
		return err
	}
	if _, err := canonicalValues(i.scope, s, p); err != nil {
		return err
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(canonical, destination.CanonicalSettings) {
		return profile.ErrProfile
	}
	return nil
}
func canonicalValues(scope profile.Scope, s settings, p profile.Policy) (profile.Destination, error) {
	v := profile.Destination{Owner: s.Owner, Repository: s.Repository, Environment: s.Environment}
	return v, profile.ValidateDestination(scope, v, p)
}

// InterpretTarget returns owned scoped target data and value bounds from a
// validated destination. The canonical path is also the static consumer locator;
// this does not establish service existence or ENKV ownership.
func (i Implementation) InterpretTarget(ctx context.Context, r output.TargetRequest) (protocol.Target, error) {
	if r.PayloadEncoding != protocol.EncodingRaw && r.PayloadEncoding != protocol.EncodingBase64 {
		return protocol.Target{}, profile.ErrProfile
	}
	if err := i.ValidateCanonical(ctx, r.Destination); err != nil {
		return protocol.Target{}, err
	}
	s, err := decodeSettings(r.Destination.CanonicalSettings)
	if err != nil {
		return protocol.Target{}, err
	}
	p, err := profile.ParsePolicy(r.Destination.Policy)
	if err != nil {
		return protocol.Target{}, err
	}
	values, err := canonicalValues(i.scope, s, p)
	if err != nil {
		return protocol.Target{}, err
	}
	coordinate, err := profile.Derive(i.scope, values, r.EntryName, p)
	if err != nil {
		return protocol.Target{}, err
	}
	data, err := json.Marshal(struct {
		Scope      profile.Scope `json:"scope"`
		Coordinate string        `json:"coordinate"`
	}{i.scope, coordinate})
	if err != nil {
		return protocol.Target{}, err
	}
	return protocol.Target{ServiceContractID: profile.ServiceContractID, TargetContractID: profile.TargetContractID, CanonicalTarget: coordinate, ConsumerLocator: coordinate, TargetData: data, PayloadEncoding: r.PayloadEncoding, Capabilities: actions(i.scope), CreateValueBounds: protocol.PayloadBounds{Maximum: MaximumRawValueBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: MaximumRawValueBytes}}, nil
}
func (i Implementation) checkTarget(t protocol.Target) error {
	if !t.Valid() || t.ServiceContractID != profile.ServiceContractID || t.TargetContractID != profile.TargetContractID || t.ConsumerLocator != t.CanonicalTarget || t.LocatorRequiresCreation || t.Capabilities & ^actions(i.scope) != 0 {
		return profile.ErrProfile
	}
	var data struct {
		Scope      profile.Scope `json:"scope"`
		Coordinate string        `json:"coordinate"`
	}
	decoder := json.NewDecoder(bytes.NewReader(t.TargetData))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&data) != nil || decoder.Decode(new(any)) != io.EOF || data.Scope != i.scope || data.Coordinate != t.CanonicalTarget {
		return profile.ErrProfile
	}
	encoded, err := json.Marshal(data)
	if err != nil || !bytes.Equal(encoded, t.TargetData) {
		return profile.ErrProfile
	}
	if _, err := parseCanonicalTarget(i.scope, t.CanonicalTarget); err != nil {
		return err
	}
	for _, action := range []protocol.Action{protocol.ActionCreateWithValue, protocol.ActionWriteValue} {
		bounds := t.CreateValueBounds
		if action == protocol.ActionWriteValue {
			bounds = t.WriteValueBounds
		}
		want := protocol.PayloadBounds{}
		if t.Capabilities.Has(action) {
			want.Maximum = MaximumRawValueBytes
		}
		if bounds != want {
			return profile.ErrProfile
		}
	}
	return nil
}

// CheckAction validates action, ownership, payload length and opaque policy.
// Only organization selected-list policy has a standalone update action.
// Metadata actions return zero bounds; conditional tokens are unsupported.
func (i Implementation) CheckAction(ctx context.Context, r output.ActionCheck, p protocol.Policy) (protocol.PayloadBounds, error) {
	if ctx == nil || ctx.Err() != nil || protocol.ValidateActionPayload(r.Action, r.Target, r.PayloadLengthMode, r.PayloadLength) != nil || i.checkTarget(r.Target) != nil {
		return protocol.PayloadBounds{}, profile.ErrProfile
	}
	policy, err := profile.ParsePolicy(p)
	if err != nil {
		return protocol.PayloadBounds{}, err
	}
	if err := validateTarget(i.scope, r.Action, r.Target.CanonicalTarget, r.OwnedInstance, policy, r.ConditionalTokenLength); err != nil {
		return protocol.PayloadBounds{}, err
	}

	switch r.Action {
	case protocol.ActionCreateWithValue:
		return r.Target.CreateValueBounds, nil
	case protocol.ActionWriteValue:
		return r.Target.WriteValueBounds, nil
	}
	return protocol.PayloadBounds{}, nil
}

type prepared struct {
	implementation Implementation
	command        output.Preparation
	policy         profile.Policy
	token          []byte
	guard          *operationTransport
	client         *http.Client
	publicKey      [32]byte
	keyID          string
	sent, closed   bool
}

// Prepare captures an owned token and independently decoded policy. Value
// actions read the exact scoped public key; policy-only actions require current
// selected visibility. Deletion performs no discovery. The caller must serialize
// Send and Close, send at most once, and close on every success path. Errors
// dispose provisional private buffers; no payload is accepted during discovery.
func (i Implementation) Prepare(ctx context.Context, c output.Preparation, p protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	if c.ConditionalToken != "" || i.endpoint == "" || i.transport == nil {
		return nil, profile.ErrProfile
	}
	if _, err := i.CheckAction(ctx, output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, ConditionalTokenLength: uint16(len(c.ConditionalToken)), PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}, p); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, profile.ErrProfile
	}
	token, err := credential.Capture(ctx, inputs)
	if err != nil {
		return nil, err
	}
	policy, err := profile.ParsePolicy(p)
	if err != nil {
		clear(token)
		return nil, err
	}
	target, err := parseCanonicalTarget(i.scope, c.Target.CanonicalTarget)
	if err != nil {
		clear(token)
		return nil, err
	}
	guard := &operationTransport{base: i.transport, endpoint: i.endpoint, bearer: "Bearer " + string(token)}
	switch c.Action {
	case protocol.ActionCreateWithValue, protocol.ActionWriteValue:
		guard.readPath, guard.effectPath, guard.effectMethod = target.KeyPath, target.SecretPath, http.MethodPut
	case protocol.ActionUpdatePolicy:
		guard.readPath, guard.effectPath, guard.effectMethod = target.SecretPath, target.PolicyPath, http.MethodPut
	case protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		guard.effectPath, guard.effectMethod = target.SecretPath, http.MethodDelete
	default:
		clear(token)
		return nil, profile.ErrProfile
	}
	owned := &prepared{implementation: i, command: c, policy: policy, token: token, guard: guard, client: &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	transferred := false
	defer func() {
		if !transferred {
			owned.dispose()
		}
	}()
	switch c.Action {
	case protocol.ActionCreateWithValue, protocol.ActionWriteValue:
		owned.publicKey, owned.keyID, err = i.getKey(ctx, owned.client, target.KeyPath, token)
	case protocol.ActionUpdatePolicy:
		err = i.getSelectedMetadata(ctx, owned.client, target.SecretPath, token, c.Target.CanonicalTarget)
	}
	if err != nil {
		return nil, err
	}
	transferred = true
	return owned, nil
}
func (p *prepared) dispose() {
	if p.closed {
		return
	}
	p.closed = true
	clear(p.token)
	p.token = nil
	p.guard.bearer = ""
	if closer, ok := p.implementation.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Close clears the owned token, drops bearer state and closes idle connections.
// It is idempotent; call it only after Send returns.
func (p *prepared) Close() error { p.dispose(); return nil }

// SelectPolicyAction interprets public organization policy without credentials,
// payload or service access. The selected-list action keeps its Prepare guard.
func (i Implementation) SelectPolicyAction(ctx context.Context, r output.PolicyActionSelection, policy protocol.Policy) (protocol.Action, error) {
	if ctx == nil || ctx.Err() != nil || i.scope != profile.Organization || i.checkTarget(r.Target) != nil || r.HasPreviousPolicyDigest != !r.PreviousPolicyDigest.IsZero() {
		return 0, profile.ErrProfile
	}
	return profile.SelectPolicyAction(r.DomainID, r.PreviousPolicyDigest, policy)
}
