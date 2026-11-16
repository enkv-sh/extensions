// Package gcpsm implements fixed-target Google Secret Manager effects and credential capture.
package gcpsm

import (
	"bytes"
	"context"
	"enkv.sh/plugins/outputs/gcp-secret-manager/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"fmt"
	"os"
	"strings"
)

// NewImplementation checks the descriptor name, settings contract and SDK route
// before returning callbacks. It performs no credential discovery or service call.
func NewImplementation(descriptorBytes []byte) (Implementation, error) {
	binding, err := output.Bind(descriptorBytes, profile.ConfigContractID)
	if err != nil {
		return Implementation{}, fmt.Errorf("gcp-secret-manager binding: descriptor: %w: %w", profile.ErrProfile, err)
	}
	if binding.Name() != "gcp-secret-manager" {
		return Implementation{}, fmt.Errorf("gcp-secret-manager binding: descriptor.name: unsupported plugin: %w", profile.ErrProfile)
	}
	if binding.CredentialRoute().Mode != credentialroute.ModeSDK {
		return Implementation{}, fmt.Errorf("gcp-secret-manager binding: descriptor.output.credential_route: SDK discovery required: %w", profile.ErrProfile)
	}
	i := New()
	i.Binding = binding
	return i, nil
}

// NormalizeDestination returns owned canonical public settings without credentials
// or service access. A nil or cancelled context is refused with profile.ErrProfile.
func (i Implementation) NormalizeDestination(ctx context.Context, settings []byte) (protocol.Destination, error) {
	if ctx == nil || ctx.Err() != nil {
		return protocol.Destination{}, profile.ErrProfile
	}
	return profile.Normalize(settings)
}

// ValidateCanonical checks exact retained destination facts without normalizing
// them or discovering credentials. It retains no destination aliases.
func (i Implementation) ValidateCanonical(ctx context.Context, destination protocol.Destination) error {
	if ctx == nil || ctx.Err() != nil {
		return profile.ErrProfile
	}
	return profile.ValidateDestination(destination)
}

// InterpretTarget derives owned target data from canonical destination settings
// and the entry name. It performs no service or credential lookup.
func (i Implementation) InterpretTarget(ctx context.Context, r output.TargetRequest) (protocol.Target, error) {
	if ctx == nil || ctx.Err() != nil {
		return protocol.Target{}, profile.ErrProfile
	}
	return profile.Derive(r.Destination, r.EntryName, r.PayloadEncoding)
}

// CheckAction validates the exact action, ownership and payload-length arm.
// Value actions return their bounds; metadata actions return zero bounds.
// Policy and conditional tokens are unsupported; refusals use profile.ErrProfile.
func (i Implementation) CheckAction(ctx context.Context, r output.ActionCheck, p protocol.Policy) (protocol.PayloadBounds, error) {
	if ctx == nil || ctx.Err() != nil || protocol.ValidateActionPayload(r.Action, r.Target, r.PayloadLengthMode, r.PayloadLength) != nil || r.ConditionalTokenLength != 0 || p.Present() || len(p.Data) != 0 {
		return protocol.PayloadBounds{}, profile.ErrProfile
	}
	c := output.Preparation{Action: r.Action, Target: r.Target, OwnedInstance: r.OwnedInstance}
	if err := validateConsumer(c, p); err != nil {
		return protocol.PayloadBounds{}, err
	}
	if r.Action == protocol.ActionWriteValue {
		return r.Target.WriteValueBounds, nil
	}
	return protocol.PayloadBounds{}, nil
}

// The standard SDK chain reads process environment. Native Main installs the
// captured inputs; in-process calls must already have that same environment.
func (i Implementation) checkEnvironment(inputs []credentialroute.Input) error {
	encoded, err := credentialroute.EncodeInputs(i.CredentialRoute(), inputs)
	if err != nil {
		return profile.ErrProfile
	}
	clear(encoded)
	for _, input := range inputs {
		value, present := os.LookupEnv(input.Name)
		if present != input.Present || present && value != string(input.Value) || strings.ContainsRune(value, 0) {
			return profile.ErrProfile
		}
	}
	return nil
}

// Prepare requires captured environment inputs to equal the process environment.
// It checks the admitted action, target, policy and payload-length facts, then
// captures credentials. It copies retained target data into one invocation owner
// before payload readiness.
// The SDK separately admits the full wire command.
// The caller must serialize Send and Close, send at most once, and close even
// without a send. Preparation failures dispose provisional private byte buffers.
// Credential discovery alone does not prove permission for the mutation.
func (i Implementation) Prepare(ctx context.Context, c output.Preparation, p protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	if i.checkEnvironment(inputs) != nil {
		return nil, profile.ErrProfile
	}
	if _, err := i.CheckAction(ctx, output.ActionCheck{Action: c.Action, Target: c.Target, OwnedInstance: c.OwnedInstance, ConditionalTokenLength: uint16(len(c.ConditionalToken)), PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}, p); err != nil {
		return nil, err
	}
	wire, _, err := captureCredential(ctx)
	if err != nil {
		return nil, err
	}
	c.Target.TargetData = bytes.Clone(c.Target.TargetData)
	return &prepared{implementation: i, command: c, policy: p, credential: wire}, nil
}

type prepared struct {
	implementation Implementation
	command        output.Preparation
	policy         protocol.Policy
	credential     []byte
	sent, closed   bool
}

// Send borrows payload until return and consumes the one-send opportunity even
// when the provider result is unknown. Close remains required after any result;
// a missing acknowledgement grants no resend right.
func (p *prepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	if p == nil || p.closed || p.sent || ctx == nil || ctx.Err() != nil {
		return output.Outcome{}, profile.ErrProfile
	}
	p.sent = true
	return p.implementation.send(ctx, p.command, p.policy, payload, p.credential)
}

// Close clears owned credential and target byte buffers and closes idle
// transport connections. It is idempotent; call it after Send has returned.
func (p *prepared) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	clear(p.credential)
	p.credential = nil
	clear(p.command.Target.TargetData)
	p.command.Target.TargetData = nil
	if closer, ok := p.implementation.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

// SelectPolicyAction refuses because this plugin has no publication policy.
func (i Implementation) SelectPolicyAction(context.Context, output.PolicyActionSelection, protocol.Policy) (protocol.Action, error) {
	return 0, profile.ErrProfile
}
