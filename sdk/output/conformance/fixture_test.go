package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestSemanticFixtureOwnsHostCorrelation(t *testing.T) {
	for _, condition := range []string{"create", "owned-write", "owned-delete", "uncertain-delete", "explicit-attempt", "payload-mismatch", "route-mutation", "descriptor-mutation", "input-name", "invalid-outcome", "missing-create-resource"} {
		t.Run(condition, func(t *testing.T) {
			impl, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			request := Request{Preparation: output.Preparation{Action: protocol.ActionCreateWithValue, Target: impl.command.Target, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5}, Inputs: fixture(impl).Inputs, Payload: []byte("value")}
			defer clear(request.Inputs[0].Value[:cap(request.Inputs[0].Value)])
			if condition == "owned-write" {
				request.Preparation.Action = protocol.ActionWriteValue
				request.Preparation.OwnedInstance = "owned"
				request.Preparation.Target.Capabilities |= protocol.CapabilityWriteValue
				request.Preparation.Target.WriteValueBounds = protocol.PayloadBounds{Maximum: 65536}
			}
			if condition == "owned-delete" {
				request.Preparation.Action = protocol.ActionDeleteOwned
				request.Preparation.OwnedInstance = "owned"
				request.Preparation.Target.Capabilities |= protocol.CapabilityDeleteOwned
				request.Preparation.PayloadLengthMode = protocol.LengthAbsent
				request.Preparation.PayloadLength = 0
				request.Payload = nil
			}
			if condition == "uncertain-delete" {
				request.Preparation.Action = protocol.ActionDeleteReservedSlot
				request.Preparation.Target.Capabilities |= protocol.CapabilityDeleteReservedSlot
				request.Preparation.PayloadLengthMode = protocol.LengthAbsent
				request.Preparation.PayloadLength = 0
				request.Payload = nil
				request.UncertainCreateAttemptID = protocol.ID{55}
				request.ExclusiveNamespaceDigest = protocol.ID{56}
			}
			if condition == "explicit-attempt" {
				request.Preparation.AttemptID = protocol.ID{99}
				request.Preparation.ConditionalToken = "exact-token"
			}
			if condition == "payload-mismatch" {
				request.Preparation.PayloadLength--
			}
			if condition == "input-name" {
				request.Inputs[0].Name = "PRIVATE_INPUT_NAME"
			}
			expected := output.Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: 201, SafeResourceID: "synthetic-resource"}
			if condition == "invalid-outcome" {
				expected.Class = 99
			}
			if condition == "missing-create-resource" {
				expected.SafeResourceID = ""
			}
			f, err := NewFixture(impl, request, expected)
			invalid := condition == "payload-mismatch" || condition == "input-name" || condition == "invalid-outcome" || condition == "missing-create-resource"
			if (err != nil) != invalid {
				t.Fatal("semantic fixture construction changed", err)
			}
			if invalid {
				if err == nil || strings.Contains(err.Error(), "PRIVATE_INPUT_NAME") {
					t.Fatal("unsafe fixture error", err)
				}
				return
			}
			if f.Command.DescriptorID != impl.Identity().DescriptorID || f.Expected.AttemptID != f.Command.AttemptID || f.Command.ConditionalToken != request.Preparation.ConditionalToken || f.Command.PayloadLength != request.Preparation.PayloadLength || f.Command.PayloadLengthMode != request.Preparation.PayloadLengthMode {
				t.Fatal("fixture changed semantic or host binding")
			}
			if condition == "explicit-attempt" && f.Command.AttemptID != request.Preparation.AttemptID {
				t.Fatal("explicit attempt replaced")
			}
			if condition == "route-mutation" {
				f.Command.CredentialRouteID = protocol.ID{99}
			}
			if condition == "descriptor-mutation" {
				f.Command.DescriptorID = protocol.ID{99}
			}
			if condition == "route-mutation" || condition == "descriptor-mutation" {
				entered := false
				serve := func(context.Context, output.Endpoints, output.Implementation) int { entered = true; return 0 }
				err = CheckImplementation(t.Context(), serve, impl, f)
				if entered || !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), "binding mismatch") {
					t.Fatal("mutated fixture entered serving", err)
				}
			}
		})
	}
}

type passiveImplementation struct {
	*synthetic
	defect string
}

type retainedDeletionImplementation struct {
	passiveImplementation
	exactCapabilities bool
}

func (p retainedDeletionImplementation) NormalizeDestination(_ context.Context, b []byte) (protocol.Destination, error) {
	return protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: bytes.Clone(b), Capabilities: p.command.Target.Capabilities}, nil
}

func (p retainedDeletionImplementation) CheckAction(_ context.Context, r output.ActionCheck, _ protocol.Policy) (protocol.PayloadBounds, error) {
	if p.exactCapabilities && r.Target.Capabilities != p.command.Target.Capabilities {
		return protocol.PayloadBounds{}, protocol.ErrProtocol
	}
	return protocol.PayloadBounds{}, nil
}

// full_only: false
func TestPublicAuthorCheckIncludesRetainedDeletionTargetSubset(t *testing.T) {
	for _, action := range []protocol.Action{protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot} {
		for _, condition := range []string{"subset", "exact-equality-defect", "added-capability", "invalid-interval"} {
			t.Run(fmt.Sprintf("%d/%s", action, condition), func(t *testing.T) {
				p, err := newImplementation()
				if err != nil {
					t.Fatal(err)
				}
				capability := protocol.CapabilityDeleteOwned
				if action == protocol.ActionDeleteReservedSlot {
					capability = protocol.CapabilityDeleteReservedSlot
				}
				p.command.Target.Capabilities |= capability
				d := protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: []byte(`{}`), Capabilities: p.command.Target.Capabilities}
				check := output.ActionCheck{Action: action, Target: p.command.Target, OwnedInstance: "owned", OwnershipMode: protocol.OwnershipQualified, OwnedInstanceDigest: protocol.ID{1}}
				if action == protocol.ActionDeleteReservedSlot {
					check.OwnedInstance, check.OwnedInstanceDigest = "", protocol.ID{}
					check.OwnershipMode, check.UncertainCreateAttemptID, check.ExclusiveNamespaceDigest = protocol.OwnershipUncertain, protocol.ID{2}, protocol.ID{3}
				}
				f := PublicFixture{PolicyAction: output.PolicyActionSelection{DomainID: protocol.ID{1}, Target: p.command.Target}, PolicyActionPolicy: protocol.Policy{ContractID: "private-policy", Data: []byte("policy")}, Settings: []byte(`{}`), ExpectedDestination: d,
					TargetRequest: output.TargetRequest{Destination: d, EntryName: "entry", PayloadEncoding: protocol.EncodingRaw}, ExpectedTarget: p.command.Target,
					ActionCheck: check, NormalizeAccepted: true, CanonicalAccepted: true, TargetAccepted: true, ActionAccepted: true}
				if condition == "added-capability" {
					p.command.Target.Capabilities |= protocol.CapabilityWriteValue
					p.command.Target.WriteValueBounds = protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}
					f.ExpectedTarget = p.command.Target
				}
				if condition == "invalid-interval" {
					f.ActionCheck.Target.Capabilities = capability
					f.ActionCheck.Target.CreateValueBounds = protocol.PayloadBounds{Maximum: 1}
				}
				impl := retainedDeletionImplementation{passiveImplementation: passiveImplementation{synthetic: p}, exactCapabilities: condition == "exact-equality-defect"}
				err = CheckPublicImplementation(t.Context(), output.RunPublic, impl, f)
				if (err != nil) != (condition != "subset") {
					t.Fatal("retained deletion subset was not checked", err)
				}
				if p.calls != 0 {
					t.Fatal("passive retained deletion entered an effect")
				}
			})
		}
	}
}

func (p passiveImplementation) NormalizeDestination(_ context.Context, b []byte) (protocol.Destination, error) {
	d := protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: bytes.Clone(b), Capabilities: protocol.CapabilityCreateWithValue | protocol.CapabilityCreateEmpty}
	if p.defect == "normalize" {
		d.CanonicalSettings = []byte(`{"wrong":true}`)
	}
	if p.defect == "illegal-refusal" {
		return d, errors.New("PRIVATE_CALLBACK_TEXT")
	}
	if p.defect == "refuse" {
		return protocol.Destination{}, errors.New("PRIVATE_CALLBACK_TEXT")
	}
	return d, nil
}
func (p passiveImplementation) ValidateCanonical(_ context.Context, d protocol.Destination) error {
	if p.defect == "canonical" {
		d.CanonicalSettings[0] = '['
	}
	if p.defect == "refuse" {
		return errors.New("PRIVATE_CALLBACK_TEXT")
	}
	return nil
}
func (p passiveImplementation) InterpretTarget(context.Context, output.TargetRequest) (protocol.Target, error) {
	target := p.command.Target
	if p.defect == "target" {
		target.CanonicalTarget = "wrong/service/key"
	}
	if p.defect == "refuse" {
		return protocol.Target{}, errors.New("PRIVATE_CALLBACK_TEXT")
	}
	return target, nil
}
func (p passiveImplementation) CheckAction(context.Context, output.ActionCheck, protocol.Policy) (protocol.PayloadBounds, error) {
	if p.defect == "refuse" {
		return protocol.PayloadBounds{}, errors.New("PRIVATE_CALLBACK_TEXT")
	}
	bounds := protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}
	if p.defect == "bounds" {
		bounds.Maximum--
	}
	return bounds, nil
}

// full_only: false
func TestPublicAuthorCheckCoversSemanticOperations(t *testing.T) {
	checkPassiveCallerContextDiagnosis(t)
	for _, condition := range []string{"valid", "normalize", "canonical", "target", "bounds", "refuse", "wrong-correlation", "trailing", "effect-entry", "fixture-settings", "fixture-policy", "illegal-refusal"} {
		t.Run(condition, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			d := protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: []byte(`{"unlisted":true}`), Capabilities: protocol.CapabilityCreateWithValue | protocol.CapabilityCreateEmpty}
			f := PublicFixture{PolicyAction: output.PolicyActionSelection{DomainID: protocol.ID{1}, Target: p.command.Target}, PolicyActionPolicy: protocol.Policy{ContractID: "private-policy", Data: []byte("policy")}, Settings: []byte(`{"unlisted":true}`), ExpectedDestination: d, TargetRequest: output.TargetRequest{Destination: d, EntryName: "entry", PayloadEncoding: protocol.EncodingRaw}, ExpectedTarget: p.command.Target, ActionCheck: output.ActionCheck{Action: protocol.ActionCreateWithValue, Target: p.command.Target, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5}, ExpectedBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, NormalizeAccepted: true, CanonicalAccepted: true, TargetAccepted: true, ActionAccepted: true}
			if condition == "refuse" || condition == "illegal-refusal" {
				f.ExpectedDestination = protocol.Destination{}
				f.ExpectedTarget = protocol.Target{}
				f.ExpectedBounds = protocol.PayloadBounds{}
				f.NormalizeAccepted = false
				f.CanonicalAccepted = false
				f.TargetAccepted = false
				f.ActionAccepted = false
			}
			if condition == "fixture-policy" {
				f.Policy = protocol.Policy{Data: []byte("PRIVATE_POLICY")}
			}
			if condition == "fixture-settings" {
				f.Settings = []byte(`{"PRIVATE_SETTING_KEY":`)
			}
			var originalWriter io.Writer
			serve := ServePublic(output.RunPublic)
			if condition == "wrong-correlation" || condition == "trailing" || condition == "effect-entry" {
				serve = func(ctx context.Context, e output.PublicEndpoints, impl output.Implementation) int {
					if condition == "effect-entry" {
						_, _ = impl.Prepare(ctx, output.Preparation{}, protocol.Policy{}, nil)
					}
					var result bytes.Buffer
					e.Result = &result
					code := output.RunPublic(ctx, e, impl)
					b := result.Bytes()
					if condition == "wrong-correlation" && len(b) > 0 {
						b[12] ^= 1
					}
					if _, err := originalWriter.Write(b); err != nil {
						t.Fatal(err)
					}
					if condition == "trailing" {
						if _, err := originalWriter.Write([]byte{1}); err != nil {
							t.Fatal(err)
						}
					}
					return code
				}
			}
			// Bind the injected serving writer per invocation without a public hook.
			if condition == "wrong-correlation" || condition == "trailing" || condition == "effect-entry" {
				injected := serve
				serve = func(ctx context.Context, e output.PublicEndpoints, impl output.Implementation) int {
					originalWriter = e.Result
					return injected(ctx, e, impl)
				}
			}
			err = CheckPublicImplementation(t.Context(), serve, passiveImplementation{synthetic: p, defect: condition}, f)
			want := condition == "valid" || condition == "refuse"
			if (err == nil) != want {
				t.Fatal("passive author sensitivity changed", err)
			}
			if err != nil && (strings.Contains(err.Error(), "PRIVATE_CALLBACK_TEXT") || strings.Contains(err.Error(), "PRIVATE_SETTING_KEY")) {
				t.Fatal("private text escaped", err)
			}
			if p.calls != 0 {
				t.Fatal("passive path sent a value")
			}
		})
	}
}

type policySelectingImplementation struct {
	passiveImplementation
	condition string
}

func (p policySelectingImplementation) SelectPolicyAction(_ context.Context, r output.PolicyActionSelection, policy protocol.Policy) (protocol.Action, error) {
	switch p.condition {
	case "write":
		return protocol.ActionWriteValue, nil
	case "refuse":
		return 0, protocol.ErrProtocol
	case "nonzero-refusal":
		return protocol.ActionUpdatePolicy, protocol.ErrProtocol
	case "invalid-action":
		return protocol.ActionDeleteOwned, nil
	case "other-action":
		return protocol.ActionWriteValue, nil
	case "mutate-policy":
		policy.Data[0] ^= 1
	case "mutate-target":
		r.Target.TargetData[0] ^= 1
	}
	return protocol.ActionUpdatePolicy, nil
}

// full_only: false
func TestPublicAuthorCheckCoversPolicyActionRawReturnsAndBorrows(t *testing.T) {
	for _, condition := range []string{"metadata", "write", "refuse", "nonzero-refusal", "invalid-action", "other-action", "mutate-policy", "mutate-target"} {
		t.Run(condition, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			d := protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: []byte(`{}`), Capabilities: protocol.CapabilityCreateWithValue | protocol.CapabilityCreateEmpty}
			target := p.command.Target
			target.TargetData = []byte("public target")
			target.Capabilities |= protocol.CapabilityUpdatePolicy | protocol.CapabilityWriteValue | protocol.CapabilityWriteSetsPolicy
			target.WriteValueBounds = protocol.PayloadBounds{Maximum: 65536}
			f := PublicFixture{Settings: []byte(`{}`), ExpectedDestination: d, TargetRequest: output.TargetRequest{Destination: d, EntryName: "entry", PayloadEncoding: protocol.EncodingRaw}, ExpectedTarget: p.command.Target, ActionCheck: output.ActionCheck{Action: protocol.ActionCreateWithValue, Target: p.command.Target, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5}, ExpectedBounds: protocol.PayloadBounds{Maximum: 65536}, NormalizeAccepted: true, CanonicalAccepted: true, TargetAccepted: true, ActionAccepted: true,
				PolicyAction: output.PolicyActionSelection{DomainID: protocol.ID{1}, Target: target, HasPreviousPolicyDigest: true, PreviousPolicyDigest: protocol.ID{2}}, PolicyActionPolicy: protocol.Policy{ContractID: "private-policy", Data: []byte("public policy")}, ExpectedPolicyAction: protocol.ActionUpdatePolicy, PolicyActionAccepted: true}
			if condition == "write" {
				f.ExpectedPolicyAction = protocol.ActionWriteValue
			}
			if condition == "refuse" || condition == "nonzero-refusal" {
				f.ExpectedPolicyAction = 0
				f.PolicyActionAccepted = false
			}
			err = CheckPublicImplementation(t.Context(), output.RunPublic, policySelectingImplementation{passiveImplementation: passiveImplementation{synthetic: p}, condition: condition}, f)
			valid := condition == "metadata" || condition == "write" || condition == "refuse"
			if (err == nil) != valid {
				t.Fatal("policy action conformance sensitivity", err)
			}
			if p.calls != 0 {
				t.Fatal("passive selection entered provider effect")
			}
		})
	}
}
