package conformance

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

type contextImplementation struct {
	output.Implementation
	cancel         context.CancelFunc
	calls, closes  *int
	target, policy *[]byte
	violate        bool
}

func (p contextImplementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	*p.calls++
	*p.target, *p.policy = c.Target.TargetData, policy.Data
	prepared, err := p.Implementation.Prepare(ctx, c, policy, inputs)
	if p.violate {
		c.Target.TargetData[0] ^= 1
	}
	if p.cancel != nil {
		p.cancel()
	}
	return contextPrepared{Prepared: prepared, closes: p.closes}, err
}

type contextPrepared struct {
	output.Prepared
	closes *int
}

func (p contextPrepared) Close() error { *p.closes++; return p.Prepared.Close() }

func checkEffectCallerContextDiagnosis(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "during-exchange", "mutation-before-cancellation"} {
		t.Run("caller-context/"+condition, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			p.command.Target.TargetData = []byte{1, 2, 3}
			f := fixture(p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := error(context.Canceled)
			if condition == "cancelled" {
				cancel()
			}
			if condition == "expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(0, 0))
				defer stop()
				want = context.DeadlineExceeded
			}
			calls, closes := 0, 0
			var target, policy []byte
			impl := contextImplementation{Implementation: p, calls: &calls, closes: &closes, target: &target, policy: &policy, violate: condition == "mutation-before-cancellation"}
			if condition == "during-exchange" || condition == "mutation-before-cancellation" {
				impl.cancel = cancel
			}
			err = CheckImplementation(ctx, output.Run, impl, f)
			if condition == "mutation-before-cancellation" {
				if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "callback.prepare.command") {
					t.Fatal("cancellation hid target mutation", err)
				}
			} else if !errors.Is(err, want) || !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), "caller.context:") {
				t.Fatal("effect context diagnosis lost its reason or cause", err)
			}
			expected := 0
			if condition == "during-exchange" || condition == "mutation-before-cancellation" {
				expected = 1
			}
			if calls != expected || closes != expected || p.calls != 0 {
				t.Fatal("context path lost prepare/close observations", calls, closes, p.calls)
			}
			for _, input := range f.Inputs {
				clear(input.Value[:cap(input.Value)])
			}
		})
	}
}

type cancellingPassive struct {
	passiveImplementation
	cancel context.CancelFunc
	calls  *int
}

func (p cancellingPassive) NormalizeDestination(ctx context.Context, b []byte) (protocol.Destination, error) {
	*p.calls++
	d, err := p.passiveImplementation.NormalizeDestination(ctx, b)
	if p.cancel != nil {
		p.cancel()
	}
	return d, err
}
func checkPassiveCallerContextDiagnosis(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "during-exchange", "violation-before-cancellation"} {
		t.Run("caller-context/"+condition, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			d := protocol.Destination{ConfigContractID: "private-config", ServiceContractID: "private-service", CanonicalSettings: []byte(`{"unlisted":true}`), Capabilities: protocol.CapabilityCreateWithValue | protocol.CapabilityCreateEmpty}
			f := PublicFixture{PolicyAction: output.PolicyActionSelection{DomainID: protocol.ID{1}, Target: p.command.Target}, PolicyActionPolicy: protocol.Policy{ContractID: "private-policy", Data: []byte("policy")}, Settings: bytes.Clone(d.CanonicalSettings), ExpectedDestination: d, TargetRequest: output.TargetRequest{Destination: d, EntryName: "entry", PayloadEncoding: protocol.EncodingRaw}, ExpectedTarget: p.command.Target, ActionCheck: output.ActionCheck{Action: protocol.ActionCreateWithValue, Target: p.command.Target, PayloadLengthMode: protocol.LengthExact, PayloadLength: 5}, ExpectedBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, NormalizeAccepted: true, CanonicalAccepted: true, TargetAccepted: true, ActionAccepted: true}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := error(context.Canceled)
			if condition == "cancelled" {
				cancel()
			}
			if condition == "expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(0, 0))
				defer stop()
				want = context.DeadlineExceeded
			}
			calls := 0
			impl := cancellingPassive{passiveImplementation: passiveImplementation{synthetic: p}, calls: &calls}
			if condition == "during-exchange" || condition == "violation-before-cancellation" {
				impl.cancel = cancel
			}
			if condition == "violation-before-cancellation" {
				impl.defect = "normalize"
			}
			err = CheckPublicImplementation(ctx, output.RunPublic, impl, f)
			if condition == "violation-before-cancellation" {
				if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "callback.normalize") {
					t.Fatal("cancellation hid raw normalization violation", err)
				}
			} else if !errors.Is(err, want) || !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), "caller.context:") {
				t.Fatal("passive context diagnosis lost its reason or cause", err)
			}
			expected := 0
			if condition == "during-exchange" || condition == "violation-before-cancellation" {
				expected = 1
			}
			if calls != expected || p.calls != 0 {
				t.Fatal("context path changed callback/effect entries", calls, p.calls)
			}
		})
	}
}

type mutatingImplementation struct {
	output.Implementation
	phase, field string
}

func (p mutatingImplementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	prepared, err := p.Implementation.Prepare(ctx, c, policy, inputs)
	value := c.Target.TargetData
	if p.field == "policy" {
		value = policy.Data
	}
	if p.phase == "prepare" {
		value[0] ^= 1
	}
	return mutatingPrepared{Prepared: prepared, phase: p.phase, value: value}, err
}

type mutatingPrepared struct {
	output.Prepared
	phase string
	value []byte
}

func (p mutatingPrepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	r, err := p.Prepared.Send(ctx, payload)
	if p.phase == "send" {
		p.value[0] ^= 1
	}
	return r, err
}
func (p mutatingPrepared) Close() error {
	err := p.Prepared.Close()
	if p.phase == "close" {
		p.value[0] ^= 1
	}
	return err
}
func checkTargetAndPolicyMutation(t *testing.T) {
	for _, field := range []string{"target", "policy"} {
		for _, phase := range []string{"unchanged", "prepare", "send", "close"} {
			t.Run("borrowed-mutation/"+field+"/"+phase, func(t *testing.T) {
				p, err := newImplementation()
				if err != nil {
					t.Fatal(err)
				}
				p.command.Target.TargetData = []byte{1, 2, 3}
				p.policy = protocol.Policy{ContractID: "unlisted-opaque-policy", Data: []byte{0xf0, 1, 2}}
				p.command.PolicyContractID = p.policy.ContractID
				p.command.PolicyDigest, err = protocol.PolicyDigest(p.command.DomainID, p.policy)
				if err != nil {
					t.Fatal(err)
				}
				f := fixture(p)
				defer clear(f.Inputs[0].Value[:cap(f.Inputs[0].Value)])
				err = CheckImplementation(t.Context(), output.Run, mutatingImplementation{Implementation: p, phase: phase, field: field}, f)
				if phase == "unchanged" {
					if err != nil {
						t.Fatal("opaque positive control refused", err)
					}
				} else {
					want := "callback." + phase + ".command"
					if field == "policy" {
						want = "callback." + phase + ".policy"
					}
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatal("borrowed bytes mutation escaped its owning phase", err)
					}
				}
				if p.calls != 1 || !bytes.Equal(f.Command.Target.TargetData, []byte{1, 2, 3}) || !bytes.Equal(f.Policy.Data, []byte{0xf0, 1, 2}) {
					t.Fatal("mutation control did not run against independent fixture", p.calls)
				}
			})
		}
	}
}
