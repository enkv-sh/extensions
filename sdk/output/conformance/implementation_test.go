package conformance

import (
	"context"
	"enkv.sh/sdk/artifact/credentialroute"
	"testing"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestCheckImplementationRunsAuthorAndRejectsBadReturns(t *testing.T) {
	checkEffectCallerContextDiagnosis(t)
	checkTargetAndPolicyMutation(t)
	for _, condition := range []string{"correct", "opaque policy", "wrong result", "callback error", "missing callback", "double callback", "changed borrowed bytes"} {
		t.Run(condition, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			p.callbackError = condition == "callback error"
			p.invalidResult = condition == "wrong result"
			if condition == "opaque policy" {
				p.policy = protocol.Policy{ContractID: "never-listed-policy", Data: []byte{0, 255, 1}}
				p.command.PolicyContractID = p.policy.ContractID
				p.command.PolicyDigest, _ = protocol.PolicyDigest(p.command.DomainID, p.policy)
			}
			impl := output.Implementation(p)
			if condition == "changed borrowed bytes" {
				impl = changingImplementation{Implementation: p}
			}
			serve := Serve(output.Run)
			if condition == "double callback" {
				serve = func(ctx context.Context, e output.Endpoints, observed output.Implementation) int {
					return output.Run(ctx, e, changingImplementation{Implementation: observed, double: true})
				}
			}
			if condition == "missing callback" {
				serve = func(context.Context, output.Endpoints, output.Implementation) int { return 0 }
			}
			err = CheckImplementation(context.Background(), serve, impl, fixture(p))
			want := condition == "correct" || condition == "opaque policy"
			if (err == nil) != want {
				t.Fatal("author acceptance changed", err)
			}
		})
	}
}

type changingImplementation struct {
	output.Implementation
	double bool
}

func (p changingImplementation) Prepare(ctx context.Context, c output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	v, err := p.Implementation.Prepare(ctx, c, policy, inputs)
	return changingPrepared{Prepared: v, double: p.double}, err
}

type changingPrepared struct {
	output.Prepared
	double bool
}

func (p changingPrepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	if p.double {
		_, _ = p.Prepared.Send(ctx, payload)
	}
	r, err := p.Prepared.Send(ctx, payload)
	if !p.double {
		payload[0] ^= 1
	}
	return r, err
}
