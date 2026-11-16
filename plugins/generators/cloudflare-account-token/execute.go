// Package cloudflare implements Cloudflare account-token creation and retirement.
package cloudflare

import (
	"bytes"
	"context"
	"fmt"

	client "enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare"
	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// NewImplementation checks the embedded declaration, production contract and
// exact CLOUDFLARE_API_TOKEN route before exposing callbacks. It performs no
// credential lookup or provider request; malformed bindings return an error.
func NewImplementation(descriptorBytes []byte) (generator.Implementation, error) {
	binding, err := generator.Bind(descriptorBytes, profile.ConfigContractID(profile.ProductionOrigin))
	if err != nil {
		return generator.Implementation{}, fmt.Errorf("cloudflare binding: descriptor: %w: %w", protocol.ErrProtocol, err)
	}
	route := binding.CredentialRoute()
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return generator.Implementation{}, err
	}
	expected, err := credentialroute.Identity(profile.CredentialRoute())
	if err != nil || routeID != expected {
		return generator.Implementation{}, protocol.ErrProtocol
	}
	return implementation(binding, profile.ProductionOrigin, client.NewProduction()), nil
}

func implementation(binding generator.Binding, origin string, executor *client.Client) generator.Implementation {
	return generator.Implementation{Binding: binding,
		Normalize: func(ctx context.Context, request protocol.NormalizeRequest) (protocol.Intent, error) {
			if err := ctx.Err(); err != nil {
				return protocol.Intent{}, err
			}
			return profile.Normalize(request.Settings, origin)
		},
		ValidateCanonical: func(ctx context.Context, intent protocol.Intent) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := profile.ParseCanonical(intent, origin)
			return err
		},
		CheckRetirementCompatibility: func(ctx context.Context, request protocol.RetirementCompatibilityRequest) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if request.CompletionClass != protocol.CompletionAcknowledged {
				return false, nil
			}
			_, _, err := retainedResource(request.Intent, request.OriginalFacts, origin)
			return err == nil, nil
		},
		Create: func(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, []byte, error) {
			return execute(ctx, invocation, origin, executor)
		},
		Retire: func(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, error) {
			facts, value, err := execute(ctx, invocation, origin, executor)
			clear(value)
			return facts, err
		}}
}

// Execute borrows one admitted invocation until return and performs at most one
// provider request. It requires a nonnil context and the exact private credential
// route. It returns closed safe facts, plus an owned bearer only for complete
// creation; the caller must clear returned private bytes even when an error is
// returned. Unknown facts do not grant a retry or establish a usable token.
func Execute(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, []byte, error) {
	return execute(ctx, invocation, profile.ProductionOrigin, client.NewProduction())
}

func execute(ctx context.Context, invocation generator.Invocation, origin string, executor *client.Client) (protocol.SafeFacts, []byte, error) {
	command := invocation.Command
	if ctx == nil || executor == nil {
		return protocol.SafeFacts{}, nil, protocol.ErrProtocol
	}
	if err := protocol.ValidateCommand(command); err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	canonical, err := protocol.DecodeIntent(command.Intent)
	if err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	controls, err := profile.ParseCanonical(canonical, origin)
	if err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	routeID, err := credentialroute.Identity(profile.CredentialRoute())
	if err != nil || command.CredentialRouteID != protocol.ID(routeID) || len(invocation.Inputs) != 1 || invocation.Inputs[0].Name != profile.CredentialEnvironment || !invocation.Inputs[0].Present || !provider.ValidBearer(invocation.Inputs[0].Value) {
		return protocol.SafeFacts{}, nil, protocol.ErrProtocol
	}
	request := provider.Command{Action: command.Action, DeadlineUnixMillis: command.DeadlineUnixMillis, Account: provider.ID(controls.Account), IntentDigest: provider.ID(controls.Digest)}
	switch command.Action {
	case protocol.ActionCreate:
		body, err := controls.RequestJSON()
		if err != nil {
			return protocol.SafeFacts{}, nil, err
		}
		request.HTTPRequestDigest = provider.ID(profile.HTTPRequestDigest(provider.ActionCreate, controls.Account, [32]byte{}, body))
		clear(body)
		request.Intent, err = profile.EncodeControls(controls)
		if err != nil {
			return protocol.SafeFacts{}, nil, err
		}
		defer clear(request.Intent)
	case protocol.ActionRetire:
		_, resource, err := retainedResource(command.Intent, command.OriginalFacts, origin)
		if err != nil {
			return protocol.SafeFacts{}, nil, err
		}
		request.TargetPresent = 1
		request.Target = resource.TokenID
		request.HTTPRequestDigest = provider.ID(profile.HTTPRequestDigest(provider.ActionDelete, controls.Account, [32]byte(resource.TokenID), nil))
	default:
		return protocol.SafeFacts{}, nil, protocol.ErrProtocol
	}
	facts, value, err := executor.Execute(ctx, request, invocation.Inputs[0].Value)
	if err != nil {
		return protocol.SafeFacts{}, value, err
	}
	opaque, err := provider.EncodeFacts(facts)
	if err != nil {
		return protocol.SafeFacts{}, value, err
	}
	disposition := uint8(protocol.DispositionUnknown)
	switch facts.Disposition {
	case provider.DispositionCompleteCreate:
		disposition = protocol.DispositionCompleteCreate
	case provider.DispositionOwnedUnusableCreate:
		disposition = protocol.DispositionOwnedUnusableCreate
	case provider.DispositionDeleteAcknowledged:
		disposition = protocol.DispositionRetirementAcknowledged
	}
	result := command.NewFacts(disposition, facts.Reason)
	result.ProviderFacts = opaque
	if command.Action == protocol.ActionRetire {
		original, err := protocol.DecodeSafeFacts(command.OriginalFacts)
		if err != nil {
			return protocol.SafeFacts{}, value, err
		}
		result.Target = bytes.Clone(original.Target)
		result.ResourceData = bytes.Clone(original.ResourceData)
	} else if facts.TokenPresent == 1 {
		result.Target = bytes.Clone(facts.Account[:])
		result.ResourceData = bytes.Clone(facts.TokenID[:])
	}
	return result, value, nil
}

// Retirement must bind both generic resource facts and provider facts to the
// original intent. A token ID alone cannot establish the account or ownership.
func retainedResource(intentBytes, factBytes []byte, origin string) (profile.Intent, provider.SafeFacts, error) {
	intent, err := protocol.DecodeIntent(intentBytes)
	if err != nil {
		return profile.Intent{}, provider.SafeFacts{}, err
	}
	controls, err := profile.ParseCanonical(intent, origin)
	if err != nil {
		return profile.Intent{}, provider.SafeFacts{}, err
	}
	digest, err := protocol.IntentDigest(intentBytes)
	if err != nil {
		return profile.Intent{}, provider.SafeFacts{}, err
	}
	facts, err := protocol.DecodeSafeFacts(factBytes)
	if err != nil || facts.Action != protocol.ActionCreate || facts.LifecycleMode != protocol.LifecycleManaged || facts.ResourceContractID != intent.ResourceContractID || facts.IntentDigest != digest || (facts.Disposition != protocol.DispositionCompleteCreate && facts.Disposition != protocol.DispositionOwnedUnusableCreate) {
		return profile.Intent{}, provider.SafeFacts{}, protocol.ErrProtocol
	}
	resource, err := provider.DecodeFacts(facts.ProviderFacts)
	if err != nil || resource.Account != provider.ID(controls.Account) || resource.IntentDigest != provider.ID(controls.Digest) || resource.TokenPresent != 1 || !profile.ValidTag([32]byte(resource.TokenID)) || !bytes.Equal(facts.Target, resource.Account[:]) || !bytes.Equal(facts.ResourceData, resource.TokenID[:]) || (facts.Disposition == protocol.DispositionCompleteCreate) != (resource.Disposition == provider.DispositionCompleteCreate) || facts.Reason != resource.Reason {
		return profile.Intent{}, provider.SafeFacts{}, protocol.ErrProtocol
	}
	return controls, resource, nil
}
