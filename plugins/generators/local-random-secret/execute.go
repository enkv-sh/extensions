// Package localrandom generates a random value without a managed resource.
package localrandom

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"enkv.sh/plugins/generators/local-random-secret/profile"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// NewImplementation binds a descriptor with no credential names to this generator.
// It returns normalization, canonical validation and creation callbacks.
// Descriptor failures wrap protocol.ErrProtocol and preserve the cause from
// generator.Bind, including artifact or credential-route decoder errors.
// A nonempty credential-name route returns protocol.ErrProtocol.
func NewImplementation(descriptorBytes []byte) (generator.Implementation, error) {
	binding, err := generator.Bind(descriptorBytes, profile.ConfigContractID())
	if err != nil {
		return generator.Implementation{}, fmt.Errorf("local random binding: descriptor: %w: %w", protocol.ErrProtocol, err)
	}
	if len(binding.CredentialRoute().Names) != 0 {
		return generator.Implementation{}, fmt.Errorf("local random binding: descriptor.generator.credential_route: environment names not allowed: %w", protocol.ErrProtocol)
	}
	return generator.Implementation{
		Binding: binding,
		Normalize: func(ctx context.Context, request protocol.NormalizeRequest) (protocol.Intent, error) {
			if err := ctx.Err(); err != nil {
				return protocol.Intent{}, err
			}
			return profile.Normalize(request.Settings)
		},
		ValidateCanonical: func(ctx context.Context, intent protocol.Intent) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return profile.ValidateCanonical(intent)
		}, Create: Execute,
	}, nil
}

// Execute obtains 32 bytes of entropy and transfers an owned 43-byte base64url
// value to the caller, which must clear it after use. It retains no invocation
// aliases and clears temporary entropy on every return. It requires a nonnil
// context, a valid create command and no private inputs. Cancellation before or
// after entropy acquisition returns no value; local refusals use protocol.ErrProtocol.
func Execute(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, []byte, error) {
	command := invocation.Command
	if ctx == nil || len(invocation.Inputs) != 0 {
		return protocol.SafeFacts{}, nil, protocol.ErrProtocol
	}
	if err := profile.ValidateCommand(command); err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	var entropy [profile.EntropyBytes]byte
	defer clear(entropy[:])
	if _, err := rand.Read(entropy[:]); err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.SafeFacts{}, nil, err
	}
	value := make([]byte, profile.ValueBytes)
	base64.RawURLEncoding.Encode(value, entropy[:])
	return command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone), value, nil
}
