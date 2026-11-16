//go:build enkv_cloudflare_testartifact

package cloudflare

import (
	client "enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// NewTestImplementation changes transport only in the dedicated hermetic build.
func NewTestImplementation(descriptor []byte) (generator.Implementation, error) {
	ordinary, err := NewImplementation(descriptor)
	if err != nil {
		return generator.Implementation{}, err
	}
	executor := client.NewTestClient()
	if executor == nil {
		return generator.Implementation{}, protocol.ErrProtocol
	}
	return implementation(ordinary.Binding, profile.ProductionOrigin, executor), nil
}
