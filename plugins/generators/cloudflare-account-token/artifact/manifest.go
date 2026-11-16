// Package artifact defines the public Cloudflare plugin dependency manifest.
package artifact

import (
	"errors"

	public "enkv.sh/sdk/artifact"
)

// ErrManifest identifies a non-generator or invalid build-facts manifest.
var ErrManifest = errors.New("cloudflare dependency manifest refused")

// DependencyManifest encodes generator build facts and returns owned bytes and
// their public dependency identity. It retains no facts aliases. Refusals
// support errors.Is with ErrManifest and preserve the public codec error.
func DependencyManifest(facts public.BuildFacts) ([]byte, [32]byte, error) {
	if facts.Role != "generator" {
		return nil, [32]byte{}, ErrManifest
	}
	body, err := public.EncodeDependency(facts)
	if err != nil {
		return nil, [32]byte{}, errors.Join(ErrManifest, err)
	}
	identity, err := public.DependencyID("generator", body)
	if err != nil {
		return nil, [32]byte{}, errors.Join(ErrManifest, err)
	}
	return body, [32]byte(identity), nil
}
