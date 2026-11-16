package profile

import (
	"crypto/sha256"
	"enkv.sh/sdk/artifact/credentialroute"
)

// CredentialRoute returns an owned route declaring GITHUB_TOKEN only; GH_TOKEN
// is not a fallback.
func CredentialRoute() credentialroute.Route {
	return credentialroute.Route{Schema: credentialroute.Schema, ContractID: sha256.Sum256([]byte("github-actions/token-environment/v1\x00")), Mode: credentialroute.ModeEnvironment, Names: []string{"GITHUB_TOKEN"}}
}
