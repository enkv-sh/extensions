package profile

import (
	"crypto/sha256"
	"enkv.sh/sdk/artifact/credentialroute"
)

// CredentialEnvironment is the sole private environment input for the plugin.
const CredentialEnvironment = "CLOUDFLARE_API_TOKEN"

// CredentialRoute returns an independently owned declaration of the one-token route.
func CredentialRoute() credentialroute.Route {
	return credentialroute.Route{Schema: credentialroute.Schema, ContractID: sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CREDENTIAL/v1\x00")), Mode: credentialroute.ModeEnvironment, Names: []string{CredentialEnvironment}}
}
