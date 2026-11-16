package profile

import (
	"encoding/hex"
	"enkv.sh/sdk/artifact/credentialroute"
	"testing"
)

// full_only: false
func TestArtifactCredentialRecipeIdentity(t *testing.T) {
	// Independent struct/hashlib framing of schema1, contract digest, mode/count,
	// the19-byte environment name and empty public data.
	route := CredentialRoute()
	id, err := credentialroute.Identity(route)
	if err != nil || hex.EncodeToString(id[:]) != "a21e2054c69433b02e91c563f60967a4b640ebf1ad275126da09cafd38604350" || len(route.Names) != 1 || route.Names[0] != "CLOUDFLARE_API_TOKEN" {
		t.Fatal("credential recipe differs")
	}
}
