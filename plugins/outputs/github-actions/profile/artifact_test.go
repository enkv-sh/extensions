package profile

import (
	"encoding/hex"
	"enkv.sh/sdk/artifact/credentialroute"
	"testing"
)

// full_only: false
func TestArtifactCredentialRecipeIdentities(t *testing.T) {
	// Independently framed with Python struct/hashlib from the shared route grammar.
	route := CredentialRoute()
	body, err := credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0001095a90c4259f7ccf9c246c4b7d26fb40332049545082795aa400bbe2a8681d3601010c4749544855425f544f4b454e00000000"
	if hex.EncodeToString(body) != want {
		t.Fatal("route grammar differs")
	}
	id, err := credentialroute.Identity(route)
	if err != nil || hex.EncodeToString(id[:]) != "87cfb42eb2de2607a1074fb863fdecbc2ee89d15da619b67fbedb274445695af" {
		t.Fatal("route identity", err)
	}
}
