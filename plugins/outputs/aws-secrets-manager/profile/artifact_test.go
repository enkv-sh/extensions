package profile

import (
	"encoding/hex"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"os"
	"testing"
)

// full_only: false
func TestArtifactCredentialRecipeIdentities(t *testing.T) {
	raw, err := os.ReadFile("../cmd/enkv-output-aws-secrets-manager/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifact.DecodeDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Identity()
	if err != nil || id.String() != "e94b164f79a21c5db3aa780ece37c940a915ee76bcc01e86f67fd8c103195fa3" {
		t.Fatal("independent exact descriptor identity", id, err)
	}
	route, err := credentialroute.Decode(d.Output.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil || hex.EncodeToString(routeID[:]) != "6a9e5b236a8b4fcd66b1149679e1d77cf791bda023676896859e2db8e0f83f90" || route.Mode != credentialroute.ModeSDK {
		t.Fatal("independent standard discovery identity", err)
	}
}
