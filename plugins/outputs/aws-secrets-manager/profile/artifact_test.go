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
	if err != nil || id.String() != "f1c462b07394555dd7a2d602b48c678bb2b2f8901310cff5713a972fbc43d6c0" {
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
