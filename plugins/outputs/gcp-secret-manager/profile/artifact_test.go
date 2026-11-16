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
	raw, err := os.ReadFile("../cmd/enkv-output-gcp-secret-manager/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifact.DecodeDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Identity()
	if err != nil || id.String() != "9f01ecfc93cd90f623d10f43c2a100ad6fd39bc8da5371dbcce8f730bf42a298" {
		t.Fatal("independent exact descriptor identity", id, err)
	}
	route, err := credentialroute.Decode(d.Output.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil || hex.EncodeToString(routeID[:]) != "ed850a0133c5d22de7353375d02bc81bbe2ed8622fc77e24ef216bdc4fe89ba9" || route.Mode != credentialroute.ModeSDK {
		t.Fatal("independent standard discovery identity", err)
	}
}
