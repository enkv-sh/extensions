//go:build enkv_cloudflare_testartifact

// Command enkv-generator-cloudflare-test serves the dedicated hermetic Cloudflare generator fixture;
// it is not a production service client.
package main

import (
	_ "embed"
	"enkv.sh/plugins/generators/cloudflare-account-token"
	"enkv.sh/sdk/generator"
	"os"
)

//go:embed plugin.json
var descriptorBytes []byte

func main() {
	implementation, err := cloudflare.NewTestImplementation(descriptorBytes)
	if err != nil {
		os.Exit(20)
	}
	os.Exit(generator.Main(implementation))
}
