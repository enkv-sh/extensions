// Command enkv-generator-cloudflare serves the native generator protocol using its embedded descriptor.
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
	implementation, err := cloudflare.NewImplementation(descriptorBytes)
	if err != nil {
		os.Exit(20)
	}
	os.Exit(generator.Main(implementation))
}
