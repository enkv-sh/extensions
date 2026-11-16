// The local-value-output command serves the local value example through
// output.Main using the embedded author descriptor.
package main

import (
	_ "embed"
	"os"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
)

//go:embed plugin.json
var descriptorBytes []byte

func newImplementation() (*implementation, error) {
	binding, err := output.Bind(descriptorBytes, configContract)
	if err != nil {
		return nil, err
	}
	route := binding.CredentialRoute()
	if route.Mode != credentialroute.ModeEnvironment || len(route.Names) != 1 || route.Names[0] != "ENKV_EXAMPLE_TOKEN" || len(route.PublicData) != 0 {
		return nil, errLocalValue
	}
	return &implementation{Binding: binding}, nil
}

func main() {
	implementation, err := newImplementation()
	if err != nil {
		os.Exit(2)
	}
	os.Exit(output.Main(implementation))
}
