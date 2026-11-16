// Command enkv-generator-local-random-secret serves the native generator protocol using its embedded descriptor.
package main

import (
	_ "embed"
	"os"

	localrandom "enkv.sh/plugins/generators/local-random-secret"
	"enkv.sh/sdk/generator"
)

//go:embed plugin.json
var descriptorBytes []byte

func main() {
	implementation, err := localrandom.NewImplementation(descriptorBytes)
	if err != nil {
		os.Exit(20)
	}
	os.Exit(generator.Main(implementation))
}
