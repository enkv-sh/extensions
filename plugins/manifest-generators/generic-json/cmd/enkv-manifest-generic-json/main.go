// Command enkv-manifest-generic-json serves the native manifest protocol using its embedded format declaration.
package main

import (
	_ "embed"
	"enkv.sh/plugins/manifest-generators/generic-json/execution"
	"enkv.sh/sdk/manifest-generator/native"
	"os"
)

//go:embed plugin.json
var descriptorJSON []byte

func main() {
	implementation, err := execution.NewImplementation(descriptorJSON)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(native.Main(implementation))
}
