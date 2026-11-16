// Command ini-reference-manifest serves the example/ini-reference/v1 format.
// It embeds plugin.json, binds its settings and renderer callbacks, and runs one
// native manifest operation. Build and capture it with enkv-plugin-build; direct
// shell execution does not supply the required native pipes and environment.
package main

import (
	_ "embed"
	"os"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/native"
)

//go:embed plugin.json
var descriptorJSON []byte

func implementation() (native.Implementation, error) {
	return native.Bind(descriptorJSON, configContract, formatContract, manifest.Implementation{ValidateFormatSettings: validateSettings, Render: render})
}

func main() {
	implementation, err := implementation()
	if err != nil {
		os.Exit(2)
	}
	os.Exit(native.Main(implementation))
}
