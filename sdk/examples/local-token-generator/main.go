// The local-token-generator command serves the managed local token example
// through generator.Main using the embedded author descriptor.
package main

import (
	_ "embed"
	"os"

	"enkv.sh/sdk/generator"
)

//go:embed plugin.json
var descriptorBytes []byte

func main() {
	implementation, err := implementation()
	if err != nil {
		os.Exit(20)
	}
	os.Exit(generator.Main(implementation))
}
