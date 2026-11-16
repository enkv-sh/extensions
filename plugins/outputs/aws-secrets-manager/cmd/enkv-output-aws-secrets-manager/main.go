// Command enkv-output-aws-secrets-manager serves the native output protocol for its fixed service and scope.
package main

import (
	_ "embed"
	"enkv.sh/plugins/outputs/aws-secrets-manager/execution"
	"enkv.sh/sdk/output"
	"os"
)

//go:embed plugin.json
var descriptor []byte

func main() {
	implementation, err := execution.NewImplementation(descriptor)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(output.Main(implementation))
}
