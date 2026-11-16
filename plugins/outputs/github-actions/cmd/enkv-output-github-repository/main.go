// Command enkv-output-github-repository serves the native output protocol for its fixed service and scope.
package main

import (
	_ "embed"
	"enkv.sh/plugins/outputs/github-actions/internal/github"
	"enkv.sh/plugins/outputs/github-actions/profile"
	"enkv.sh/sdk/output"
	"os"
)

//go:embed plugin.json
var descriptor []byte

func main() {
	implementation, err := github.New(profile.Repository, descriptor)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(output.Main(implementation))
}
