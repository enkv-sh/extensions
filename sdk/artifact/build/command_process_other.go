//go:build (!darwin || !arm64) && (!linux || !amd64)

package build

import (
	"context"
	"errors"
	"os/exec"
)

func runGoCommand(ctx context.Context, command *exec.Cmd) (bool, error) {
	return true, errors.New("Go command native process ownership is unsupported")
}
