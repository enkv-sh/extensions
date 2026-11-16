package generator

import (
	"context"
	"errors"
	"os"
	"runtime"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

// Main owns descriptors 3 through 6. It starts with an empty environment and
// installs only admitted private inputs for the synchronous effect invocation.
// Call os.Exit(Main(implementation)) from the command entry. Main accepts only
// generator-wire-v5 on darwin/arm64 or linux/amd64 with the required null standard
// streams and FIFO layout. It removes installed variables on return; it cannot
// clear immutable runtime or service-client copies. Status zero means a complete
// exchange. A nonzero status supplies no service-effect or retry evidence.
func Main(implementation Implementation) (statusCode int) {
	files := []*os.File{os.NewFile(protocol.ControlDescriptor, "generator control"), os.NewFile(protocol.EnvironmentDescriptor, "generator environment"), os.NewFile(protocol.SecretResultDescriptor, "generator private result"), os.NewFile(protocol.StatusDescriptor, "generator status")}
	defer func() {
		var closeErrors []error
		for _, file := range files {
			if file != nil {
				closeErrors = append(closeErrors, file.Close())
			}
		}
		if errors.Join(closeErrors...) != nil && statusCode == exitSuccess {
			statusCode = exitDescriptorClose
		}
	}()
	if len(os.Args) != 2 || os.Args[1] != "generator-wire-v5" || len(os.Environ()) != 0 || (runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") || !fixedDescriptors() {
		return exitInvalidArguments
	}
	for _, file := range files {
		if file == nil {
			return exitInvalidArguments
		}
	}
	return run(context.Background(), files[0], files[1], files[2], files[3], implementation, installEnvironment)
}

func installEnvironment(inputs []credentialroute.Input) (func() error, error) {
	installed := make([]string, 0, len(inputs))
	cleanup := func() error {
		var errs []error
		for _, name := range installed {
			errs = append(errs, os.Unsetenv(name))
		}
		return errors.Join(errs...)
	}
	for _, input := range inputs {
		if !input.Present {
			continue
		}
		if err := os.Setenv(input.Name, string(input.Value)); err != nil {
			return nil, errors.Join(err, cleanup())
		}
		installed = append(installed, input.Name)
	}
	return cleanup, nil
}
