package native

import (
	"context"
	"os"
	"runtime"

	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

// Main serves one captured plugin invocation. It requires the protocol mode
// argument, an empty environment, /dev/null on descriptors 0–2, and request,
// artifact and status pipes on 3–5 with no extra inheritable descriptors. Supported
// tuples are darwin/arm64 and linux/amd64.
//
// Main owns descriptor 3 and delegates 4 and 5 to Serve after native validation.
// It returns Serve exit codes, including 2 for an invalid invocation. The parent
// enforces the finite invocation lifetime, unblocks native I/O and joins the child.
// Pass the result to os.Exit from the plugin main function.
func Main(implementation Implementation) (code int) {
	request := os.NewFile(3, "manifest request")
	artifact := os.NewFile(4, "manifest artifact")
	status := os.NewFile(5, "manifest status")
	delegated := false
	defer func() {
		for _, file := range []*os.File{request, artifact, status} {
			if file == nil || delegated && file != request {
				continue
			}
			if err := file.Close(); err != nil && code == 0 {
				code = 1
			}
		}
	}()
	if len(os.Args) != 2 || os.Args[1] != protocol.Mode || len(os.Environ()) != 0 || implementation.Render == nil || implementation.ValidateFormatSettings == nil || request == nil || artifact == nil || status == nil || (runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") || !fixedDescriptors() {
		return 2
	}
	delegated = true
	return Serve(context.Background(), request, artifact, status, implementation)
}
