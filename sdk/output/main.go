// Package output serves the public output family and supplies its native entry.
// It owns exchange correlation and disposal of decoded private buffers; the
// implementation owns service semantics and its own resources.
package output

import (
	"context"
	"os"
	"reflect"
	"runtime"
)

// Run synchronously serves one action exchange. It borrows all streams and
// closes none. The caller must bound I/O and unblock it on cancellation.
// Status 0 means a complete exchange, 1 means exchange failure, and 2 means
// invalid arguments. Status alone supplies no provider-effect evidence.
func Run(ctx context.Context, endpoints Endpoints, implementation Implementation) int {
	if nilArgument(ctx) || nilArgument(implementation) || nilArgument(endpoints.Control) || nilArgument(endpoints.Credential) || nilArgument(endpoints.Payload) || nilArgument(endpoints.Result) {
		return 2
	}
	if Serve(ctx, endpoints, implementation) != nil {
		return 1
	}
	return 0
}

// RunPublic synchronously serves one passive exchange. It borrows its streams,
// closes none and uses the same status meanings and I/O obligations as Run.
func RunPublic(ctx context.Context, endpoints PublicEndpoints, implementation Implementation) int {
	if nilArgument(ctx) || nilArgument(implementation) || nilArgument(endpoints.Control) || nilArgument(endpoints.Result) {
		return 2
	}
	if ServePublic(ctx, endpoints, implementation) != nil {
		return 1
	}
	return 0
}

func nilArgument(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Main owns and closes the descriptors assigned to the selected native mode.
// It accepts output-wire-v6 or output-public-v3, an empty environment, null
// standard streams and the supported native tuples. It writes no diagnostics.
// In effect mode it installs admitted declared environment inputs before Prepare
// and removes them after Prepared.Close, or on preparation refusal. Passive mode
// installs none. Removing variables does not erase immutable copies made by
// credential libraries. A close failure changes an otherwise successful status to 1.
func Main(implementation Implementation) (status int) {
	if len(os.Args) < 2 {
		return 2
	}
	passive := false
	switch os.Args[1] {
	case "output-wire-v6":
	case "output-public-v3":
		passive = true
	default:
		return 2
	}
	last := 6
	if passive {
		last = 4
	}
	files := make([]*os.File, 0, last-2)
	defer func() {
		for _, file := range files {
			if file != nil {
				if err := file.Close(); err != nil && status == 0 {
					status = 1
				}
			}
		}
	}()
	for fd := 3; fd <= last; fd++ {
		files = append(files, os.NewFile(uintptr(fd), "output stream"))
	}
	if len(os.Args) != 2 || len(os.Environ()) != 0 || nilArgument(implementation) ||
		(runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") || !fixedDescriptors(passive) {
		return 2
	}
	for _, file := range files {
		if file == nil {
			return 2
		}
	}
	if passive {
		return RunPublic(context.Background(), PublicEndpoints{Control: files[0], Result: files[1]}, implementation)
	}
	return Run(context.Background(), Endpoints{Control: files[0], Credential: files[1], Payload: files[2], Result: files[3]}, nativeImplementation{Implementation: implementation})
}
