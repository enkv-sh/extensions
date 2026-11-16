// Package native binds author callbacks to a descriptor and serves one manifest
// operation on native pipes. Call Bind with the embedded plugin.json, supported
// config and format contracts, then pass its result to Main.
//
// For in-process author checks, pass Serve to the conformance package. A complete
// exchange may report a closed failure; it does not prove format correctness.
// Native execution is trusted code, not a sandbox.
package native

import (
	"bytes"
	"context"
	"io"
	"reflect"

	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

func nilArgument(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Chan, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func contextFailure(ctx context.Context) manifest.Failure {
	if nilArgument(ctx) {
		return manifest.InvalidInput
	}
	return manifest.FailureFromContextError(ctx.Err())
}
func byteSpansOverlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for i := range a {
		if &a[i] == &b[0] {
			return true
		}
	}
	for i := range b {
		if &b[i] == &a[0] {
			return true
		}
	}
	return false
}

// Serve borrows request and owns both writers, including on refusal. The caller
// must unblock reads on cancellation. Zero means a complete closed exchange;
// one means incomplete I/O and two means invalid invocation. None proves format
// validity, semantic correspondence or authenticated Reader success. Both
// callbacks must be present in a value returned by Bind.
//
// Callbacks run synchronously and must join their work before returning. Serve
// clears the full capacity of callback returns and disposes decoded request
// backing on every path. A reported callback failure sends no artifact bytes;
// I/O failure can leave a partial exchange. A complete exchange closes status
// before writing artifact bytes, then closes artifact. Serve does not close request.
func Serve(ctx context.Context, request io.Reader, artifact, status io.WriteCloser, implementation Implementation) (code int) {
	statusClosed, artifactClosed := false, false
	var input protocol.Request
	var rendered manifest.Result
	var settings manifest.SettingsResult
	var encoded []byte
	defer func() {
		if !statusClosed && !nilArgument(status) {
			if err := status.Close(); err != nil && code == 0 {
				code = 1
			}
		}
		if !artifactClosed && !nilArgument(artifact) {
			if err := artifact.Close(); err != nil && code == 0 {
				code = 1
			}
		}
		clear(rendered.Artifact[:cap(rendered.Artifact)])
		clear(settings.Settings[:cap(settings.Settings)])
		clear(encoded[:cap(encoded)])
		protocol.Dispose(&input)
	}()
	if nilArgument(ctx) || nilArgument(request) || nilArgument(artifact) || nilArgument(status) || implementation.Identity().ProtocolID != protocol.ProtocolID() || implementation.Identity().DescriptorID.IsZero() || implementation.ValidateFormatSettings == nil || implementation.Render == nil {
		return 2
	}
	var failure manifest.Failure
	var err error
	input, failure, err = protocol.ReadRequest(ctx, request)
	if err != nil {
		return 1
	}
	if input.Correlation.IsZero() {
		if failure == manifest.Cancelled || failure == manifest.Expired {
			return 1
		}
		return 2
	}
	if input.DescriptorID != implementation.Identity().DescriptorID {
		failure = manifest.InvalidInput
	}
	var output []byte
	if failure == "" {
		switch input.Operation {
		case protocol.OperationValidateSettings:
			digest, digestErr := protocol.SettingsRequestDigest(ctx, input)
			if digestErr != nil {
				return 1
			}
			settings = implementation.ValidateFormatSettings(ctx, input.Settings)
			failure = settings.Failure
			// Exact capacity is insufficient: a callback could return a slice of
			// borrowed settings. Check overlap across both full visible capacities.
			if manifest.ValidateSettingsResult(settings) != "" || byteSpansOverlap(settings.Settings[:cap(settings.Settings)], input.Settings.Settings[:cap(input.Settings.Settings)]) {
				failure = manifest.InvalidResult
			}
			if failure == "" && input.Settings.Canonical && !bytes.Equal(settings.Settings, input.Settings.Settings) {
				failure = manifest.InvalidResult
			}
			if contextFailure(ctx) == "" {
				after, afterErr := protocol.SettingsRequestDigest(ctx, input)
				if afterErr != nil || after != digest {
					failure = manifest.InvalidResult
				}
			}
			if f := contextFailure(ctx); f != "" {
				failure = f
			}
			if failure == "" {
				buffer := bytes.NewBuffer(make([]byte, 0, protocol.MaximumSettingsResponseBytes))
				encoded = buffer.Bytes()
				if err := protocol.WriteSettingsResponse(ctx, buffer, protocol.SettingsResponse{RequestDigest: digest, Settings: settings.Settings}); err != nil {
					encoded = buffer.Bytes()
					return 1
				}
				encoded = buffer.Bytes()
				output = encoded
			}
		case protocol.OperationRender:
			rendered = implementation.Render(ctx, manifest.Borrow(input.Projection))
			failure = rendered.Failure
			if manifest.ValidateResult(rendered) != "" {
				failure = manifest.InvalidResult
			}
			if failure == "" {
				output = rendered.Artifact
			}
		default:
			failure = manifest.InvalidInput
		}
	}
	if f := contextFailure(ctx); f != "" {
		failure = f
	}
	wire := protocol.Status{Correlation: input.Correlation, Failure: failure}
	if failure == "" {
		wire.Length = uint64(len(output))
	}
	if err := protocol.WriteStatus(status, wire); err != nil {
		return 1
	}
	// Commit and close status before artifact bytes so the receiver knows the
	// closed outcome and exact length before it consumes the artifact stream.
	statusClosed = true
	if err := status.Close(); err != nil {
		return 1
	}
	if failure == "" {
		for at := 0; at < len(output); {
			end := min(at+manifest.PlainWindowBytes, len(output))
			n, err := artifact.Write(output[at:end])
			if err != nil || n != end-at {
				return 1
			}
			at = end
		}
	}
	artifactClosed = true
	if err := artifact.Close(); err != nil {
		return 1
	}
	return 0
}
