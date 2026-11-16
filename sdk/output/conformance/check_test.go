package conformance

import (
	"bytes"
	"context"
	"io"
	"testing"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestCheckAcceptsSharedServing(t *testing.T) {
	if err := Check(output.Run, output.RunPublic); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestCheckRejectsInvalidServing(t *testing.T) {
	for _, condition := range []string{"nil", "missing exchange", "trailing result", "missing passive", "missing policy action"} {
		t.Run(condition, func(t *testing.T) {
			serve, public := Serve(output.Run), ServePublic(output.RunPublic)
			switch condition {
			case "nil":
				serve = nil
			case "missing exchange":
				serve = func(context.Context, output.Endpoints, output.Implementation) int { return 0 }
			case "trailing result":
				serve = func(ctx context.Context, e output.Endpoints, p output.Implementation) int {
					status := output.Run(ctx, e, p)
					_, _ = e.Result.Write([]byte{0})
					return status
				}
			case "missing policy action":
				public = func(ctx context.Context, e output.PublicEndpoints, p output.Implementation) int {
					data, err := io.ReadAll(e.Control)
					if err != nil {
						return 1
					}
					reader := bytes.NewReader(data)
					if _, err := protocol.ReadFrame(reader, protocol.HelloBytes); err != nil {
						return 1
					}
					frame, err := protocol.ReadFrame(reader, protocol.MaximumPublicRequestBytes)
					if err != nil {
						return 1
					}
					if frame.Kind == protocol.KindPolicyActionRequest {
						return 0
					}
					e.Control = bytes.NewReader(data)
					return output.RunPublic(ctx, e, p)
				}
			case "missing passive":
				public = func(context.Context, output.PublicEndpoints, output.Implementation) int { return 0 }
			}
			if Check(serve, public) == nil {
				t.Fatal("broken serving passed")
			}
		})
	}
}
