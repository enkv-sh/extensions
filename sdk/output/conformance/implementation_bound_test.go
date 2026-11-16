package conformance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestCheckImplementationRejectsIgnoredResultOverflow(t *testing.T) {
	for _, method := range []string{"write", "write-string", "copy"} {
		t.Run(method, func(t *testing.T) {
			p, err := newImplementation()
			if err != nil {
				t.Fatal(err)
			}
			var digestErr error
			p.command.PolicyDigest, digestErr = protocol.PolicyDigest(p.command.DomainID, p.policy)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			completed := false
			serve := func(ctx context.Context, e output.Endpoints, impl output.Implementation) int {
				result := e.Result
				var prefix bytes.Buffer
				e.Result = io.MultiWriter(result, &prefix)
				code := output.Run(ctx, e, impl)
				if code != 0 {
					t.Fatal("baseline serving failed", code)
				}
				completed = true
				if prefix.Len() == 0 || prefix.Len() > 4321 {
					t.Fatal("baseline result length outside exchange bound", prefix.Len())
				}
				// The additional write is one byte beyond the remaining capacity.
				body := bytes.Repeat([]byte{'x'}, 4321-prefix.Len()+1)
				var n int64
				var err error
				switch method {
				case "write":
					var written int
					written, err = result.Write(body)
					n = int64(written)
				case "write-string":
					var written int
					written, err = io.WriteString(result, strings.Repeat("x", len(body)))
					n = int64(written)
				case "copy":
					// Hide WriterTo so io.Copy tries destination ReaderFrom first.
					n, err = io.Copy(result, io.LimitReader(bytes.NewReader(body), int64(len(body))))
				}
				if n != 0 || !errors.Is(err, io.ErrShortWrite) {
					t.Errorf("oversized write accepted: n=%d err=%v", n, err)
				}
				return code // Deliberately ignore the refused trailing write.
			}
			err = CheckImplementation(context.Background(), serve, p, fixture(p))
			if !completed || p.calls != 1 || !p.valid || err == nil {
				t.Fatal("ignored overflow passed or callback did not run", err)
			}
		})
	}
}
