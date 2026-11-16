package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"testing"

	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

type writerFixture struct {
	bytes.Buffer
	name                   string
	events                 *[]string
	closes                 int
	short, fail, closeFail bool
	borrowed               []byte
	beforeClose            func()
}

func (w *writerFixture) Write(b []byte) (int, error) {
	*w.events = append(*w.events, w.name+"-write")
	w.borrowed = b
	if w.fail {
		return 0, errors.New("write refused")
	}
	if w.short {
		return len(b) - 1, nil
	}
	return w.Buffer.Write(b)
}
func (w *writerFixture) Close() error {
	if w.beforeClose != nil {
		w.beforeClose()
	}
	*w.events = append(*w.events, w.name+"-close")
	w.closes++
	if w.closeFail {
		return errors.New("close refused")
	}
	return nil
}
func implementationFixture(render manifest.Renderer) Implementation {
	return Implementation{identity: manifest.Identity{ProtocolID: protocol.ProtocolID(), DescriptorID: manifest.ID{9}}, Implementation: manifest.Implementation{ValidateFormatSettings: func(context.Context, manifest.SettingsRequest) manifest.SettingsResult {
		return manifest.SettingsResult{Settings: []byte("{}")}
	}, Render: render}}
}
func requestFixture(t *testing.T) *bytes.Reader {
	t.Helper()
	p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}"), Selection: manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}, Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4}, Entries: []manifest.Entry{}, ExcludedEntries: []manifest.ExcludedEntry{}, ResolvedEntries: []manifest.EntryIdentity{}}
	var b bytes.Buffer
	if err := protocol.WriteRequest(context.Background(), &b, protocol.Request{Operation: protocol.OperationRender, Correlation: manifest.ID{8}, DescriptorID: manifest.ID{9}, Projection: p}); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b.Bytes())
}

// full_only: false
func TestServeOwnsWritersAndClosesStatusBeforeArtifact(t *testing.T) {
	events := []string{}
	artifact := &writerFixture{name: "artifact", events: &events}
	status := &writerFixture{name: "status", events: &events}
	owned := []byte("{}")
	calls := 0
	code := Serve(context.Background(), requestFixture(t), artifact, status, implementationFixture(func(_ context.Context, v manifest.View) manifest.Result {
		calls++
		if v.Header().TargetRecipientID != (manifest.ID{4}) {
			t.Fatal("view differs")
		}
		return manifest.Result{Artifact: owned}
	}))
	if code != 0 || calls != 1 || artifact.closes != 1 || status.closes != 1 || !slices.Equal(events, []string{"status-write", "status-close", "artifact-write", "artifact-close"}) {
		t.Fatal(code, calls, events)
	}
	s, err := protocol.ReadStatus(bytes.NewReader(status.Bytes()))
	if err != nil || s.Failure != "" || s.Length != 2 || artifact.String() != "{}" {
		t.Fatal(s, err)
	}
	if !bytes.Equal(owned, []byte{0, 0}) {
		t.Fatal("child artifact not cleared")
	}
}

// full_only: false
func TestServeClosedFailuresAndIncompleteIO(t *testing.T) {
	for _, condition := range []string{"failure", "unknown", "artifact-on-failure", "spare-capacity", "nil-artifact", "cancelled", "status-short", "status-error", "status-close", "artifact-short", "artifact-error", "artifact-close", "nil-context", "nil-request", "nil-renderer", "nil-artifact-stream", "nil-status-stream"} {
		t.Run(condition, func(t *testing.T) {
			events := []string{}
			a := &writerFixture{name: "artifact", events: &events}
			s := &writerFixture{name: "status", events: &events}
			a.beforeClose = func() {
				if len(a.borrowed) > 0 && bytes.Equal(a.borrowed, make([]byte, len(a.borrowed))) {
					t.Fatal("artifact cleared before owned writer close")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := manifest.Result{Artifact: []byte("{}")}
			switch condition {
			case "failure":
				result.Artifact = nil
				result.Failure = manifest.InvalidInput
			case "unknown":
				result.Failure = "private error"
			case "artifact-on-failure":
				result.Failure = manifest.InvalidInput
			case "spare-capacity":
				result.Artifact = []byte{'{', '}', 0xcc}[:2]
			case "nil-artifact":
				result.Artifact = nil
			case "cancelled":
				cancel()
			case "status-short":
				s.short = true
			case "status-error":
				s.fail = true
			case "status-close":
				s.closeFail = true
			case "artifact-short":
				a.short = true
			case "artifact-error":
				a.fail = true
			case "artifact-close":
				a.closeFail = true
			case "nil-context":
				ctx = nil
			}
			var request io.Reader = requestFixture(t)
			if condition == "nil-request" {
				request = nil
			}
			var owned []byte
			render := manifest.Renderer(func(context.Context, manifest.View) manifest.Result {
				owned = result.Artifact[:cap(result.Artifact)]
				return result
			})
			if condition == "nil-renderer" {
				render = nil
			}
			var artifact, status io.WriteCloser = a, s
			if condition == "nil-artifact-stream" {
				artifact = nil
			}
			if condition == "nil-status-stream" {
				status = nil
			}
			code := Serve(ctx, request, artifact, status, implementationFixture(render))
			want := 0
			switch condition {
			case "status-short", "status-error", "status-close", "artifact-short", "artifact-error", "artifact-close", "cancelled":
				want = 1
			case "nil-context", "nil-request", "nil-renderer", "nil-artifact-stream", "nil-status-stream":
				want = 2
			}
			if code != want || artifact != nil && a.closes != 1 || status != nil && s.closes != 1 {
				t.Fatal(code, want, a.closes, s.closes)
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("returned artifact backing remained")
			}
			if want != 0 {
				return
			}
			out, err := protocol.ReadStatus(bytes.NewReader(s.Bytes()))
			if err != nil || out.Failure == "" || out.Length != 0 || a.Len() != 0 {
				t.Fatal(out, err)
			}
		})
	}
}

type borrowedRequest struct {
	*bytes.Reader
	closed bool
}

func (r *borrowedRequest) Close() error { r.closed = true; return nil }

// full_only: false
func TestServeBorrowsRequestAndRefusesItBeforeRenderer(t *testing.T) {
	for _, condition := range []string{"complete", "invalid-magic", "truncated"} {
		t.Run(condition, func(t *testing.T) {
			original := requestFixture(t)
			body := make([]byte, original.Len())
			if _, err := original.Read(body); err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "invalid-magic":
				body[0] = 'X'
			case "truncated":
				body = body[:len(body)-1]
			}
			request := &borrowedRequest{Reader: bytes.NewReader(body)}
			events := []string{}
			a := &writerFixture{name: "artifact", events: &events}
			s := &writerFixture{name: "status", events: &events}
			calls := 0
			code := Serve(context.Background(), request, a, s, implementationFixture(func(context.Context, manifest.View) manifest.Result {
				calls++
				return manifest.Result{Artifact: []byte("{}")}
			}))
			if request.closed || a.closes != 1 || s.closes != 1 {
				t.Fatal("stream ownership differs", request.closed, a.closes, s.closes)
			}
			if condition == "complete" {
				if code != 0 || calls != 1 {
					t.Fatal(code, calls)
				}
				return
			}
			if calls != 0 || a.Len() != 0 {
				t.Fatal("invalid request reached renderer", calls, code)
			}
			if condition == "truncated" {
				if code != 1 {
					t.Fatal("truncated I/O completed", code)
				}
				return
			}
			if code != 2 || s.Len() != 0 {
				t.Fatal("malformed header completed a correlated exchange", code)
			}
		})
	}
}

// full_only: false
func TestServeSettingsOwnsCanonicalResultAndBindsRequest(t *testing.T) {
	for _, condition := range []string{"normalized", "canonical", "copied-marshal", "maximum-copy", "changed-canonical", "borrowed-result", "mutated-input", "malformed-result", "spare-capacity", "wrong-descriptor", "late-cancel"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := protocol.Request{Operation: protocol.OperationValidateSettings, Correlation: manifest.ID{8}, DescriptorID: manifest.ID{9}, Settings: manifest.SettingsRequest{FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}")}}
			if condition == "canonical" || condition == "changed-canonical" {
				input.Settings.Canonical = true
				input.Settings.Settings = []byte(`{"prefix":"dev"}`)
			}
			var request bytes.Buffer
			if err := protocol.WriteRequest(t.Context(), &request, input); err != nil {
				t.Fatal(err)
			}
			digest, err := protocol.SettingsRequestDigest(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			events := []string{}
			artifact := &writerFixture{name: "artifact", events: &events}
			status := &writerFixture{name: "status", events: &events}
			calls := 0
			var returned, borrowed []byte
			implementation := implementationFixture(func(context.Context, manifest.View) manifest.Result {
				t.Fatal("settings reached render")
				return manifest.Result{}
			})
			implementation.ValidateFormatSettings = func(callbackContext context.Context, settings manifest.SettingsRequest) manifest.SettingsResult {
				calls++
				borrowed = settings.Settings
				returned = []byte(`{"prefix":"dev"}`)
				if condition == "copied-marshal" || condition == "maximum-copy" {
					var scratch []byte
					if condition == "maximum-copy" {
						scratch = make([]byte, 16384, 20000)
						for i := range scratch {
							scratch[i] = 's'
						}
						scratch[0], scratch[len(scratch)-1] = '"', '"'
					} else {
						var err error
						scratch, err = json.Marshal(struct {
							Prefix string `json:"prefix"`
						}{"dev"})
						if err != nil {
							t.Fatal(err)
						}
					}
					defer clear(scratch[:cap(scratch)])
					result := manifest.CopySettingsResult(callbackContext, scratch)
					returned = result.Settings
					return result
				}
				switch condition {
				case "changed-canonical":
					returned = []byte(`{"prefix":"other"}`)
				case "borrowed-result":
					returned = settings.Settings
				case "mutated-input":
					settings.Settings[0] = '['
				case "malformed-result":
					returned = []byte("{")
				case "spare-capacity":
					returned = []byte{'{', '}', 0xcc}[:2]
				case "late-cancel":
					cancel()
				}
				return manifest.SettingsResult{Settings: returned}
			}
			if condition == "wrong-descriptor" {
				implementation.identity.DescriptorID = manifest.ID{10}
			}
			code := Serve(ctx, bytes.NewReader(request.Bytes()), artifact, status, implementation)
			if code != 0 || artifact.closes != 1 || status.closes != 1 {
				t.Fatal(code, artifact.closes, status.closes)
			}
			wire, err := protocol.ReadStatus(bytes.NewReader(status.Bytes()))
			if err != nil || wire.Correlation != input.Correlation {
				t.Fatal(wire, err)
			}
			if condition == "normalized" || condition == "canonical" || condition == "copied-marshal" || condition == "maximum-copy" {
				if wire.Failure != "" || calls != 1 {
					t.Fatal(wire, calls)
				}
				response, f, err := protocol.ReadSettingsResponse(t.Context(), bytes.NewReader(artifact.Bytes()), digest, nil)
				want := []byte(`{"prefix":"dev"}`)
				if condition == "maximum-copy" {
					want = append([]byte{'"'}, bytes.Repeat([]byte{'s'}, 16382)...)
					want = append(want, '"')
				}
				if err != nil || f != "" || !bytes.Equal(response.Settings, want) || len(response.Settings) != cap(response.Settings) {
					t.Fatal(f, err)
				}
				clear(response.Settings)
			} else {
				want := manifest.InvalidResult
				if condition == "wrong-descriptor" {
					want = manifest.InvalidInput
					if calls != 0 {
						t.Fatal("mismatched descriptor invoked author")
					}
				}
				if condition == "late-cancel" {
					want = manifest.Cancelled
				}
				if wire.Failure != want || wire.Length != 0 || artifact.Len() != 0 {
					t.Fatal(wire, want)
				}
			}
			if !bytes.Equal(returned[:cap(returned)], make([]byte, cap(returned))) || !bytes.Equal(borrowed[:cap(borrowed)], make([]byte, cap(borrowed))) {
				t.Fatal("settings backing remained")
			}
		})
	}
}

type endedContext struct {
	context.Context
	cause error
}

func (c *endedContext) Err() error { return c.cause }

// full_only: false
func TestServeContextMappingPreservesOwnedWriters(t *testing.T) {
	var typedNil *endedContext
	for _, row := range []struct {
		name        string
		ctx         context.Context
		code, calls int
	}{
		{"nil", nil, 2, 0}, {"typed-nil", typedNil, 2, 0}, {"valid", t.Context(), 0, 1},
		{"cancelled", &endedContext{Context: t.Context(), cause: context.Canceled}, 1, 0},
		{"expired", &endedContext{Context: t.Context(), cause: context.DeadlineExceeded}, 1, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			events := []string{}
			a, s := &writerFixture{name: "artifact", events: &events}, &writerFixture{name: "status", events: &events}
			calls := 0
			owned := []byte("{}")
			code := Serve(row.ctx, requestFixture(t), a, s, implementationFixture(func(context.Context, manifest.View) manifest.Result { calls++; return manifest.Result{Artifact: owned} }))
			if code != row.code || calls != row.calls || a.closes != 1 || s.closes != 1 || calls > 0 && !bytes.Equal(owned, []byte{0, 0}) {
				t.Fatal("context changed callback or disposal", code, calls, events)
			}
		})
	}
}
