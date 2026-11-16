package conformance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/native"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

func projection() *manifest.Projection {
	return &manifest.Projection{Schema: manifest.Schema, FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}"), Selection: manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}, Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4}, Entries: []manifest.Entry{}, ExcludedEntries: []manifest.ExcludedEntry{}, ResolvedEntries: []manifest.EntryIdentity{}}
}
func emptyLiteral() string { return "private=reference\n" }
func artifactForTest(text string) []byte {
	owned := make([]byte, len(text))
	copy(owned, text)
	return owned
}
func authorImplementation(t *testing.T, render manifest.Renderer) native.Implementation {
	t.Helper()
	body, err := artifact.EncodeDescriptor(artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "controlled-manifest", Role: "manifest-generator", Version: "1.0.0", Wire: native.DescriptorWire(), Manifest: &artifact.ManifestDeclaration{ConfigContractID: "private/settings", FormatContractID: "private/format"}})
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := native.Bind(body, "private/settings", "private/format", manifest.Implementation{ValidateFormatSettings: func(context.Context, manifest.SettingsRequest) manifest.SettingsResult {
		return manifest.SettingsResult{Settings: []byte("{}")}
	}, Render: render})
	if err != nil {
		t.Fatal(err)
	}
	return implementation
}

func serveRenderer(ctx context.Context, r io.Reader, a, s io.WriteCloser, implementation native.Implementation, render manifest.Renderer) int {
	implementation.Render = render
	return native.Serve(ctx, r, a, s, implementation)
}
func authorFixture() Fixture {
	return Fixture{Projection: projection(), ExpectedArtifact: []byte(emptyLiteral())}
}
func authorRenderer(context.Context, manifest.View) manifest.Result {
	return manifest.Result{Artifact: artifactForTest(emptyLiteral())}
}

type authorTestWriter struct {
	destination io.WriteCloser
	write       func([]byte) (int, error)
	close       func() error
}

func (w *authorTestWriter) Write(b []byte) (int, error) {
	if w.write != nil {
		return w.write(b)
	}
	return w.destination.Write(b)
}
func (w *authorTestWriter) Close() error {
	if w.close != nil {
		return w.close()
	}
	return w.destination.Close()
}

type authorReaderOnly struct{ reader io.Reader }

func (r authorReaderOnly) Read(b []byte) (int, error) { return r.reader.Read(b) }

// full_only: false
func TestCheckImplementationInvokesActualRendererAndRejectsRawNormalization(t *testing.T) {
	for _, spare := range []int{0, 17} {
		name := "exact-expected-capacity"
		if spare != 0 {
			name = "borrowed-spare-capacity"
		}
		t.Run(name, func(t *testing.T) {
			fixture := authorFixture()
			expected := make([]byte, len(fixture.ExpectedArtifact), len(fixture.ExpectedArtifact)+spare)
			copy(expected, fixture.ExpectedArtifact)
			tail := bytes.Repeat([]byte{0xa5}, spare)
			copy(expected[len(expected):cap(expected)], tail)
			fixture.ExpectedArtifact = expected
			calls := 0
			actual := func(ctx context.Context, view manifest.View) manifest.Result {
				calls++
				return authorRenderer(ctx, view)
			}
			if err := CheckImplementation(t.Context(), native.Serve, authorImplementation(t, actual), fixture); err != nil || calls != 1 {
				t.Fatal("actual author did not complete once", calls, err)
			}
			if cap(fixture.ExpectedArtifact) != len(expected)+spare || !bytes.Equal(expected[len(expected):cap(expected)], tail) {
				t.Fatal("borrowed expected storage changed")
			}
		})
	}
	for _, f := range []manifest.Failure{manifest.InvalidInput, manifest.InvalidUTF8, manifest.LimitExceeded, manifest.Cancelled, manifest.Expired, manifest.InvalidResult} {
		t.Run(string(f), func(t *testing.T) {
			fixture := authorFixture()
			fixture.ExpectedArtifact, fixture.ExpectedFailure = nil, f
			if err := CheckImplementation(t.Context(), native.Serve, authorImplementation(t, func(context.Context, manifest.View) manifest.Result { return manifest.Result{Failure: f} }), fixture); err != nil {
				t.Fatal("valid exact closed failure refused", err)
			}
		})
	}
	for _, row := range []struct {
		name     string
		render   manifest.Renderer
		expected manifest.Failure
	}{
		{"empty-normalized-to-expected-failure", func(context.Context, manifest.View) manifest.Result { return manifest.Result{} }, manifest.InvalidResult},
		{"artifact-on-expected-failure", func(context.Context, manifest.View) manifest.Result {
			return manifest.Result{Artifact: []byte("x"), Failure: manifest.InvalidResult}
		}, manifest.InvalidResult},
		{"unknown-failure", func(context.Context, manifest.View) manifest.Result { return manifest.Result{Failure: "other"} }, manifest.InvalidResult},
		{"changed-byte", func(context.Context, manifest.View) manifest.Result {
			b := artifactForTest(emptyLiteral())
			b[0] ^= 1
			return manifest.Result{Artifact: b}
		}, ""},
		{"spare-capacity", func(context.Context, manifest.View) manifest.Result {
			b := make([]byte, len(emptyLiteral()), len(emptyLiteral())+1)
			copy(b, emptyLiteral())
			return manifest.Result{Artifact: b}
		}, manifest.InvalidResult},
		{"wrong-closed-failure", func(context.Context, manifest.View) manifest.Result {
			return manifest.Result{Failure: manifest.InvalidInput}
		}, manifest.InvalidResult},
	} {
		t.Run(row.name, func(t *testing.T) {
			fixture := authorFixture()
			expected := make([]byte, len(fixture.ExpectedArtifact), len(fixture.ExpectedArtifact)+17)
			copy(expected, fixture.ExpectedArtifact)
			fixture.ExpectedArtifact = expected
			if row.expected != "" {
				fixture.ExpectedArtifact, fixture.ExpectedFailure = nil, row.expected
			}
			calls := 0
			actual := func(ctx context.Context, view manifest.View) manifest.Result { calls++; return row.render(ctx, view) }
			if err := CheckImplementation(t.Context(), native.Serve, authorImplementation(t, actual), fixture); err == nil || calls != 1 {
				t.Fatal("bad raw author passed or was not reached", calls, err)
			}
		})
	}
}

// full_only: false
func TestCheckImplementationRejectsIncompleteSerializedExchange(t *testing.T) {
	for _, name := range []string{"status-magic", "status-length", "status-failure", "status-trailing", "artifact-short", "artifact-trailing", "status-not-closed", "artifact-not-closed", "duplicate-close", "write-after-close", "artifact-before-status-close", "uncleared-return", "unreleased-view", "changed-received-input", "missing-callback", "double-callback", "request-leftover"} {
		t.Run(name, func(t *testing.T) {
			var retained []byte
			var alternate *manifest.Projection
			serve := func(ctx context.Context, request io.Reader, artifact, status io.WriteCloser, implementation native.Implementation) int {
				render := implementation.Render
				a, s := &authorTestWriter{destination: artifact}, &authorTestWriter{destination: status}
				wrapped := func(ctx context.Context, view manifest.View) manifest.Result {
					if name == "missing-callback" {
						return authorRenderer(ctx, view)
					}
					if name == "unreleased-view" || name == "changed-received-input" {
						alternate = projection()
						if name == "changed-received-input" {
							alternate.TargetRecipientID[0] ^= 1
						}
						view = manifest.Borrow(alternate)
					}
					if name == "double-callback" {
						first := render(ctx, view)
						clear(first.Artifact[:cap(first.Artifact)])
					}
					result := render(ctx, view)
					retained = result.Artifact
					return result
				}
				switch name {
				case "status-magic", "status-length", "status-failure", "status-trailing":
					s.write = func(body []byte) (int, error) {
						b := append([]byte(nil), body...)
						switch name {
						case "status-magic":
							b[0] ^= 1
						case "status-length":
							b[len(b)-1] ^= 1
						case "status-failure":
							b[49] = 1
						}
						n, err := status.Write(b)
						if name == "status-trailing" && err == nil {
							_, err = status.Write([]byte{0})
						}
						return n, err
					}
				case "artifact-short", "artifact-trailing":
					a.write = func(body []byte) (int, error) {
						b := body
						if name == "artifact-short" {
							b = b[:len(b)-1]
						}
						_, err := artifact.Write(b)
						if name == "artifact-trailing" && err == nil {
							_, err = artifact.Write([]byte{0})
						}
						return len(body), err
					}
				case "status-not-closed":
					s.close = func() error { return nil }
				case "artifact-not-closed":
					a.close = func() error { return nil }
				case "duplicate-close":
					a.close = func() error { _ = artifact.Close(); _ = artifact.Close(); return nil }
				case "write-after-close":
					a.close = func() error { _ = artifact.Close(); _, _ = artifact.Write([]byte{0}); return nil }
				case "artifact-before-status-close":
					s.close = func() error { return nil }
					a.close = func() error { _ = artifact.Close(); return status.Close() }
				case "request-leftover":
					var encoded bytes.Buffer
					if err := protocol.WriteRenderRequest(ctx, &encoded, manifest.ID{11}, implementation.Identity().DescriptorID, manifest.Borrow(projection())); err != nil {
						t.Fatal(err)
					}
					b := make([]byte, encoded.Len()-1)
					if _, err := io.ReadFull(request, b); err != nil {
						t.Fatal(err)
					}
					request = bytes.NewReader(append(b, 0)) // final zero excluded-count byte
				}
				code := serveRenderer(ctx, request, a, s, implementation, wrapped)
				if name == "uncleared-return" {
					retained[0] = 1
				}
				return code
			}
			authorCalls := 0
			actual := func(ctx context.Context, view manifest.View) manifest.Result {
				authorCalls++
				return authorRenderer(ctx, view)
			}
			err := CheckImplementation(t.Context(), serve, authorImplementation(t, actual), authorFixture())
			wantCalls := 1
			if name == "missing-callback" {
				wantCalls = 0
			}
			if authorCalls != wantCalls {
				t.Fatal("actual author invocation count differs", authorCalls, wantCalls)
			}
			if alternate != nil {
				protocol.DisposeProjection(alternate)
			}
			clear(retained[:cap(retained)])
			if err == nil {
				t.Fatal("incomplete exchange passed", name)
			}
		})
	}
}

// full_only: false
func TestCheckImplementationRejectsIgnoredWriterOverflow(t *testing.T) {
	for _, stream := range []string{"artifact", "status"} {
		for _, method := range []string{"Write", "WriteString", "Copy"} {
			t.Run(stream+"/"+method, func(t *testing.T) {
				attempted := false
				serve := func(ctx context.Context, request io.Reader, artifact, status io.WriteCloser, implementation native.Implementation) int {
					render := implementation.Render
					selected := artifact
					if stream == "status" {
						selected = status
					}
					if _, ok := selected.(io.StringWriter); ok {
						t.Fatal("promoted WriteString bypass exposed")
					}
					if _, ok := selected.(io.ReaderFrom); ok {
						t.Fatal("promoted ReaderFrom bypass exposed")
					}
					writer := &authorTestWriter{destination: selected}
					writer.write = func(body []byte) (int, error) {
						n, err := selected.Write(body)
						if err != nil {
							return n, err
						}
						attempted = true
						// Both legal prefixes leave exactly one permitted trailing byte.
						switch method {
						case "Write":
							_, _ = selected.Write([]byte{1, 2})
						case "WriteString":
							_, _ = io.WriteString(selected, "xx")
						case "Copy":
							_, _ = io.Copy(selected, authorReaderOnly{strings.NewReader("xx")})
						}
						return n, nil // Deliberately ignore the refused trailing write.
					}
					if stream == "status" {
						status = writer
					} else {
						artifact = writer
					}
					return serveRenderer(ctx, request, artifact, status, implementation, render)
				}
				if err := CheckImplementation(t.Context(), serve, authorImplementation(t, authorRenderer), authorFixture()); err == nil || !attempted {
					t.Fatal("ignored overflow passed or was not reached", attempted, err)
				}
			})
		}
	}
}

// full_only: false
func TestCheckImplementationRefusesInvalidFixturesAndDetectsCallerMutation(t *testing.T) {
	checkRenderCallerContextDiagnosis(t)
	for _, name := range []string{"nil-context", "nil-serve", "nil-renderer", "nil-projection", "invalid-schema", "nonempty-failure-artifact", "empty-nonnil-failure-artifact", "unknown-failure"} {
		t.Run(name, func(t *testing.T) {
			fixture := authorFixture()
			ctx := t.Context()
			switch name {
			case "nil-context":
				ctx = nil
			case "nil-projection":
				fixture.Projection = nil
			case "invalid-schema":
				fixture.Projection.Schema = "other"
			case "nonempty-failure-artifact":
				fixture.ExpectedFailure = manifest.InvalidInput
			case "empty-nonnil-failure-artifact":
				fixture.ExpectedFailure = manifest.InvalidInput
				fixture.ExpectedArtifact = []byte{}
			case "unknown-failure":
				fixture.ExpectedFailure = "other"
				fixture.ExpectedArtifact = nil
			}
			calls := 0
			serve := func(context.Context, io.Reader, io.WriteCloser, io.WriteCloser, native.Implementation) int {
				calls++
				return 0
			}
			var selectedServe Serve = serve
			var selectedRenderer manifest.Renderer = authorRenderer
			if name == "nil-serve" {
				selectedServe = nil
			}
			if name == "nil-renderer" {
				selectedRenderer = nil
			}
			if err := CheckImplementation(ctx, selectedServe, authorImplementation(t, selectedRenderer), fixture); err == nil || calls != 0 || !errors.Is(err, protocol.ErrWire) {
				t.Fatal("bad fixture reached serving", calls, err)
			}
		})
	}
	for _, name := range []string{"caller-projection", "expected-bytes", "expected-artifact-alias"} {
		t.Run(name, func(t *testing.T) {
			fixture := authorFixture()
			actual := func(ctx context.Context, view manifest.View) manifest.Result {
				if name == "expected-artifact-alias" {
					return manifest.Result{Artifact: fixture.ExpectedArtifact}
				}
				if name == "caller-projection" {
					fixture.Projection.TargetRecipientID[0] ^= 1
				} else {
					fixture.ExpectedArtifact[0] ^= 1
				}
				return authorRenderer(ctx, view)
			}
			if err := CheckImplementation(t.Context(), native.Serve, authorImplementation(t, actual), fixture); err == nil || err.Error() != "manifest author check: callback.fixture: caller storage changed: manifest exchange invalid" {
				t.Fatal("caller mutation was not identified", err)
			}
		})
	}
}

// full_only: false
func TestCheckImplementationRefusesCallbackBeforeJoin(t *testing.T) {
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan int, 1)
	actual := func(ctx context.Context, view manifest.View) manifest.Result {
		close(entered)
		<-release
		return authorRenderer(ctx, view)
	}
	serve := func(ctx context.Context, request io.Reader, artifact, status io.WriteCloser, implementation native.Implementation) int {
		render := implementation.Render
		go func() { joined <- serveRenderer(ctx, request, artifact, status, implementation, render) }()
		<-entered
		return 0
	}
	err := CheckImplementation(t.Context(), serve, authorImplementation(t, actual), authorFixture())
	close(release)
	if code := <-joined; code != 1 {
		t.Fatal("test serving child did not refuse finalized I/O and join", code)
	}
	if err == nil || err.Error() != "manifest author check: callback.completion: count or join invalid: manifest exchange invalid" {
		t.Fatal("unjoined callback passed", err)
	}
}

// full_only: false
func TestCheckImplementationClosesAdmissionBeforeDelayedUse(t *testing.T) {
	var request io.Reader
	var artifact, status io.WriteCloser
	var late manifest.Renderer
	serve := func(_ context.Context, r io.Reader, a, s io.WriteCloser, implementation native.Implementation) int {
		render := implementation.Render
		request, artifact, status, late = r, a, s, render
		return 0
	}
	authorCalls := 0
	actual := func(ctx context.Context, view manifest.View) manifest.Result {
		authorCalls++
		return authorRenderer(ctx, view)
	}
	if err := CheckImplementation(t.Context(), serve, authorImplementation(t, actual), authorFixture()); err == nil {
		t.Fatal("uncalled author passed")
	}
	if result := late(t.Context(), manifest.Borrow(projection())); result.Artifact != nil || result.Failure != manifest.InvalidInput || authorCalls != 0 {
		t.Fatal("delayed callback reached author", authorCalls, result.Failure)
	}
	var body [1]byte
	if n, err := request.Read(body[:]); n != 0 || err != io.ErrClosedPipe {
		t.Fatal("delayed request read touched finalized backing", n, err)
	}
	for _, w := range []io.WriteCloser{artifact, status} {
		if n, err := w.Write(body[:]); n != 0 || err != io.ErrClosedPipe {
			t.Fatal("delayed write touched finalized backing", n, err)
		}
		if err := w.Close(); err != io.ErrClosedPipe {
			t.Fatal("delayed close touched finalized owner", err)
		}
	}
}

// full_only: false
func TestCheckImplementationRejectsConcurrentDuplicateAuthorEntry(t *testing.T) {
	var authorCalls atomic.Int32
	actual := func(ctx context.Context, view manifest.View) manifest.Result {
		authorCalls.Add(1)
		return authorRenderer(ctx, view)
	}
	servingCode := -1
	serve := func(ctx context.Context, request io.Reader, artifact, status io.WriteCloser, implementation native.Implementation) int {
		render := implementation.Render
		servingCode = serveRenderer(ctx, request, artifact, status, implementation, func(callbackContext context.Context, view manifest.View) manifest.Result {
			start := make(chan struct{})
			results := make(chan manifest.Result, 2)
			var joined sync.WaitGroup
			joined.Add(2)
			for i := 0; i < 2; i++ {
				go func() {
					defer joined.Done()
					<-start
					results <- render(callbackContext, view)
				}()
			}
			close(start)
			first, second := <-results, <-results
			joined.Wait()
			if first.Artifact == nil {
				first, second = second, first
			}
			clear(second.Artifact[:cap(second.Artifact)])
			return first
		})
		return servingCode
	}
	err := CheckImplementation(t.Context(), serve, authorImplementation(t, actual), authorFixture())
	if err == nil || err.Error() != "manifest author check: callback.completion: count or join invalid: manifest exchange invalid" || authorCalls.Load() != 1 || servingCode != 0 {
		t.Fatal("concurrent duplicate author entry was not refused after joined serving", authorCalls.Load(), servingCode, err)
	}
}

// full_only: false
func TestCheckSettingsImplementationInvokesAuthorAndRejectsRawNormalization(t *testing.T) {
	checkSettingsCallerContextDiagnosis(t)
	fixture := SettingsFixture{Request: manifest.SettingsRequest{FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}")}, ExpectedSettings: []byte(`{"prefix":"dev"}`)}
	for _, condition := range []string{"complete", "wrong-settings", "borrowed-input", "empty-normalized-to-failure", "caller-mutation"} {
		t.Run(condition, func(t *testing.T) {
			copyFixture := fixture
			copyFixture.Request.Settings = append([]byte(nil), fixture.Request.Settings...)
			copyFixture.ExpectedSettings = append([]byte(nil), fixture.ExpectedSettings...)
			implementation := authorImplementation(t, authorRenderer)
			calls := 0
			implementation.ValidateFormatSettings = func(_ context.Context, input manifest.SettingsRequest) manifest.SettingsResult {
				calls++
				switch condition {
				case "wrong-settings":
					return manifest.SettingsResult{Settings: []byte(`{"prefix":"other"}`)}
				case "borrowed-input":
					return manifest.SettingsResult{Settings: input.Settings}
				case "empty-normalized-to-failure":
					return manifest.SettingsResult{}
				case "caller-mutation":
					copyFixture.Request.Settings[0] = '['
				}
				return manifest.SettingsResult{Settings: []byte(`{"prefix":"dev"}`)}
			}
			if condition == "empty-normalized-to-failure" {
				copyFixture.ExpectedSettings = nil
				copyFixture.ExpectedFailure = manifest.InvalidResult
			}
			err := CheckSettingsImplementation(t.Context(), native.Serve, implementation, copyFixture)
			if condition == "complete" {
				if err != nil || calls != 1 {
					t.Fatal(calls, err)
				}
			} else if err == nil || calls != 1 {
				t.Fatal("bad author accepted or not invoked", calls, err)
			}
		})
	}
}
