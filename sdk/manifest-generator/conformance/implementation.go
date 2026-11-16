// Package conformance checks author-supplied settings and artifact fixtures
// through the public callbacks and bounded native exchange.
//
// Bind the actual callbacks with native.Bind. Pass native.Serve (or a compatible
// synchronous serving function) to CheckSettingsImplementation and
// CheckImplementation. Supply a valid frozen request/projection and independently
// derived complete expected bytes, or a supported expected failure with nil bytes.
// Fixtures must contain test data, never operator secrets. Keep fixture storage
// unchanged until the check returns.
//
// The checks compare raw callback results, serialization, closure and observable
// disposal. They do not define a format or prove that expected bytes are correct.
// Authors must also compare decoded consumer values with independent expectations.
// Passing checks does not authenticate Reader state, qualify installation, prove
// absence of hidden aliases or sandbox arbitrary native code.
//
// Returned check errors support errors.Is with protocol.ErrWire. Cancellation and
// expiry can also wrap context.Canceled or context.DeadlineExceeded; check failures
// found first can take precedence over the caller context.
package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
	"sync"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/native"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

// Serve performs one synchronous manifest exchange and joins its users before
// returning. The signature matches native.Serve.
type Serve func(context.Context, io.Reader, io.WriteCloser, io.WriteCloser, native.Implementation) int

// Fixture borrows one valid frozen projection and independently expected bytes
// or an exact closed failure. All bytes are test data, never operator secrets.
type Fixture struct {
	Projection       *manifest.Projection
	ExpectedArtifact []byte
	ExpectedFailure  manifest.Failure
}

// CheckImplementation invokes the actual renderer once through the supplied
// serving function. It checks the raw return before serving normalization, then
// the serialized exchange and observable disposal. It does not authenticate
// Reader state or qualify installation. Callbacks must do finite synchronous
// work and join their users. The helper never writes caller fixture storage;
// it detects observable mutation but cannot prevent author or serving code from
// mutating externally captured storage. Released View accessors do not prove
// erasure of hidden backing inaccessible through the public API.
func CheckImplementation(ctx context.Context, serve Serve, implementation native.Implementation, fixture Fixture) error {
	fail := func(name string) error { return fmt.Errorf("manifest author check: %s: %w", name, protocol.ErrWire) }
	if nilContext(ctx) || serve == nil {
		return fail("fixture.context: missing context or serving function")
	}
	if implementation.Render == nil || implementation.ValidateFormatSettings == nil || implementation.Identity().ProtocolID != protocol.ProtocolID() || implementation.Identity().DescriptorID.IsZero() {
		return fail("fixture.implementation: invalid callbacks or identity")
	}
	auditContext := context.WithoutCancel(ctx)
	if manifest.Validate(auditContext, fixture.Projection) != "" {
		return fail("fixture.projection: invalid structure")
	}
	if !fixture.ExpectedFailure.Valid() {
		return fail("fixture.expected_failure: unsupported failure")
	}
	if fixture.ExpectedFailure == "" {
		if len(fixture.ExpectedArtifact) == 0 || uint64(len(fixture.ExpectedArtifact)) > manifest.MaxArtifactBytes {
			return fail("fixture.expected_artifact: invalid length")
		}

	} else if fixture.ExpectedArtifact != nil {
		return fail("fixture.expected_artifact: conflicting failure expectation")
	}
	if err := callerContextError(ctx); err != nil {
		return err
	}
	original, err := fingerprintView(ctx, manifest.Borrow(fixture.Projection), implementation.Identity().DescriptorID)
	if err != nil {
		if cause := callerContextError(ctx); cause != nil {
			return cause
		}
		return fail("fixture.request: encoding refused")
	}
	request := fixedAuthorBytes{owned: make([]byte, original.length)}
	defer clear(request.owned)
	if err := protocol.WriteRenderRequest(ctx, &request, manifest.ID{11}, implementation.Identity().DescriptorID, manifest.Borrow(fixture.Projection)); err != nil {
		if request.refused == nil {
			if cause := callerContextError(ctx); cause != nil {
				return cause
			}
		}
		return fail("fixture.request: encoding refused")
	}
	if request.refused != nil || request.used != original.length || sha256.Sum256(request.owned) != original.digest {
		return fail("fixture.request: encoding mismatch")
	}
	expectedDigest := sha256.Sum256(fixture.ExpectedArtifact)
	// Cancellation changes the callback outcome, not the frozen input facts.
	exchange := new(authorExchange)
	input := &authorInput{exchange: exchange, reader: bytes.NewReader(request.owned)}
	artifact := authorWriter{exchange: exchange, bytes: fixedAuthorBytes{owned: make([]byte, len(fixture.ExpectedArtifact)+1)}}
	status := authorWriter{exchange: exchange, bytes: fixedAuthorBytes{owned: make([]byte, protocol.StatusBytes+1)}, status: true}
	artifact.peer, status.peer = &status, &artifact
	defer clear(artifact.bytes.owned)
	defer clear(status.bytes.owned)
	defer func() {
		exchange.mu.Lock()
		exchange.finished = true
		exchange.mu.Unlock()
	}()
	calls := 0
	claimed, completed := false, false
	valid := true
	var returned []byte
	var received manifest.View
	var entry manifest.EntryView
	var destination manifest.DestinationView
	render := implementation.Render
	wrapped := implementation
	wrapped.Render = func(callbackContext context.Context, view manifest.View) manifest.Result {
		exchange.mu.Lock()
		if exchange.finished {
			exchange.mu.Unlock()
			return manifest.Result{Failure: manifest.InvalidInput}
		}
		calls++
		if claimed {
			exchange.mu.Unlock()
			return manifest.Result{Failure: manifest.InvalidInput}
		}
		claimed = true
		before, beforeErr := fingerprintView(auditContext, view, implementation.Identity().DescriptorID)
		received = view
		entry, _ = view.Entry(0)
		for i := 0; i < view.EntryCount(); i++ {
			e, _ := view.Entry(i)
			if d, ok := e.Destination(0); ok {
				destination = d
				break
			}
		}
		exchange.mu.Unlock()
		result := render(callbackContext, view)
		exchange.mu.Lock()
		defer exchange.mu.Unlock()
		if exchange.finished {
			// A caller that broke the synchronous Serve precondition must join
			// this callback. Forward its actual raw result for Serve's cleanup.
			return result
		}
		returned = result.Artifact
		after, afterErr := fingerprintView(auditContext, view, implementation.Identity().DescriptorID)
		valid = valid && beforeErr == nil && before == original && afterErr == nil && after == original &&
			manifest.ValidateResult(result) == "" && result.Failure == fixture.ExpectedFailure && bytes.Equal(result.Artifact, fixture.ExpectedArtifact)
		completed = true
		return result
	}
	code := serve(ctx, input, &artifact, &status, wrapped)
	exchange.mu.Lock()
	exchange.finished = true
	inputEOF := protocol.RequireEOF(input.reader)
	exchange.mu.Unlock()
	if claimed && !completed {
		return fail("callback.completion: count or join invalid")
	}
	after, afterErr := fingerprintView(auditContext, manifest.Borrow(fixture.Projection), implementation.Identity().DescriptorID)
	callerIntact := afterErr == nil && after == original && sha256.Sum256(fixture.ExpectedArtifact) == expectedDigest
	if !callerIntact {
		return fail("callback.fixture: caller storage changed")
	}
	if calls > 1 {
		return fail("callback.completion: count or join invalid")
	}
	if !valid {
		return fail("callback.result: wrong raw outcome or changed input")
	}
	if artifact.bytes.refused != nil || status.bytes.refused != nil || artifact.closes != 1 || status.closes != 1 || artifact.badOrder || status.badOrder {
		return fail("serving.completion: status or stream ownership invalid")
	}
	if !allZeroArtifact(returned[:cap(returned)]) || received.Header() != (manifest.Header{}) || received.EntryCount() != 0 || received.ExcludedCount() != 0 || received.Validate(auditContext) != manifest.InvalidInput ||
		entry.Metadata() != (manifest.EntryMetadata{}) || entry.PlainLength() != 0 || entry.DestinationCount() != 0 || destination.Metadata() != (manifest.DestinationMetadata{}) ||
		destination.PolicyLength() != 0 || destination.TargetDataLength() != 0 {
		return fail("disposal.borrowed_or_returned: backing not released")
	}
	if calls == 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return fail("callback.completion: count or join invalid")
	}
	if code != 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return fail("serving.completion: status or stream ownership invalid")
	}
	if inputEOF != nil {
		return fail("serving.request: trailing bytes")
	}
	wireStatus, err := protocol.ReadStatus(bytes.NewReader(status.bytes.owned[:status.bytes.used]))
	wantStatus := protocol.Status{Correlation: manifest.ID{11}, Failure: fixture.ExpectedFailure}
	if fixture.ExpectedFailure == "" {
		wantStatus.Length = uint64(len(fixture.ExpectedArtifact))
	}
	if err != nil || wireStatus.Correlation != wantStatus.Correlation {
		return fail("serialized.status: correlation or outcome mismatch")
	}
	if cause := callerContextError(ctx); cause != nil {
		expected := manifest.Cancelled
		if errors.Is(cause, context.DeadlineExceeded) {
			expected = manifest.Expired
		}
		if wireStatus.Failure == expected && wireStatus.Length == 0 {
			if artifact.bytes.used != 0 {
				return fail("serialized.artifact: unexpected failure bytes")
			}
			return cause
		}
	}
	if err != nil || wireStatus != wantStatus {
		return fail("serialized.status: correlation or outcome mismatch")
	}
	wireArtifact := bytes.NewReader(artifact.bytes.owned[:artifact.bytes.used])
	if wireArtifact.Len() != len(fixture.ExpectedArtifact) || !bytes.Equal(artifact.bytes.owned[:artifact.bytes.used], fixture.ExpectedArtifact) {
		return fail("serialized.artifact: exact bytes mismatch")
	}
	if _, err := wireArtifact.Seek(int64(len(fixture.ExpectedArtifact)), io.SeekStart); err != nil || protocol.RequireEOF(wireArtifact) != nil {
		return fail("serialized.artifact: trailing bytes")
	}
	return callerContextError(ctx)
}

func nilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	v := reflect.ValueOf(ctx)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

type inputFingerprint struct {
	length int
	digest [32]byte
}

type countedAuthorHash struct {
	hash   hash.Hash
	length int
}

// Write hashes request bytes while counting their complete encoded length.
func (w *countedAuthorHash) Write(body []byte) (int, error) {
	if len(body) > int(^uint(0)>>1)-w.length {
		return 0, io.ErrShortWrite
	}
	n, err := w.hash.Write(body)
	w.length += n
	return n, err
}

func fingerprintView(ctx context.Context, view manifest.View, descriptorID manifest.ID) (inputFingerprint, error) {
	w := countedAuthorHash{hash: sha256.New()}
	if err := protocol.WriteRenderRequest(ctx, &w, manifest.ID{11}, descriptorID, view); err != nil {
		return inputFingerprint{}, err
	}
	var digest [32]byte
	copy(digest[:], w.hash.Sum(nil))
	return inputFingerprint{w.length, digest}, nil
}

type fixedAuthorBytes struct {
	owned   []byte
	used    int
	refused error
}

// Write refuses overflow instead of allowing the fixture buffer to grow.
func (w *fixedAuthorBytes) Write(body []byte) (int, error) {
	if w.refused != nil {
		return 0, w.refused
	}
	if len(body) > len(w.owned)-w.used {
		w.refused = io.ErrShortWrite
		return 0, w.refused
	}
	copy(w.owned[w.used:], body)
	w.used += len(body)
	return len(body), nil
}

type authorExchange struct {
	mu       sync.Mutex
	finished bool
}

type authorInput struct {
	exchange *authorExchange
	reader   *bytes.Reader
}

// Read refuses use after the synchronous exchange has finished.
func (r *authorInput) Read(body []byte) (int, error) {
	r.exchange.mu.Lock()
	defer r.exchange.mu.Unlock()
	if r.exchange.finished {
		return 0, io.ErrClosedPipe
	}
	return r.reader.Read(body)
}

type authorWriter struct {
	exchange *authorExchange
	bytes    fixedAuthorBytes
	peer     *authorWriter
	closes   int
	status   bool
	badOrder bool
}

// Write records stream-order violations and refuses writes after close/return.
func (w *authorWriter) Write(body []byte) (int, error) {
	w.exchange.mu.Lock()
	defer w.exchange.mu.Unlock()
	if w.exchange.finished {
		return 0, io.ErrClosedPipe
	}
	if w.closes != 0 {
		w.bytes.refused = io.ErrClosedPipe
		return 0, w.bytes.refused
	}
	if len(body) != 0 && (w.status && w.peer.bytes.used != 0 || !w.status && w.peer.closes != 1) {
		w.badOrder = true
	}
	return w.bytes.Write(body)
}

// Close records exactly-once closure and the status-before-artifact order.
func (w *authorWriter) Close() error {
	w.exchange.mu.Lock()
	defer w.exchange.mu.Unlock()
	if w.exchange.finished {
		return io.ErrClosedPipe
	}
	w.closes++
	if w.closes != 1 {
		w.bytes.refused = io.ErrClosedPipe
		return w.bytes.refused
	}
	if w.status && w.peer.closes != 0 || !w.status && w.peer.closes != 1 {
		w.badOrder = true
	}
	return nil
}

func allZeroArtifact(body []byte) bool {
	for _, b := range body {
		if b != 0 {
			return false
		}
	}
	return true
}

// SettingsFixture borrows a valid request and independently expected canonical
// settings, or an exact supported failure with nil ExpectedSettings. All bytes
// are frozen test data for the call; the helper does not own caller storage.
type SettingsFixture struct {
	Request          manifest.SettingsRequest
	ExpectedSettings []byte
	ExpectedFailure  manifest.Failure
}

// CheckSettingsImplementation exercises the actual public settings callback and
// checks its raw result before serving normalization, exact request binding,
// unchanged fixture bytes and observable disposal. It interprets no settings.
// The serving function and callbacks must do finite synchronous work and join
// all users. As with CheckImplementation, observable checks cannot prevent
// externally captured fixture mutation or prove erasure of hidden backing.
func CheckSettingsImplementation(ctx context.Context, serve Serve, implementation native.Implementation, fixture SettingsFixture) error {
	fail := func(name string) error {
		return fmt.Errorf("manifest settings author check: %s: %w", name, protocol.ErrWire)
	}
	if nilContext(ctx) || serve == nil {
		return fail("fixture.context: missing context or serving function")
	}
	if implementation.ValidateFormatSettings == nil || implementation.Render == nil || implementation.Identity().ProtocolID != protocol.ProtocolID() || implementation.Identity().DescriptorID.IsZero() {
		return fail("fixture.implementation: invalid callbacks or identity")
	}
	if manifest.ValidateSettingsRequest(fixture.Request) != "" {
		return fail("fixture.settings_request: invalid structure")
	}
	if !fixture.ExpectedFailure.Valid() {
		return fail("fixture.expected_failure: unsupported failure")
	}
	if fixture.ExpectedFailure == "" {
		if manifest.ValidateSettings(fixture.ExpectedSettings) != "" {
			return fail("fixture.expected_settings: invalid encoding")
		}
	} else if fixture.ExpectedSettings != nil {
		return fail("fixture.expected_settings: conflicting failure expectation")
	}
	if err := callerContextError(ctx); err != nil {
		return err
	}
	auditContext := context.WithoutCancel(ctx)
	request := protocol.Request{Operation: protocol.OperationValidateSettings, Correlation: manifest.ID{12}, DescriptorID: implementation.Identity().DescriptorID, Settings: fixture.Request}
	digest, err := protocol.SettingsRequestDigest(ctx, request)
	if err != nil {
		if cause := callerContextError(ctx); cause != nil {
			return cause
		}
		return fail("fixture.request: encoding refused")
	}
	original := sha256.Sum256(fixture.Request.Settings)
	expected := sha256.Sum256(fixture.ExpectedSettings)
	wire := fixedAuthorBytes{owned: make([]byte, protocol.MaximumSettingsRequestBytes)}
	defer clear(wire.owned)
	if err := protocol.WriteRequest(ctx, &wire, request); err != nil {
		if wire.refused == nil {
			if cause := callerContextError(ctx); cause != nil {
				return cause
			}
		}
		return fail("fixture.request: encoding refused")
	}
	if wire.refused != nil {
		return fail("fixture.request: encoding mismatch")
	}
	exchange := new(authorExchange)
	input := &authorInput{exchange: exchange, reader: bytes.NewReader(wire.owned[:wire.used])}
	artifact := authorWriter{exchange: exchange, bytes: fixedAuthorBytes{owned: make([]byte, protocol.MaximumSettingsResponseBytes+1)}}
	status := authorWriter{exchange: exchange, bytes: fixedAuthorBytes{owned: make([]byte, protocol.StatusBytes+1)}, status: true}
	artifact.peer, status.peer = &status, &artifact
	defer clear(artifact.bytes.owned)
	defer clear(status.bytes.owned)
	calls, valid := 0, true
	completed := false
	var returned, borrowed []byte
	wrapped := implementation
	wrapped.ValidateFormatSettings = func(callbackContext context.Context, received manifest.SettingsRequest) manifest.SettingsResult {
		exchange.mu.Lock()
		if exchange.finished {
			exchange.mu.Unlock()
			return manifest.SettingsResult{Failure: manifest.InvalidInput}
		}
		calls++
		if calls != 1 {
			exchange.mu.Unlock()
			return manifest.SettingsResult{Failure: manifest.InvalidInput}
		}
		borrowed = received.Settings
		valid = valid && received.FormatContractID == fixture.Request.FormatContractID && received.ConfigContractID == fixture.Request.ConfigContractID && received.Canonical == fixture.Request.Canonical && bytes.Equal(received.Settings, fixture.Request.Settings)
		exchange.mu.Unlock()
		result := implementation.ValidateFormatSettings(callbackContext, received)
		exchange.mu.Lock()
		defer exchange.mu.Unlock()
		if exchange.finished {
			return result
		}
		returned = result.Settings
		valid = valid && manifest.ValidateSettingsResult(result) == "" && result.Failure == fixture.ExpectedFailure && bytes.Equal(result.Settings, fixture.ExpectedSettings)
		completed = true
		return result
	}
	code := serve(ctx, input, &artifact, &status, wrapped)
	exchange.mu.Lock()
	exchange.finished = true
	joined := completed
	exchange.mu.Unlock()
	if calls > 0 && !joined {
		return fail("callback.completion: count or join invalid")
	}
	if sha256.Sum256(fixture.Request.Settings) != original || sha256.Sum256(fixture.ExpectedSettings) != expected {
		return fail("callback.fixture: caller storage changed")
	}
	if calls > 1 || !valid {
		return fail("callback.result: wrong raw outcome or changed input")
	}
	if artifact.bytes.refused != nil || status.bytes.refused != nil || artifact.closes != 1 || status.closes != 1 || artifact.badOrder || status.badOrder {
		return fail("serving.completion: status or stream ownership invalid")
	}
	if !allZeroArtifact(returned[:cap(returned)]) || !allZeroArtifact(borrowed[:cap(borrowed)]) {
		return fail("disposal.borrowed_or_returned: backing not released")
	}
	if calls == 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return fail("callback.completion: count or join invalid")
	}
	if code != 0 {
		if err := callerContextError(ctx); err != nil {
			return err
		}
		return fail("serving.completion: status or stream ownership invalid")
	}
	if protocol.RequireEOF(input.reader) != nil {
		return fail("serving.request: trailing bytes")
	}
	wireStatus, err := protocol.ReadStatus(bytes.NewReader(status.bytes.owned[:status.bytes.used]))
	if err != nil || wireStatus.Correlation != request.Correlation {
		return fail("serialized.status: correlation or outcome mismatch")
	}
	if cause := callerContextError(ctx); cause != nil {
		expected := manifest.Cancelled
		if errors.Is(cause, context.DeadlineExceeded) {
			expected = manifest.Expired
		}
		if wireStatus.Failure == expected && wireStatus.Length == 0 {
			if artifact.bytes.used != 0 {
				return fail("serialized.failure: unexpected bytes")
			}
			return cause
		}
	}
	if err != nil || wireStatus.Correlation != request.Correlation || wireStatus.Failure != fixture.ExpectedFailure {
		return fail("serialized.status: correlation or outcome mismatch")
	}
	if fixture.ExpectedFailure != "" {
		if wireStatus.Length != 0 || artifact.bytes.used != 0 {
			return fail("serialized.failure: unexpected bytes")
		}
		return callerContextError(ctx)
	}
	if wireStatus.Length != uint64(artifact.bytes.used) {
		return fail("serialized.length: length mismatch")
	}
	var canonical []byte
	if fixture.Request.Canonical {
		canonical = fixture.Request.Settings
	}
	response, failure, err := protocol.ReadSettingsResponse(auditContext, bytes.NewReader(artifact.bytes.owned[:artifact.bytes.used]), digest, canonical)
	defer clear(response.Settings[:cap(response.Settings)])
	if err != nil || failure != "" || !bytes.Equal(response.Settings, fixture.ExpectedSettings) {
		return fail("serialized.settings: exact bytes or request binding mismatch")
	}
	return callerContextError(ctx)
}

func callerContextError(ctx context.Context) error {
	cause := ctx.Err()
	if cause == nil {
		return nil
	}
	reason := "cancelled"
	sentinel := error(context.Canceled)
	if errors.Is(cause, context.DeadlineExceeded) {
		reason = "deadline exceeded"
		sentinel = context.DeadlineExceeded
	}
	return fmt.Errorf("manifest author check: caller.context: %s: %w: %w", reason, protocol.ErrWire, sentinel)
}
