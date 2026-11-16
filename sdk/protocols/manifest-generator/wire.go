// Package manifestprotocol streams bounded public settings and consumption projections.
// The wire grants no authenticated Reader authority.
package manifestprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"unicode/utf8"

	manifest "enkv.sh/sdk/manifest-generator"
)

const (
	// Version is the manifest wire version.
	Version = 2
	// Mode is the native manifest serving-mode string.
	Mode  = "manifest-wire-v2"
	magic = "ENKV/MANIFEST/v2\x00"
	// OperationValidateSettings selects settings normalization or exact canonical validation.
	OperationValidateSettings uint8 = 1
	// OperationRender selects rendering of one complete public projection.
	OperationRender uint8 = 2
	// StatusBytes is the exact fixed status length in bytes.
	StatusBytes = 58
	// MaximumSettingsRequestBytes bounds the complete settings request encoding in bytes.
	MaximumSettingsRequestBytes = 16991
	// MaximumSettingsResponseBytes bounds the complete canonical-settings response encoding in bytes.
	MaximumSettingsResponseBytes = 16420
	// MaximumRequestBytes bounds the complete render request encoding in bytes.
	MaximumRequestBytes = 46440177
)

// ErrWire identifies invalid outgoing structure or a refused wire exchange.
// Incoming request parsing also reports typed manifest failures and raw I/O errors;
// inspect all return values rather than relying only on errors.Is(err, ErrWire).
var ErrWire = errors.New("manifest exchange invalid")

// ProtocolID returns the exact identity of manifest wire version 2.
func ProtocolID() manifest.ID {
	return manifest.ID(sha256.Sum256([]byte("ENKV/MANIFEST-PROTOCOL/v2\x00")))
}

// Request contains nonzero correlation and pre-build descriptor identities.
// OperationValidateSettings uses Settings and no Projection. OperationRender uses
// Projection with zero Settings. Constructed requests borrow their inputs;
// ReadRequest returns owned backing that Dispose must release after all users join.
type Request struct {
	Operation                 uint8
	Correlation, DescriptorID manifest.ID
	Settings                  manifest.SettingsRequest
	Projection                *manifest.Projection
}

// SettingsResponse binds canonical settings to the digest of the exact request.
// ReadSettingsResponse transfers owned Settings bytes; retain through all users
// and clear the full owned allocation after they finish.
type SettingsResponse struct {
	RequestDigest manifest.ID
	Settings      []byte
}

// Status declares a nonzero correlation, closed failure and artifact byte length.
// Success uses empty Failure and a positive length up to manifest.MaxArtifactBytes;
// failure uses zero Length. The receiver must check expected correlation and the
// operation-specific length bound. This is transport status, not format validation.
type Status struct {
	Correlation manifest.ID
	Failure     manifest.Failure
	Length      uint64
}

var failures = [...]manifest.Failure{"", manifest.InvalidInput, manifest.InvalidUTF8, manifest.LimitExceeded, manifest.Cancelled, manifest.Expired, manifest.InvalidResult}

func (s Status) valid() bool {
	return !s.Correlation.IsZero() && s.Failure.Valid() && (s.Failure == "" && s.Length > 0 && s.Length <= manifest.MaxArtifactBytes || s.Failure != "" && s.Length == 0)
}

// WriteStatus writes the exact fixed-size status and does not close w.
// The sender must close its status stream before writing artifact bytes. A write
// error can leave partial bytes; the transport owner must close and join it.
func WriteStatus(w io.Writer, s Status) error {
	if w == nil || !s.valid() {
		return ErrWire
	}
	var b [StatusBytes]byte
	copy(b[:], magic)
	copy(b[len(magic):], s.Correlation[:])
	for i, f := range failures {
		if f == s.Failure {
			b[len(magic)+32] = byte(i)
			break
		}
	}
	binary.BigEndian.PutUint64(b[len(magic)+33:], s.Length)
	return write(w, b[:])
}

// ReadStatus checks the complete status, including exact EOF. It can block until
// the stream closes; the caller owns cancellation and deadlines. The caller must
// also compare expected correlation and enforce the selected operation's length bound.
func ReadStatus(r io.Reader) (Status, error) {
	var b [StatusBytes]byte
	if r == nil {
		return Status{}, ErrWire
	}
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Status{}, err
	}
	if string(b[:len(magic)]) != magic || int(b[len(magic)+32]) >= len(failures) {
		return Status{}, ErrWire
	}
	s := Status{Failure: failures[b[len(magic)+32]], Length: binary.BigEndian.Uint64(b[len(magic)+33:])}
	copy(s.Correlation[:], b[len(magic):])
	if !s.valid() {
		return Status{}, ErrWire
	}
	if err := RequireEOF(r); err != nil {
		return Status{}, err
	}
	return s, nil
}

// RequireEOF accepts only immediate exact EOF. It can block and does not close r;
// the transport owner supplies finite lifetime and cancellation.
func RequireEOF(r io.Reader) error {
	if r == nil {
		return ErrWire
	}
	var b [1]byte
	n, err := io.ReadFull(r, b[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrWire
}
func write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
func contextFailure(ctx context.Context) manifest.Failure {
	if ctx == nil {
		return manifest.InvalidInput
	}
	value := reflect.ValueOf(ctx)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return manifest.InvalidInput
	}
	return manifest.FailureFromContextError(ctx.Err())
}

type writer struct {
	ctx          context.Context
	w            io.Writer
	err          error
	total, limit int
	window       [manifest.PlainWindowBytes]byte
}

func (w *writer) bytes(b []byte) {
	if w.err != nil {
		return
	}
	if contextFailure(w.ctx) != "" || len(b) > w.limit-w.total {
		w.err = ErrWire
		return
	}
	w.err = write(w.w, b)
	w.total += len(b)
}
func (w *writer) u8(v uint8) { w.bytes([]byte{v}) }
func (w *writer) u32(v int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	w.bytes(b[:])
}
func (w *writer) id(v manifest.ID) { w.bytes(v[:]) }
func (w *writer) blob(v []byte) {
	w.u32(len(v))
	for len(v) > 0 && w.err == nil {
		n := min(len(v), len(w.window))
		w.bytes(v[:n])
		v = v[n:]
	}
}
func (w *writer) text(v string) {
	w.u32(len(v))
	for len(v) > 0 && w.err == nil {
		n := min(len(v), len(w.window))
		copy(w.window[:n], v[:n])
		w.bytes(w.window[:n])
		v = v[n:]
	}
}
func (w *writer) copyBlob(length int, copyAt func(int, []byte) (int, manifest.Failure)) {
	w.u32(length)
	for at := 0; at < length && w.err == nil; {
		n := min(length-at, len(w.window))
		copied, f := copyAt(at, w.window[:n])
		if f != "" || copied != n {
			w.err = ErrWire
			return
		}
		w.bytes(w.window[:n])
		at += n
	}
}
func settingsZero(s manifest.SettingsRequest) bool {
	return s.FormatContractID == "" && s.ConfigContractID == "" && !s.Canonical && s.Settings == nil
}

// WriteRequest borrows every input through return and retains no encoded copy.
// It checks request structure and streams one operation without closing dst.
// Supply a live nonnil context. Checks between writes do not interrupt a blocked
// writer; the caller owns pipe cancellation. Failure can leave partial output.
func WriteRequest(ctx context.Context, dst io.Writer, request Request) error {
	if dst == nil || contextFailure(ctx) != "" || request.Correlation.IsZero() || request.DescriptorID.IsZero() {
		return ErrWire
	}
	switch request.Operation {
	case OperationValidateSettings:
		if request.Projection != nil || manifest.ValidateSettingsRequest(request.Settings) != "" {
			return ErrWire
		}
	case OperationRender:
		if !settingsZero(request.Settings) {
			return ErrWire
		}
		return WriteRenderRequest(ctx, dst, request.Correlation, request.DescriptorID, manifest.Borrow(request.Projection))
	default:
		return ErrWire
	}
	w := writer{ctx: ctx, w: dst, limit: MaximumSettingsRequestBytes}
	defer clear(w.window[:])
	w.bytes([]byte(magic))
	w.u8(request.Operation)
	w.id(request.Correlation)
	w.id(request.DescriptorID)
	s := request.Settings
	w.text(s.FormatContractID)
	w.text(s.ConfigContractID)
	if s.Canonical {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.blob(s.Settings)
	return w.err
}

// WriteRenderRequest validates and borrows a read-only view through return,
// without acquiring mutable backing. It streams in bounded windows and never
// closes dst. Context checks do not interrupt blocked I/O; the transport owner
// must arrange cancellation, closure and joins. Failure can leave partial bytes.
func WriteRenderRequest(ctx context.Context, dst io.Writer, correlation, descriptorID manifest.ID, v manifest.View) error {
	if dst == nil || correlation.IsZero() || descriptorID.IsZero() || v.Validate(ctx) != "" {
		return ErrWire
	}
	w := writer{ctx: ctx, w: dst, limit: MaximumRequestBytes}
	defer clear(w.window[:])
	w.bytes([]byte(magic))
	w.u8(OperationRender)
	w.id(correlation)
	w.id(descriptorID)
	h := v.Header()

	w.text(h.Schema)
	w.text(h.FormatContractID)
	w.text(h.ConfigContractID)
	w.copyBlob(v.SettingsLength(), v.CopySettings)
	if h.Selection.TargetMode == manifest.CurrentAuthority {
		w.u8(1)
	} else {
		w.u8(2)
	}
	if h.Selection.EntryMode == manifest.AllAuthorized {
		w.u8(1)
	} else {
		w.u8(2)
	}
	if h.HasServiceFilter {
		w.u8(1)
		w.text(h.ServiceFilter)
	} else {
		w.u8(0)
	}
	w.id(h.Observation.DomainID)
	w.id(h.Observation.HEADRevisionID)
	w.id(h.Observation.SnapshotID)
	w.id(h.TargetRecipientID)
	w.u32(v.EntryCount())
	for i := 0; i < v.EntryCount() && w.err == nil; i++ {
		e, _ := v.Entry(i)
		m := e.Metadata()
		w.text(m.Name)
		w.id(m.EntryIncarnationID)
		w.u8(m.Kind)
		if m.Kind == manifest.Plain {
			w.copyBlob(e.PlainLength(), e.CopyPlain)
			continue
		}
		w.u32(e.DestinationCount())
		for j := 0; j < e.DestinationCount() && w.err == nil; j++ {
			d, _ := e.Destination(j)
			m := d.Metadata()
			for _, s := range []string{m.DestinationID, m.ServiceContractID, m.ConsumerLocator, m.TargetContractID, m.CanonicalTarget} {
				w.text(s)
			}
			w.copyBlob(d.TargetDataLength(), d.CopyTargetData)
			w.text(m.PolicyContractID)
			w.copyBlob(d.PolicyLength(), d.CopyPolicy)
			w.id(m.BindingIncarnationID)
			w.id(m.EntryIncarnationID)
			w.id(m.PolicyDigest)
			w.u8(m.PayloadEncoding)
			if m.PolicyPresent {
				w.u8(1)
			} else {
				w.u8(0)
			}
		}
	}
	w.u32(v.ExcludedCount())
	for i := 0; i < v.ExcludedCount() && w.err == nil; i++ {
		e, _ := v.Excluded(i)
		w.text(e.Name)
		w.id(e.EntryIncarnationID)
		if e.Reason == manifest.NoOutput {
			w.u8(1)
		} else {
			w.u8(2)
		}
	}
	return w.err
}

type reader struct {
	ctx                                context.Context
	r                                  io.Reader
	failure                            manifest.Failure
	err                                error
	total, limit, raw, output, targets int
	window                             [manifest.PlainWindowBytes]byte
}

func (r *reader) refuse(f manifest.Failure) {
	if r.failure == "" {
		r.failure = f
	}
}
func (r *reader) bytes(b []byte) {
	if r.failure != "" || r.err != nil {
		return
	}
	if f := contextFailure(r.ctx); f != "" {
		r.refuse(f)
		return
	}
	if len(b) > r.limit-r.total {
		r.refuse(manifest.LimitExceeded)
		return
	}
	_, r.err = io.ReadFull(r.r, b)
	r.total += len(b)
}
func (r *reader) u8() uint8 { var b [1]byte; r.bytes(b[:]); return b[0] }
func (r *reader) count(maximum int) int {
	var b [4]byte
	r.bytes(b[:])
	n := binary.BigEndian.Uint32(b[:])
	if maximum < 0 || uint64(n) > uint64(maximum) {
		r.refuse(manifest.LimitExceeded)
		return 0
	}
	return int(n)
}
func (r *reader) id() (id manifest.ID) { r.bytes(id[:]); return }
func (r *reader) blob(maximum int) []byte {
	n := r.count(maximum)
	if r.failure != "" || r.err != nil {
		return nil
	}
	b := make([]byte, n)
	for at := 0; at < n && r.failure == "" && r.err == nil; {
		end := min(at+len(r.window), n)
		r.bytes(b[at:end])
		at = end
	}
	return b
}
func (r *reader) text(maximum int) string {
	n := r.count(maximum)
	if r.failure != "" || r.err != nil {
		return ""
	}
	if n > len(r.window) {
		r.refuse(manifest.LimitExceeded)
		return ""
	}
	r.bytes(r.window[:n])
	if r.err != nil || r.failure != "" {
		return ""
	}
	if !utf8.Valid(r.window[:n]) {
		r.refuse(manifest.InvalidUTF8)
		return ""
	}
	return string(r.window[:n])
}
func (r *reader) outputText(maximum int) string {
	s := r.text(min(maximum, manifest.MaxOutputBytes-r.output))
	r.output += len(s)
	return s
}
func (r *reader) outputBlob(maximum int) []byte {
	b := r.blob(min(maximum, manifest.MaxOutputBytes-r.output))
	r.output += len(b)
	return b
}

// ReadRequest returns one owned request after exact EOF. Check both failure and
// err: validation/cancellation uses a typed manifest failure, while transport can
// return an I/O error. On failure it clears partial backing and retains decoded
// operation/correlation/descriptor header facts for a closed failure reply.
// On success, call Dispose only after every borrower joins. Context checks between
// reads do not interrupt blocked I/O; callers own transport cancellation.
func ReadRequest(ctx context.Context, src io.Reader) (result Request, failure manifest.Failure, err error) {
	if src == nil {
		return Request{}, manifest.InvalidInput, nil
	}
	if f := contextFailure(ctx); f != "" {
		return Request{}, f, nil
	}
	r := reader{ctx: ctx, r: src, limit: MaximumRequestBytes}
	request := Request{}
	defer func() {
		clear(r.window[:])
		if failure != "" || err != nil {
			header := Request{Operation: request.Operation, Correlation: request.Correlation, DescriptorID: request.DescriptorID}
			Dispose(&request)
			result = header
		}
	}()
	var prefix [len(magic)]byte
	r.bytes(prefix[:])
	if string(prefix[:]) != magic && r.err == nil {
		r.refuse(manifest.InvalidInput)
	}
	request.Operation = r.u8()
	request.Correlation = r.id()
	request.DescriptorID = r.id()
	if request.Correlation.IsZero() || request.DescriptorID.IsZero() {
		r.refuse(manifest.InvalidInput)
	}
	switch request.Operation {
	case OperationValidateSettings:
		r.limit = MaximumSettingsRequestBytes
		s := &request.Settings
		s.FormatContractID = r.text(manifest.MaxContractBytes)
		s.ConfigContractID = r.text(manifest.MaxContractBytes)
		tag := r.u8()
		if tag > 1 {
			r.refuse(manifest.InvalidInput)
		}
		s.Canonical = tag == 1
		s.Settings = r.blob(manifest.MaxSettingsBytes)
		if r.failure == "" && r.err == nil {
			r.refuse(manifest.ValidateSettingsRequest(*s))
		}
	case OperationRender:
		p := &manifest.Projection{}
		request.Projection = p
		p.Schema = r.text(manifest.MaxContractBytes)
		p.FormatContractID = r.text(manifest.MaxContractBytes)
		p.ConfigContractID = r.text(manifest.MaxContractBytes)
		p.Settings = r.blob(manifest.MaxSettingsBytes)
		target, entries := r.u8(), r.u8()
		switch target {
		case 1:
			p.Selection.TargetMode = manifest.CurrentAuthority
		case 2:
			p.Selection.TargetMode = manifest.ExactRecipient
		default:
			r.refuse(manifest.InvalidInput)
		}
		switch entries {
		case 1:
			p.Selection.EntryMode = manifest.AllAuthorized
		case 2:
			p.Selection.EntryMode = manifest.ExactNames
		default:
			r.refuse(manifest.InvalidInput)
		}
		filter := r.u8()
		if filter > 1 {
			r.refuse(manifest.InvalidInput)
		}
		if filter == 1 {
			s := r.text(manifest.MaxContractBytes)
			p.ServiceFilter = &s
		}
		p.Observation = manifest.Observation{DomainID: r.id(), HEADRevisionID: r.id(), SnapshotID: r.id()}
		p.TargetRecipientID = r.id()
		count := r.count(manifest.MaxEntries)
		if r.failure == "" && r.err == nil {
			p.Entries = make([]manifest.Entry, count)
		}
		for i := range p.Entries {
			e := &p.Entries[i]
			e.Name = r.text(manifest.MaxNameBytes)
			e.EntryIncarnationID = r.id()
			e.Kind = r.u8()
			switch e.Kind {
			case manifest.Plain:
				e.PlainValue = r.blob(min(manifest.MaxRawValue, manifest.MaxRawSet-r.raw))
				r.raw += len(e.PlainValue)
			case manifest.Secret:
				n := r.count(min(manifest.MaxEntryDestinations, manifest.MaxDestinations-r.targets))
				r.targets += n
				if r.failure == "" && r.err == nil {
					e.Destinations = make([]manifest.Destination, n)
				}
				for j := range e.Destinations {
					d := &e.Destinations[j]
					d.DestinationID = r.outputText(256)
					d.ServiceContractID = r.outputText(256)
					d.ConsumerLocator = r.outputText(manifest.MaxLocatorBytes)
					d.TargetContractID = r.outputText(256)
					d.CanonicalTarget = r.outputText(manifest.MaxLocatorBytes)
					d.TargetData = r.outputBlob(manifest.MaxTargetDataBytes)
					d.PolicyContractID = r.outputText(256)
					d.PolicyData = r.outputBlob(manifest.MaxPolicyBytes)
					d.BindingIncarnationID = r.id()
					d.EntryIncarnationID = r.id()
					d.PolicyDigest = r.id()
					d.PayloadEncoding = r.u8()
					tag := r.u8()
					if tag > 1 {
						r.refuse(manifest.InvalidInput)
					}
					d.PolicyPresent = tag == 1
					if r.failure != "" || r.err != nil {
						break
					}
				}
			default:
				r.refuse(manifest.InvalidInput)
			}
			if r.failure != "" || r.err != nil {
				break
			}
		}
		excluded := r.count(manifest.MaxEntries - count)
		if r.failure == "" && r.err == nil {
			p.ExcludedEntries = make([]manifest.ExcludedEntry, excluded)
		}
		for i := range p.ExcludedEntries {
			e := &p.ExcludedEntries[i]
			e.Name = r.text(manifest.MaxNameBytes)
			e.EntryIncarnationID = r.id()
			switch r.u8() {
			case 1:
				e.Reason = manifest.NoOutput
			case 2:
				e.Reason = manifest.NoMatchingService
			default:
				r.refuse(manifest.InvalidInput)
			}
			if r.failure != "" || r.err != nil {
				break
			}
		}
		if r.failure == "" && r.err == nil {
			derivePartition(p)
			r.refuse(manifest.Validate(ctx, p))
		}
	default:
		r.refuse(manifest.InvalidInput)
	}
	if r.failure != "" || r.err != nil {
		return request, r.failure, r.err
	}
	if eof := RequireEOF(src); eof != nil {
		return request, manifest.InvalidInput, eof
	}
	return request, "", nil
}

// derivePartition reconstructs the complete identity partition omitted from the
// wire. Validation below rejects unordered or conflicting input; deriving this
// header does not turn the received projection into authenticated Reader evidence.
func derivePartition(p *manifest.Projection) {
	p.ResolvedEntries = make([]manifest.EntryIdentity, len(p.Entries)+len(p.ExcludedEntries))
	a, b := 0, 0
	for i := range p.ResolvedEntries {
		if a < len(p.Entries) && (b == len(p.ExcludedEntries) || p.Entries[a].Name < p.ExcludedEntries[b].Name) {
			e := p.Entries[a]
			p.ResolvedEntries[i] = manifest.EntryIdentity{Name: e.Name, EntryIncarnationID: e.EntryIncarnationID}
			a++
		} else {
			e := p.ExcludedEntries[b]
			p.ResolvedEntries[i] = manifest.EntryIdentity{Name: e.Name, EntryIncarnationID: e.EntryIncarnationID}
			b++
		}
	}
}

// SettingsRequestDigest validates a settings request by streaming its exact wire
// encoding into the settings domain hash. It borrows input through return and
// requires OperationValidateSettings and a live nonnil context.
func SettingsRequestDigest(ctx context.Context, r Request) (manifest.ID, error) {
	if r.Operation != OperationValidateSettings {
		return manifest.ID{}, ErrWire
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ENKV/MANIFEST-SETTINGS/v1\x00"))
	if err := WriteRequest(ctx, h, r); err != nil {
		return manifest.ID{}, err
	}
	var id manifest.ID
	copy(id[:], h.Sum(nil))
	return id, nil
}

// WriteSettingsResponse validates a nonzero request digest and canonical settings
// shape, then streams them without retaining or closing w. It borrows settings
// through return; a failure can leave partial bytes. A live nonnil context is required.
func WriteSettingsResponse(ctx context.Context, w io.Writer, response SettingsResponse) error {
	if w == nil || response.RequestDigest.IsZero() || manifest.ValidateSettings(response.Settings) != "" {
		return ErrWire
	}
	out := writer{ctx: ctx, w: w, limit: MaximumSettingsResponseBytes}
	defer clear(out.window[:])
	out.id(response.RequestDigest)
	out.blob(response.Settings)
	return out.err
}

// ReadSettingsResponse transfers owned settings only after request binding,
// settings validation and exact EOF. A nonnil canonicalInput must match byte for
// byte; it is borrowed through return. Check both typed failure and I/O err. On
// failure, partial settings backing is cleared. Context checks cannot interrupt
// blocked reads; the caller owns cancellation and transport closure.
func ReadSettingsResponse(ctx context.Context, src io.Reader, expected manifest.ID, canonicalInput []byte) (result SettingsResponse, failure manifest.Failure, err error) {
	if src == nil || expected.IsZero() {
		return SettingsResponse{}, manifest.InvalidInput, nil
	}
	if f := contextFailure(ctx); f != "" {
		return SettingsResponse{}, f, nil
	}
	r := reader{ctx: ctx, r: src, limit: MaximumSettingsResponseBytes}
	response := SettingsResponse{RequestDigest: r.id()}
	response.Settings = r.blob(manifest.MaxSettingsBytes)
	defer func() {
		clear(r.window[:])
		if failure != "" || err != nil {
			clear(response.Settings[:cap(response.Settings)])
		}
	}()
	if r.failure != "" || r.err != nil {
		return SettingsResponse{}, r.failure, r.err
	}
	if response.RequestDigest != expected || manifest.ValidateSettings(response.Settings) != "" || canonicalInput != nil && !bytes.Equal(canonicalInput, response.Settings) {
		return SettingsResponse{}, manifest.InvalidResult, nil
	}
	if err := RequireEOF(src); err != nil {
		return SettingsResponse{}, manifest.InvalidResult, err
	}
	return response, "", nil
}

// Dispose clears the full capacity of request settings, calls DisposeProjection,
// and resets r after every borrower has joined. Nil is harmless. Use only with
// owned input such as ReadRequest results; constructed requests can alias
// another owner. DisposeProjection describes the clearing limits. Concurrent
// use is unsafe.
func Dispose(r *Request) {
	if r == nil {
		return
	}
	clear(r.Settings.Settings[:cap(r.Settings.Settings)])
	DisposeProjection(r.Projection)
	*r = Request{}
}

// DisposeProjection clears settings, byte fields of active entries and
// destinations, and their row vectors through capacity, then resets p. It does
// not erase immutable strings or nested allocations reachable only from spare
// row capacity. ReadRequest constructs exact-length row vectors.
//
// Call only after every borrower has joined and only with backing the caller
// owns. Aliases observe clearing; concurrent use is unsafe. Nil is harmless.
func DisposeProjection(p *manifest.Projection) {
	if p == nil {
		return
	}
	clear(p.Settings[:cap(p.Settings)])
	for i := range p.Entries {
		e := &p.Entries[i]
		clear(e.PlainValue[:cap(e.PlainValue)])
		for j := range e.Destinations {
			d := &e.Destinations[j]
			clear(d.TargetData[:cap(d.TargetData)])
			clear(d.PolicyData[:cap(d.PolicyData)])
		}
		clear(e.Destinations[:cap(e.Destinations)])
	}
	clear(p.Entries[:cap(p.Entries)])
	clear(p.ExcludedEntries[:cap(p.ExcludedEntries)])
	clear(p.ResolvedEntries[:cap(p.ResolvedEntries)])
	*p = manifest.Projection{}
}
