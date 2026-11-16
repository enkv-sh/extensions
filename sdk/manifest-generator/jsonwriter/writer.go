// Package jsonwriter supplies bounded JSON mechanics for manifest layouts.
// It defines no profile, layout or correspondence verifier. A layout supplies
// every field, delimiter and semantic choice. Use Encode to create a Writer;
// its zero value is not ready for use. Layouts run twice and must make the same
// ordered writes from unchanged input. They must not retain the Writer or views.
package jsonwriter

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"

	manifest "enkv.sh/sdk/manifest-generator"
)

// Writer owns one count/write exchange and bounded encoding scratch.
// Encode is its lifetime owner; layouts must not retain its pointer.
type Writer struct {
	ctx          context.Context
	body         []byte
	at, limit    uint64
	failed       manifest.Failure
	raw          uint64
	destinations int
	plainWindow  [manifest.PlainWindowBytes]byte
	quoted       [manifest.QuotedTokenBytes]byte
}

func contextFailure(ctx context.Context) manifest.Failure {
	if ctx == nil {
		return manifest.InvalidInput
	}
	return manifest.FailureFromContextError(ctx.Err())
}

// Refuse preserves the first nonempty encoding failure. Supply a supported
// manifest.Failure; the empty value has no effect. Later writes stop on failure.
func (w *Writer) Refuse(f manifest.Failure) {
	if w.failed == "" {
		w.failed = f
	}
}
func (w *Writer) reserve(n uint64) []byte {
	if w.failed != "" {
		return nil
	}
	if f := contextFailure(w.ctx); f != "" {
		w.failed = f
		return nil
	}
	if w.at > w.limit || n > w.limit-w.at {
		w.Refuse(manifest.LimitExceeded)
		return nil
	}
	start := w.at
	w.at += n
	if w.body == nil {
		return nil
	}
	if w.at > uint64(len(w.body)) {
		w.Refuse(manifest.InvalidInput)
		return nil
	}
	return w.body[int(start):int(w.at)]
}

// Literal emits fixed syntax supplied by the layout. It does not validate
// JSON, quote s or check whether it belongs at the current position.
func (w *Writer) Literal(s string) {
	if b := w.reserve(uint64(len(s))); b != nil {
		copy(b, s)
	}
}

// Text emits one canonical JSON string with its field bound.
// The byte bound max must be between zero and manifest.MaxQuotedTextBytes.
// Invalid UTF-8 records InvalidUTF8; excess length records LimitExceeded. When
// empty is false, an empty string records InvalidInput.
func (w *Writer) Text(s string, max int, empty bool) {
	if w.failed != "" {
		return
	}
	if max < 0 || max > manifest.MaxQuotedTextBytes || len(s) > max {
		w.Refuse(manifest.LimitExceeded)
		return
	}
	if !utf8.ValidString(s) {
		w.Refuse(manifest.InvalidUTF8)
		return
	}
	if !empty && s == "" {
		w.Refuse(manifest.InvalidInput)
		return
	}
	b := w.quoted[:0]
	b = append(b, '"')
	const digits = "0123456789abcdef"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b = append(b, '\\', c)
		case '\b':
			b = append(b, `\b`...)
		case '\f':
			b = append(b, `\f`...)
		case '\n':
			b = append(b, `\n`...)
		case '\r':
			b = append(b, `\r`...)
		case '\t':
			b = append(b, `\t`...)
		case '<', '>', '&':
			b = append(b, '\\', 'u', '0', '0', digits[c>>4], digits[c&15])
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', digits[c>>4], digits[c&15])
			} else if c == 0xe2 && i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xa8 || s[i+2] == 0xa9) {
				b = append(b, '\\', 'u', '2', '0', '2', digits[s[i+2]&15])
				i += 2
			} else {
				b = append(b, c)
			}
		}
	}
	b = append(b, '"')
	if dst := w.reserve(uint64(len(b))); dst != nil {
		copy(dst, b)
	}
}

// ID emits a required nonzero identity as lowercase quoted hex.
func (w *Writer) ID(id manifest.ID) {
	if id.IsZero() {
		w.Refuse(manifest.InvalidInput)
		return
	}
	if b := w.reserve(66); b != nil {
		b[0] = '"'
		hex.Encode(b[1:65], id[:])
		b[65] = '"'
	}
}

// Plain emits a quoted standard padded Base64 value using bounded copies. It
// requires a Plain entry and charges its bytes against MaxRawSet for this pass.
// An empty plain value emits an empty string; a Secret or invalid view is refused.
func (w *Writer) Plain(e manifest.EntryView) {
	if w.failed != "" {
		return
	}
	if e.Metadata().Kind != manifest.Plain {
		w.Refuse(manifest.InvalidInput)
		return
	}
	length := e.PlainLength()
	if length > manifest.MaxRawValue || uint64(length) > uint64(manifest.MaxRawSet)-w.raw {
		w.Refuse(manifest.LimitExceeded)
		return
	}
	w.raw += uint64(length)
	w.Base64(length, manifest.MaxRawValue, e.CopyPlain)
}

// Base64 emits one quoted standard padded Base64 field through bounded copies.
// length and maximum must be nonnegative, length must not exceed maximum, and
// maximum must not exceed manifest.MaxOutputBytes. copyAt must synchronously fill
// each requested window without retaining it. A short copy or copy failure becomes
// InvalidInput. No copies occur during the count pass. A full window is divisible
// by three, so intermediate chunks have no padding.
func (w *Writer) Base64(length, maximum int, copyAt func(int, []byte) (int, manifest.Failure)) {
	if length < 0 || maximum < 0 || length > maximum || maximum > manifest.MaxOutputBytes {
		w.Refuse(manifest.LimitExceeded)
		return
	}
	if copyAt == nil {
		w.Refuse(manifest.InvalidInput)
		return
	}
	w.Literal(`"`)
	for offset := 0; offset < length; {
		n := min(length-offset, len(w.plainWindow))
		dst := w.reserve(uint64(base64.StdEncoding.EncodedLen(n)))
		if w.failed != "" {
			return
		}
		if dst != nil {
			copied, f := copyAt(offset, w.plainWindow[:n])
			if f != "" || copied != n {
				w.Refuse(manifest.InvalidInput)
				return
			}
			base64.StdEncoding.Encode(dst, w.plainWindow[:n])
			clear(w.plainWindow[:n])
		}
		offset += n
	}
	w.Literal(`"`)
}

func (w *Writer) complete(expected uint64) ([]byte, manifest.Failure) {
	if w.failed == "" {
		w.failed = contextFailure(w.ctx)
	}
	if w.failed == "" && w.at != expected {
		w.Refuse(manifest.InvalidInput)
	}
	if w.failed != "" {
		clear(w.body[:cap(w.body)])
		clear(w.plainWindow[:])
		clear(w.quoted[:])
		return nil, w.failed
	}
	return w.body, ""
}

// Encode calls layout twice: first to count, then to write one exact allocation.
// Layout and view are synchronous borrows and must remain unchanged throughout.
// The layout owns grammar and semantic checks; Encode does not call Validate
// automatically. It checks the common artifact ceiling, context and equal pass
// lengths, but equal lengths alone do not establish identical layout choices.
// Success transfers the complete allocation under manifest.Result rules; failure
// clears provisional artifact backing. Layouts must not retain the Writer or
// start work that outlives a call.
func Encode(ctx context.Context, view manifest.View, layout func(*Writer, manifest.View)) manifest.Result {
	limit := manifest.MaxArtifactBytes
	if layout == nil {
		return manifest.Result{Failure: manifest.InvalidInput}
	}
	w := Writer{ctx: ctx, limit: limit}
	defer func() {
		clear(w.plainWindow[:])
		clear(w.quoted[:])
		w.body = nil
		w.ctx = nil
		w.failed = manifest.InvalidInput
	}()
	layout(&w, view)
	if w.failed != "" {
		return manifest.Result{Failure: w.failed}
	}
	expected := w.at
	if expected == 0 {
		return manifest.Result{Failure: manifest.InvalidInput}
	}
	w.body = make([]byte, int(expected))
	w.at, w.limit, w.raw, w.destinations = 0, expected, 0, 0
	layout(&w, view)
	body, failure := w.complete(expected)
	return manifest.Result{Artifact: body, Failure: failure}
}

// Failure reports the first encoding failure.
func (w *Writer) Failure() manifest.Failure { return w.failed }

// Validate checks the original view at the layout-selected validation point.
func (w *Writer) Validate(view manifest.View) { w.Refuse(view.Validate(w.ctx)) }

// Destinations charges one entry's positive destination count against the per-entry
// and aggregate bounds for this pass. It returns false and records a failure for
// zero/negative or excess counts. Layouts that use this accounting call it once
// per secret entry in each pass. Validate already checks both bounds over the
// complete unchanged view; such a layout need not also charge those same rows.
func (w *Writer) Destinations(count int) bool {
	if count <= 0 {
		w.Refuse(manifest.InvalidInput)
		return false
	}
	if count > manifest.MaxEntryDestinations || count > manifest.MaxDestinations-w.destinations {
		w.Refuse(manifest.LimitExceeded)
		return false
	}
	w.destinations += count
	return true
}
