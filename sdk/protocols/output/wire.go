// Package output defines the bounded output family wire. It grants no
// operation permission, source trust or provider-effect proof. SDK serving and
// child lifetime are separate responsibilities.
//
// Message encoders validate structure and return new buffers. Message decoders
// borrow byte fields from their input unless stated otherwise; retain the input
// unchanged through every borrower and clear private bodies after use. Decoding
// does not perform plugin-owned semantic checks. ErrProtocol and ErrCapacity can
// be checked with errors.Is; transport operations can also return I/O errors.
package output

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// Version is the output frame version.
	Version uint16 = 6
	// HeaderLength is the frame header size in bytes, excluding its body.
	HeaderLength = 43
	// KindHello carries the initiating Hello.
	KindHello uint8 = 1
	// KindHelloAck carries its Hello acknowledgement.
	KindHelloAck uint8 = 2
	// KindCommand carries an admitted public Command.
	KindCommand uint8 = 3
	// KindCredential carries private selected credential inputs.
	KindCredential uint8 = 4
	// KindPayload carries the private encoded value.
	KindPayload uint8 = 5
	// KindPolicy carries opaque canonical policy bytes.
	KindPolicy uint8 = 6
	// KindReadyForPayload is an empty readiness signal before private payload delivery.
	KindReadyForPayload uint8 = 7
	// KindResult carries a closed provider Result.
	KindResult uint8 = 8
	// KindNormalizeRequest carries ordinary public destination settings.
	KindNormalizeRequest uint8 = 9
	// KindNormalizeResult carries normalized public destination facts or refusal.
	KindNormalizeResult uint8 = 10
	// KindPreparationRefused is an empty refusal before effect entry.
	KindPreparationRefused uint8 = 11
	// KindArm is the empty explicit arm signal after preparation.
	KindArm uint8 = 12
	// MaximumCommandBytes bounds encoded command body bytes.
	MaximumCommandBytes = 16 << 10
	// MaximumCredentialBytes bounds the complete private credential-input body in bytes.
	MaximumCredentialBytes = 64 << 10
	// MaximumPayloadBytes bounds one encoded private value in bytes.
	MaximumPayloadBytes = 64 << 10
	// MaximumPolicyBytes bounds opaque canonical policy bytes.
	MaximumPolicyBytes = 524546
	// MaximumResultBytes bounds an encoded effect result body in bytes.
	MaximumResultBytes = 4 << 10
	// KindCanonicalRequest asks for exact destination validation.
	KindCanonicalRequest uint8 = 13
	// KindCanonicalResult carries canonical-validation acceptance or refusal.
	KindCanonicalResult uint8 = 14
	// KindInterpretRequest asks for one entry target.
	KindInterpretRequest uint8 = 15
	// KindInterpretResult carries one target or refusal.
	KindInterpretResult uint8 = 16
	// KindActionCheckRequest carries an exact passive action check.
	KindActionCheckRequest uint8 = 17
	// KindActionCheckResult carries action acceptance and payload bounds or refusal.
	KindActionCheckResult uint8 = 18
	// KindPolicyActionRequest asks which existing action applies a changed policy.
	KindPolicyActionRequest uint8 = 19
	// KindPolicyActionResult carries that action choice or refusal.
	KindPolicyActionResult uint8 = 20
	// MaximumPolicyActionRequestBytes bounds the exact public request body.
	MaximumPolicyActionRequestBytes = 7094
	// MaximumPolicyActionResultBytes bounds the closed result body.
	MaximumPolicyActionResultBytes = 36
	// MaximumPublicRequestBytes bounds a passive public request body in bytes.
	MaximumPublicRequestBytes = 1 << 20
	// MaximumPublicResultBytes bounds a passive public result body in bytes.
	MaximumPublicResultBytes = 1 << 20
	// MaximumActionCheckRequestBytes bounds an encoded action-check request body in bytes.
	MaximumActionCheckRequestBytes = 16 << 10
	// MaximumActionCheckResultBytes bounds an encoded action-check result body in bytes.
	MaximumActionCheckResultBytes = 4 << 10
)

var (
	// ErrProtocol identifies malformed messages or inconsistent output-wire relations.
	ErrProtocol = errors.New("output protocol violation")
	// ErrCapacity identifies an exceeded encoded byte bound.
	ErrCapacity = errors.New("output protocol capacity exceeded")
)

// ID is a 32-byte identity or commitment. Individual messages require nonzero IDs.
type ID [32]byte

// IsZero reports whether every identity byte is zero.
func (id ID) IsZero() bool { return id == ID{} }

// ProtocolID returns the exact identity of output wire version 6.
func ProtocolID() ID {
	return sha256.Sum256([]byte("ENKV/OUTPUT-WIRE/v6\x00"))
}

// Frame carries a kind, nonzero correlation and opaque body. Body is borrowed
// when writing and newly allocated when reading. Readiness, refusal and arm frames
// require an empty body. Framing alone does not validate the message body.
type Frame struct {
	Kind          uint8
	CorrelationID ID
	Body          []byte
}

func validKind(kind uint8) bool { return kind >= KindHello && kind <= KindPolicyActionResult }
func zeroBodyKind(kind uint8) bool {
	return kind == KindReadyForPayload || kind == KindPreparationRefused || kind == KindArm
}

// WriteFrame writes a header and the borrowed body without closing w. It validates
// framing, not message-specific capacity or content. An error can leave a partial
// frame; callers own pipe deadlines, cancellation and closure.
func WriteFrame(w io.Writer, frame Frame) error {
	if w == nil || !validKind(frame.Kind) || frame.CorrelationID.IsZero() || uint64(len(frame.Body)) > uint64(^uint32(0)) ||
		zeroBodyKind(frame.Kind) && len(frame.Body) != 0 {
		return ErrProtocol
	}
	header := make([]byte, HeaderLength)
	copy(header[:4], "ENKO")
	binary.BigEndian.PutUint16(header[4:6], Version)
	header[6] = frame.Kind
	copy(header[7:39], frame.CorrelationID[:])
	binary.BigEndian.PutUint32(header[39:43], uint32(len(frame.Body)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, frame.Body)
}

// ReadFrame reads one frame and allocates its body only after checking maximum
// body bytes. The caller owns the returned body and must clear private bytes after
// all borrowers finish. It does not require EOF or enforce exchange ordering.
func ReadFrame(r io.Reader, maximum uint32) (Frame, error) {
	if r == nil {
		return Frame{}, ErrProtocol
	}
	var header [HeaderLength]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	if string(header[:4]) != "ENKO" || binary.BigEndian.Uint16(header[4:6]) != Version || !validKind(header[6]) {
		return Frame{}, ErrProtocol
	}
	length := binary.BigEndian.Uint32(header[39:43])
	if zeroBodyKind(header[6]) && length != 0 {
		return Frame{}, ErrProtocol
	}
	if length > maximum {
		return Frame{}, ErrCapacity
	}
	var out Frame
	out.Kind = header[6]
	copy(out.CorrelationID[:], header[7:39])
	if out.CorrelationID.IsZero() {
		return Frame{}, ErrProtocol
	}
	out.Body = make([]byte, length)
	if _, err := io.ReadFull(r, out.Body); err != nil {
		clear(out.Body)
		return Frame{}, err
	}
	return out, nil
}

// ReadExpectedFrame reads one bounded frame, checks its kind and correlation, and
// returns its owned body. It clears a body rejected for either mismatch. It does
// not require EOF; the caller must finish the exchange and clear private bytes.
func ReadExpectedFrame(r io.Reader, kind uint8, correlation ID, maximum uint32) ([]byte, error) {
	frame, err := ReadFrame(r, maximum)
	if err != nil {
		return nil, err
	}
	if frame.Kind != kind || frame.CorrelationID != correlation {
		clear(frame.Body)
		return nil, ErrProtocol
	}
	return frame.Body, nil
}

// RequireEOF requires the next read to return no bytes and io.EOF. It can block
// until the owner closes the stream; callers must supply bounded pipe lifetime.
func RequireEOF(r io.Reader) error {
	if r == nil {
		return ErrProtocol
	}
	var b [1]byte
	n, err := r.Read(b[:])
	if n != 0 || err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func writeAll(w io.Writer, body []byte) error {
	for len(body) != 0 {
		n, err := w.Write(body)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(body) {
			return io.ErrShortWrite
		}
		body = body[n:]
	}
	return nil
}
