// Package generator defines the bounded generator family wire. It grants no
// operation permission, source trust or provider-effect proof. SDK serving and
// child lifetime are separate responsibilities.
//
// Message encoders validate structure and return new buffers. Message decoders
// borrow byte fields from their input unless stated otherwise; retain the input
// unchanged through every borrower and clear private bodies after use. Decoding
// does not perform plugin-owned semantic checks. ErrProtocol and ErrCapacity can
// be checked with errors.Is; transport operations can also return I/O errors.
package generator

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// ControlDescriptor is the inherited read-only public-control file descriptor.
	ControlDescriptor = 3
	// EnvironmentDescriptor is the inherited private selected-environment descriptor.
	EnvironmentDescriptor = 4
	// SecretResultDescriptor is the inherited private result descriptor.
	SecretResultDescriptor = 5
	// StatusDescriptor is the inherited closed-status descriptor.
	StatusDescriptor = 6
	// FirstUnassignedDescriptor is the first descriptor outside this wire assignment.
	FirstUnassignedDescriptor = 7
)

// Version is the generator frame version.
const Version uint16 = 5

const (
	// HeaderLength is the frame header length in bytes, excluding its body.
	HeaderLength = 43
	// KindHello carries the initiating Hello.
	KindHello uint8 = 1
	// KindHelloAck carries the peer Hello acknowledgement.
	KindHelloAck uint8 = 2
	// KindCommand carries one admitted effect Command.
	KindCommand uint8 = 3
	// KindEnvironment carries encoded private credential-route inputs.
	KindEnvironment uint8 = 4
	// KindResult carries one effect Result, including private value bytes.
	KindResult uint8 = 5
	// KindStatus carries the closed transport Status.
	KindStatus uint8 = 6
	// KindNormalize carries a passive NormalizeRequest.
	KindNormalize uint8 = 7
	// KindNormalized carries its NormalizeResponse.
	KindNormalized uint8 = 8
	// KindValidateCanonical carries a passive CanonicalRequest.
	KindValidateCanonical uint8 = 9
	// KindCanonicalValidation carries its ValidationResponse.
	KindCanonicalValidation uint8 = 10
	// KindRetirementCompatibility carries a passive RetirementCompatibilityRequest.
	KindRetirementCompatibility uint8 = 11
	// KindRetirementCompatibilityResult carries its ValidationResponse.
	KindRetirementCompatibilityResult uint8 = 12
)

var (
	// ErrProtocol identifies malformed messages or inconsistent wire relations.
	ErrProtocol = errors.New("generator wire protocol violation")
	// ErrCapacity identifies an exceeded encoded byte bound.
	ErrCapacity = errors.New("generator wire capacity exceeded")
)

// ID is a 32-byte identity or commitment. Individual messages require nonzero IDs.
type ID [32]byte

// IsZero reports whether every identity byte is zero.
func (id ID) IsZero() bool { return id == ID{} }

// Frame carries a kind, nonzero command correlation and opaque body. Body is
// borrowed when writing and newly allocated when reading. Framing alone does not
// validate the message body.
type Frame struct {
	Kind      uint8
	CommandID ID
	Body      []byte
}

func validKind(kind uint8) bool {
	return kind >= KindHello && kind <= KindRetirementCompatibilityResult
}

// WriteFrame writes a header and the borrowed body without closing w. It validates
// framing, not message-specific capacity or content. An error can leave a partial
// frame; callers own pipe deadlines, cancellation and closure.
func WriteFrame(w io.Writer, frame Frame) error {
	if w == nil || !validKind(frame.Kind) || frame.CommandID.IsZero() || uint64(len(frame.Body)) > uint64(^uint32(0)) {
		return ErrProtocol
	}
	header := make([]byte, HeaderLength)
	copy(header[:4], "ENKG")
	binary.BigEndian.PutUint16(header[4:6], Version)
	header[6] = frame.Kind
	copy(header[7:39], frame.CommandID[:])
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
	var out Frame
	if r == nil {
		return out, ErrProtocol
	}
	header := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return out, err
	}
	if string(header[:4]) != "ENKG" || binary.BigEndian.Uint16(header[4:6]) != Version || !validKind(header[6]) {
		return out, ErrProtocol
	}
	out.Kind = header[6]
	copy(out.CommandID[:], header[7:39])
	if out.CommandID.IsZero() {
		return Frame{}, ErrProtocol
	}
	length := binary.BigEndian.Uint32(header[39:43])
	if length > maximum {
		return Frame{}, ErrCapacity
	}
	out.Body = make([]byte, int(length))
	if _, err := io.ReadFull(r, out.Body); err != nil {
		clear(out.Body)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return out, nil
}

// ReadExpectedFrame reads one bounded frame, checks its kind and correlation, and
// returns its owned body. It clears a body rejected for either mismatch. It does
// not require EOF; the caller must finish the exchange and clear private bytes.
func ReadExpectedFrame(r io.Reader, kind uint8, command ID, maximum uint32) ([]byte, error) {
	frame, err := ReadFrame(r, maximum)
	if err != nil {
		return nil, err
	}
	if frame.Kind != kind || frame.CommandID != command {
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
	for len(body) > 0 {
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
