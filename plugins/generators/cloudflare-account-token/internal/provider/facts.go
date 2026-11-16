// Package provider owns the Cloudflare request and response interpretation.
package provider

import (
	"encoding/binary"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	protocol "enkv.sh/sdk/protocols/generator"
)

// ID is the generator protocol identity used for request and resource facts.
type ID = protocol.ID

// ErrProtocol reports malformed facts; ErrCapacity reports an exceeded codec
// bound. Both are suitable for errors.Is checks.
var (
	ErrProtocol = errors.New("cloudflare provider facts refused")
	ErrCapacity = errors.New("cloudflare provider facts capacity exceeded")
)

// Actions identify token creation or exact deletion.
const (
	ActionCreate = 1
	ActionDelete = 2
)

// Dispositions distinguish a usable value, a cleanup target and uncertainty.
const (
	DispositionCompleteCreate      = 1
	DispositionOwnedUnusableCreate = 2
	DispositionDeleteAcknowledged  = 3
	DispositionUnknown             = 4
)

// Reasons are bounded public classifications; raw service errors are excluded.
const (
	ReasonNone             = 0
	ReasonMissingValue     = 1
	ReasonInvalidValue     = 2
	ReasonControls         = 3
	ReasonInactive         = 4
	ReasonMalformed        = 5
	ReasonOverflow         = 6
	ReasonRejected         = 7
	ReasonTransport        = 8
	ReasonDeadline         = 9
	ReasonIdentityConflict = 10
)

// Status zero means no reported status; TokenPresent states token presence separately.
const (
	TokenStatusAbsent   = 0
	TokenStatusActive   = 1
	TokenStatusDisabled = 2
	TokenStatusExpired  = 3
)

// Echo bits record which controls a bounded response reports; a matched digest
// requires the complete applicable control predicate.
const (
	EchoNone           = 0
	EchoName           = 1
	EchoPolicies       = 2
	EchoCondition      = 4
	EchoNotBefore      = 8
	EchoExpiry         = 16
	EchoRequiredCreate = EchoName | EchoPolicies
	EchoMask           = EchoRequiredCreate | EchoCondition | EchoNotBefore | EchoExpiry
)

// Bearer, diagnostic, observation and HTTP status bounds limit public decoding
// and private credential admission; they are local implementation bounds.
const (
	MinimumBearerLength      = 40
	MaximumBearerLength      = 80
	SafeFactsErrorLimit      = 16
	ObservationTimeMaxLength = 64
	HTTPStatusAbsent         = 0
	HTTPStatusMaximum        = 599
)

// Record bounds cap the internal controls, returned bearer and encoded facts.
const (
	MaximumIntentLength  = 393216
	MaximumSecretLength  = 80
	MaximumSafeFactsBody = 442
)

// Command fixes one request, its intent and deadline. Intent is borrowed until
// Execute returns and is present only for creation. TargetPresent distinguishes
// the absent create target from the exact retained delete token.
type Command struct {
	Action                                           uint8
	DeadlineUnixMillis                               uint64
	HTTPRequestDigest, IntentDigest, Account, Target ID
	TargetPresent                                    uint8
	Intent                                           []byte
}

// ValidBearer checks only the local 40–80 byte base64url token grammar. It
// neither authenticates the token nor establishes its permissions.
func ValidBearer(body []byte) bool {
	if len(body) < MinimumBearerLength || len(body) > MaximumBearerLength {
		return false
	}
	for _, b := range body {
		if b != '_' && b != '-' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

// SafeFacts contains bounded public observations for one request. Schema is 1.
// Presence and echo fields qualify optional IDs and times; unknown disposition
// is not evidence that the provider had no effect. It contains no bearer value.
// DecodeFacts borrows timestamp spans; ErrorCodes are independently allocated.
type SafeFacts struct {
	Schema                                             uint16
	Disposition, Reason                                uint8
	HTTPStatus                                         uint16
	Account                                            ID
	TokenPresent                                       uint8
	TokenID                                            ID
	TokenStatus                                        uint8
	EchoPresence                                       uint16
	RequestDigest, IntentDigest, MatchedControlsDigest ID
	ErrorCodes                                         []uint32
	IssuedUTC, ModifiedUTC, LastUsedUTC                []byte
}

func (v SafeFacts) valid() bool {
	if v.Schema != 1 || v.Disposition < DispositionCompleteCreate || v.Disposition > DispositionUnknown || v.Reason > ReasonIdentityConflict ||
		v.HTTPStatus != HTTPStatusAbsent && (v.HTTPStatus < http.StatusContinue || v.HTTPStatus > HTTPStatusMaximum) || v.Account.IsZero() ||
		v.RequestDigest.IsZero() || v.IntentDigest.IsZero() || v.TokenPresent > 1 ||
		(v.TokenPresent == 0) != v.TokenID.IsZero() || v.TokenStatus > TokenStatusExpired || v.EchoPresence > EchoMask ||
		len(v.ErrorCodes) > SafeFactsErrorLimit || len(v.IssuedUTC) > ObservationTimeMaxLength || len(v.ModifiedUTC) > ObservationTimeMaxLength || len(v.LastUsedUTC) > ObservationTimeMaxLength ||
		!v.MatchedControlsDigest.IsZero() && v.MatchedControlsDigest != v.IntentDigest {
		return false
	}
	for _, text := range [][]byte{v.IssuedUTC, v.ModifiedUTC, v.LastUsedUTC} {
		if len(text) > 0 && (!utf8.Valid(text) || func() bool { _, err := time.Parse(time.RFC3339Nano, string(text)); return err != nil }()) {
			return false
		}
	}
	switch v.Disposition {
	case DispositionCompleteCreate:
		return v.HTTPStatus == http.StatusOK && v.Reason == ReasonNone && v.TokenPresent == 1 && v.TokenStatus == TokenStatusActive &&
			v.EchoPresence&EchoRequiredCreate == EchoRequiredCreate && v.MatchedControlsDigest == v.IntentDigest && len(v.ErrorCodes) == 0
	case DispositionOwnedUnusableCreate:
		return v.HTTPStatus == http.StatusOK && v.Reason >= ReasonMissingValue && v.Reason <= ReasonInactive && v.TokenPresent == 1 && len(v.ErrorCodes) == 0
	case DispositionDeleteAcknowledged:
		return v.HTTPStatus == http.StatusOK && v.Reason == ReasonNone && v.TokenPresent == 1 && v.TokenStatus == TokenStatusAbsent &&
			v.EchoPresence == EchoNone && v.MatchedControlsDigest.IsZero() && len(v.ErrorCodes) == 0 &&
			len(v.IssuedUTC) == 0 && len(v.ModifiedUTC) == 0 && len(v.LastUsedUTC) == 0
	case DispositionUnknown:
		return v.Reason >= ReasonMalformed
	}
	return false
}

// EncodeFacts validates the closed facts predicate and returns new owned bytes.
// Invalid facts return ErrProtocol; an encoded bound overflow returns ErrCapacity.
func EncodeFacts(v SafeFacts) ([]byte, error) {
	if !v.valid() {
		return nil, ErrProtocol
	}
	body := make([]byte, 0, MaximumSafeFactsBody)
	body = binary.BigEndian.AppendUint16(body, v.Schema)
	body = append(body, v.Disposition, v.Reason)
	body = binary.BigEndian.AppendUint16(body, v.HTTPStatus)
	body = append(body, v.Account[:]...)
	body = append(body, v.TokenPresent)
	if v.TokenPresent == 1 {
		body = append(body, v.TokenID[:]...)
	}
	body = append(body, v.TokenStatus)
	body = binary.BigEndian.AppendUint16(body, v.EchoPresence)
	body = append(body, v.RequestDigest[:]...)
	body = append(body, v.IntentDigest[:]...)
	body = append(body, v.MatchedControlsDigest[:]...)
	body = append(body, uint8(len(v.ErrorCodes)))
	for _, code := range v.ErrorCodes {
		body = binary.BigEndian.AppendUint32(body, code)
	}
	for _, text := range [][]byte{v.IssuedUTC, v.ModifiedUTC, v.LastUsedUTC} {
		if len(text) == 0 {
			body = append(body, 0)
		} else {
			body = append(body, 1)
			body = appendBlob(body, text)
		}
	}
	if len(body) > MaximumSafeFactsBody {
		return nil, ErrCapacity
	}
	return body, nil
}

// DecodeFacts checks the complete bounded record. Returned timestamp slices
// alias body with capacity limited to their spans; keep body unchanged and alive
// while using them, or copy them. IDs and ErrorCodes do not alias body. Refusals
// return ErrProtocol or ErrCapacity.
func DecodeFacts(body []byte) (SafeFacts, error) {
	var v SafeFacts
	if len(body) > MaximumSafeFactsBody {
		return v, ErrCapacity
	}
	r := messageReader{body: body}
	v.Schema, v.Disposition, v.Reason, v.HTTPStatus = r.u16(), r.u8(), r.u8(), r.u16()
	v.Account, v.TokenPresent = r.id(), r.u8()
	if v.TokenPresent == 1 {
		v.TokenID = r.id()
	}
	v.TokenStatus, v.EchoPresence = r.u8(), r.u16()
	v.RequestDigest, v.IntentDigest, v.MatchedControlsDigest = r.id(), r.id(), r.id()
	n := int(r.u8())
	if n > SafeFactsErrorLimit {
		return SafeFacts{}, ErrCapacity
	}
	v.ErrorCodes = make([]uint32, n)
	for i := range v.ErrorCodes {
		v.ErrorCodes[i] = r.u32()
	}
	for _, text := range []*[]byte{&v.IssuedUTC, &v.ModifiedUTC, &v.LastUsedUTC} {
		present := r.u8()
		if present > 1 {
			return SafeFacts{}, ErrProtocol
		}
		if present == 1 {
			*text = r.blob(ObservationTimeMaxLength)
			if len(*text) == 0 {
				return SafeFacts{}, ErrProtocol
			}
		}
	}
	if r.err != nil || r.offset != len(body) || !v.valid() {
		return SafeFacts{}, ErrProtocol
	}
	return v, nil
}

type messageReader struct {
	body   []byte
	offset int
	err    error
}

// take borrows an exact-capacity span. Appends cannot overwrite adjacent input,
// but in-span writes still alias the body. The input owner controls its lifetime;
// a caller that retains decoded bytes beyond that lifetime must copy them.
func (r *messageReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.body)-r.offset {
		r.err = ErrProtocol
		return nil
	}
	body := r.body[r.offset : r.offset+n : r.offset+n]
	r.offset += n
	return body
}

func (r *messageReader) u8() uint8 {
	body := r.take(1)
	if len(body) != 1 {
		return 0
	}
	return body[0]
}

func (r *messageReader) u16() uint16 {
	body := r.take(2)
	if len(body) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(body)
}

func (r *messageReader) u32() uint32 {
	body := r.take(4)
	if len(body) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(body)
}

func (r *messageReader) id() ID {
	var id ID
	copy(id[:], r.take(32))
	return id
}

func (r *messageReader) blob(maximum int) []byte {
	n := r.u32()
	if uint64(n) > uint64(maximum) {
		r.err = ErrCapacity
		return nil
	}
	return r.take(int(n))
}

func appendBlob(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)))
	return append(dst, body...)
}
