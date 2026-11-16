// Package credential encodes one captured AWS output credential without SDK access.
package credential

import (
	"encoding/binary"
	"errors"
	"math"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
)

// ErrCredential reports malformed, oversized or expired credential snapshots.
// Callers may use errors.Is; no credential bytes are included in the error.
var ErrCredential = errors.New("AWS output credential refused")

// Snapshot holds credential fields borrowed from decoded wire bytes. Keep that
// buffer unchanged and alive until the action joins, then clear it. Expiry is
// zero for non-expiring credentials. The zero Snapshot is invalid.
type Snapshot struct {
	AccessKeyID, SecretAccessKey, SessionToken []byte
	Expiry                                     time.Time
}

// Encode copies validated fields into owned version-one bytes. The caller must
// clear them after use. Zero expiry means non-expiring SDK credentials; other
// expiries must still be in the future at validation. Refusals return ErrCredential.
func Encode(access, secret, token string, expiry time.Time) ([]byte, error) {
	length := 16 + len(access) + len(secret) + len(token)
	if length > protocol.MaximumCredentialBytes-36 || len(access) > math.MaxUint16 || len(secret) > math.MaxUint16 || len(token) > math.MaxUint16 {
		return nil, ErrCredential
	}
	b := make([]byte, 0, length)
	b = binary.BigEndian.AppendUint16(b, 1)
	millis := int64(0)
	if !expiry.IsZero() {
		millis = expiry.UnixMilli()
		if millis <= 0 {
			return nil, ErrCredential
		}
	}
	b = binary.BigEndian.AppendUint64(b, uint64(millis))
	for _, field := range []string{access, secret, token} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(field)))
		b = append(b, field...)
	}
	if _, err := Decode(b, time.Now()); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

// Decode validates the exact snapshot and its expiry at now. Returned private
// slices borrow b with capacity limited to each field. Do not mutate or clear b
// while they are in use; copy them if they must outlive b. Refusals return
// ErrCredential; syntax success does not establish service permission.
func Decode(b []byte, now time.Time) (Snapshot, error) {
	if len(b) < 16 || len(b) > protocol.MaximumCredentialBytes-36 || binary.BigEndian.Uint16(b) != 1 {
		return Snapshot{}, ErrCredential
	}
	millis := binary.BigEndian.Uint64(b[2:10])
	if millis > math.MaxInt64 || millis != 0 && int64(millis) <= now.UnixMilli() {
		return Snapshot{}, ErrCredential
	}
	var value Snapshot
	if millis != 0 {
		value.Expiry = time.UnixMilli(int64(millis))
	}
	index := 10
	for _, field := range []*[]byte{&value.AccessKeyID, &value.SecretAccessKey, &value.SessionToken} {
		if len(b)-index < 2 {
			return Snapshot{}, ErrCredential
		}
		size := int(binary.BigEndian.Uint16(b[index : index+2]))
		index += 2
		if size > len(b)-index {
			return Snapshot{}, ErrCredential
		}
		*field = b[index : index+size : index+size]
		index += size
	}
	if index != len(b) || len(value.AccessKeyID) < 16 || len(value.AccessKeyID) > 128 || len(value.SecretAccessKey) == 0 || len(value.SecretAccessKey) > 256 {
		return Snapshot{}, ErrCredential
	}
	for _, c := range value.AccessKeyID {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return Snapshot{}, ErrCredential
		}
	}
	for _, field := range [][]byte{value.SecretAccessKey, value.SessionToken} {
		for _, c := range field {
			if c < 0x21 || c > 0x7e {
				return Snapshot{}, ErrCredential
			}
		}
	}
	return value, nil
}
