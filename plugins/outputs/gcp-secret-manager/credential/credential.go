// Package credential encodes one captured GCP output bearer without SDK access.
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
var ErrCredential = errors.New("GCP output credential refused")

// Snapshot borrows Token from decoded wire bytes; QuotaProject is an owned
// string. Keep the buffer unchanged and alive until the action joins, then clear
// it. Expiry must be in the future. The zero Snapshot is invalid.
type Snapshot struct {
	Token        []byte
	Expiry       time.Time
	QuotaProject string
}

// Encode copies a bearer, future expiry and optional quota project into owned
// version-one bytes. The caller must clear them after use. Refusals return
// ErrCredential; a zero or expired expiry is not accepted.
func Encode(token string, expiry time.Time, quotaProject string) ([]byte, error) {
	if len(token) > 16384 || len(quotaProject) > 253 || expiry.IsZero() || expiry.UnixMilli() <= 0 {
		return nil, ErrCredential
	}
	b := make([]byte, 0, 14+len(token)+len(quotaProject))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(expiry.UnixMilli()))
	for _, field := range []string{token, quotaProject} {
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
	if len(b) < 14 || len(b) > protocol.MaximumCredentialBytes-36 || binary.BigEndian.Uint16(b) != 1 {
		return Snapshot{}, ErrCredential
	}
	millis := binary.BigEndian.Uint64(b[2:10])
	if millis == 0 || millis > math.MaxInt64 || int64(millis) <= now.UnixMilli() {
		return Snapshot{}, ErrCredential
	}
	index := 10
	var fields [2][]byte
	for i := range fields {
		if len(b)-index < 2 {
			return Snapshot{}, ErrCredential
		}
		size := int(binary.BigEndian.Uint16(b[index : index+2]))
		index += 2
		if size > len(b)-index {
			return Snapshot{}, ErrCredential
		}
		fields[i] = b[index : index+size : index+size]
		index += size
	}
	if index != len(b) || len(fields[0]) == 0 || len(fields[0]) > 16384 || len(fields[1]) > 253 {
		return Snapshot{}, ErrCredential
	}
	for _, c := range fields[0] {
		if c < 0x21 || c > 0x7e || c == ':' || c == '\\' || c == '"' {
			return Snapshot{}, ErrCredential
		}
	}
	for _, c := range fields[1] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != ':' {
			return Snapshot{}, ErrCredential
		}
	}
	return Snapshot{Token: fields[0], Expiry: time.UnixMilli(int64(millis)), QuotaProject: string(fields[1])}, nil
}
