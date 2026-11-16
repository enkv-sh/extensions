// Package credentialroute defines the bounded public credential recipe and its
// private environment-input encoding. It performs no credential discovery.
package credentialroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	// Schema is the route and private-input encoding version.
	Schema uint16 = 1
	// ModeEnvironment declares ordinary environment-based discovery.
	ModeEnvironment uint8 = 1
	// ModeSDK declares standard SDK credential discovery.
	ModeSDK uint8 = 2
	// MaxRouteBytes bounds the complete public route encoding in bytes.
	MaxRouteBytes = 1581
	// MaxInputsBytes bounds the complete private input encoding in bytes.
	MaxInputsBytes = 65536
	// MaxNames bounds the number of declared environment names.
	MaxNames = 32
	// MaxNameBytes bounds each ASCII environment name in bytes.
	MaxNameBytes = 128
)

// ErrRecord identifies invalid route or private-input encodings.
var ErrRecord = errors.New("credential route refused")

// Route declares a public credential recipe, not credentials or permission.
// Use Schema, a nonzero ContractID and one discovery Mode. Names must be sorted,
// distinct ASCII environment names, at most MaxNames with MaxNameBytes each.
// PublicData is opaque public contract data; all fields share MaxRouteBytes.
// ContractID identifies the plugin-owned discovery rules and the meaning of
// Names/PublicData. Rotate it for incompatible interpretation changes, not for
// secret-value rotation. Identity separately binds every encoded public field.
type Route struct {
	Schema     uint16
	ContractID [32]byte
	Mode       uint8
	Names      []string
	PublicData []byte
}

// Input distinguishes an absent variable from a present empty value. Names and
// order must exactly match Route.Names. Absent inputs have empty Value; present
// values may be empty but cannot contain NUL. Ownership depends on construction:
// DecodeInputs borrows values, while EncodeInputs copies them.
type Input struct {
	Name    string
	Present bool
	Value   []byte
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > MaxNameBytes {
		return false
	}
	for i := range s {
		c := s[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func routeLength(v Route) (int, error) {
	if v.Schema != Schema || v.ContractID == [32]byte{} || v.Mode != ModeEnvironment && v.Mode != ModeSDK || len(v.Names) > MaxNames || len(v.PublicData) > MaxRouteBytes-40 {
		return 0, ErrRecord
	}
	n := 40 + len(v.PublicData)
	for i, name := range v.Names {
		if !validName(name) || i > 0 && v.Names[i-1] >= name {
			return 0, ErrRecord
		}
		n += 1 + len(name)
	}
	if n > MaxRouteBytes {
		return 0, ErrRecord
	}
	return n, nil
}

// Encode validates the complete route and returns new canonical bytes without
// retaining the supplied Names or PublicData. Invalid input returns ErrRecord.
func Encode(v Route) ([]byte, error) {
	n, err := routeLength(v)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, n)
	b = binary.BigEndian.AppendUint16(b, v.Schema)
	b = append(b, v.ContractID[:]...)
	b = append(b, v.Mode, byte(len(v.Names)))
	for _, name := range v.Names {
		b = append(b, byte(len(name)))
		b = append(b, name...)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(v.PublicData)))
	return append(b, v.PublicData...), nil
}

// Decode validates exact route framing and returns owned names and public data.
// No returned bytes alias body; malformed or excess input returns ErrRecord.
func Decode(body []byte) (Route, error) {
	if len(body) < 40 || len(body) > MaxRouteBytes {
		return Route{}, ErrRecord
	}
	r := reader{body: body}
	v := Route{Schema: r.u16()}
	copy(v.ContractID[:], r.take(32))
	v.Mode = r.u8()
	count := int(r.u8())
	if count > MaxNames {
		return Route{}, ErrRecord
	}
	v.Names = make([]string, 0, count)
	for range count {
		v.Names = append(v.Names, string(r.take(int(r.u8()))))
	}
	v.PublicData = append([]byte(nil), r.blob()...)
	if r.failed || len(r.body) != 0 {
		return Route{}, ErrRecord
	}
	if _, err := routeLength(v); err != nil {
		return Route{}, err
	}
	return v, nil
}

// Identity hashes a validated canonical route with its domain separator.
// It contains no private inputs or executable identity.
func Identity(v Route) ([32]byte, error) {
	body, err := Encode(v)
	if err != nil {
		return [32]byte{}, err
	}
	prefix := []byte("ENKV/CREDENTIAL-ROUTE/v1\x00")
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(body)))
	return sha256.Sum256(append(prefix, body...)), nil
}

func inputsLength(route Route, inputs []Input) (int, error) {
	if _, err := routeLength(route); err != nil || len(inputs) != len(route.Names) {
		return 0, ErrRecord
	}
	n := 3
	for i, input := range inputs {
		if input.Name != route.Names[i] || !input.Present && len(input.Value) != 0 || len(input.Value) > MaxInputsBytes || bytes.IndexByte(input.Value, 0) >= 0 {
			return 0, ErrRecord
		}
		n += 6 + len(input.Name) + len(input.Value)
		if n > MaxInputsBytes {
			return 0, ErrRecord
		}
	}
	return n, nil
}

// EncodeInputs copies the selected private environment inputs into a new buffer.
// The caller owns that buffer and must clear it after the invocation joins.
func EncodeInputs(route Route, inputs []Input) ([]byte, error) {
	n, err := inputsLength(route, inputs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, n)
	b = binary.BigEndian.AppendUint16(b, Schema)
	b = append(b, byte(len(inputs)))
	for _, input := range inputs {
		b = append(b, byte(len(input.Name)))
		b = append(b, input.Name...)
		if input.Present {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(input.Value)))
		b = append(b, input.Value...)
	}
	return b, nil
}

// DecodeInputs borrows every Value from body. The caller must retain body until
// its borrowers return, then clear it. Names are public owned strings.
func DecodeInputs(route Route, body []byte) ([]Input, error) {
	if len(body) < 3 || len(body) > MaxInputsBytes {
		return nil, ErrRecord
	}
	r := reader{body: body}
	if r.u16() != Schema || int(r.u8()) != len(route.Names) || len(route.Names) > MaxNames {
		return nil, ErrRecord
	}
	inputs := make([]Input, 0, len(route.Names))
	for range route.Names {
		name := string(r.take(int(r.u8())))
		present := r.u8()
		value := r.blob()
		if r.failed || present > 1 {
			return nil, ErrRecord
		}
		inputs = append(inputs, Input{Name: name, Present: present == 1, Value: value})
	}
	if r.failed || len(r.body) != 0 {
		return nil, ErrRecord
	}
	if _, err := inputsLength(route, inputs); err != nil {
		return nil, err
	}
	return inputs, nil
}

type reader struct {
	body   []byte
	failed bool
}

func (r *reader) take(n int) []byte {
	if r.failed || n < 0 || n > len(r.body) {
		r.failed = true
		return nil
	}
	b := r.body[:n:n]
	r.body = r.body[n:]
	return b
}

func (r *reader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) blob() []byte {
	b := r.take(4)
	if b == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(r.body)) {
		r.failed = true
		return nil
	}
	return r.take(int(n))
}
