package output

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	// MaximumSettingsBytes bounds public JSON destination settings in bytes.
	MaximumSettingsBytes = 65536
	// MaximumTargetDataBytes bounds opaque public target data in bytes.
	MaximumTargetDataBytes = 4096
	// EncodingRaw selects raw value bytes.
	EncodingRaw uint8 = 1
	// EncodingBase64 selects base64-encoded value bytes.
	EncodingBase64 uint8 = 2
)

// ActionCapabilities describes supported actions and their policy effects, not
// permission to send.
type ActionCapabilities uint8

const (
	// CapabilityCreateEmpty advertises create without a value.
	CapabilityCreateEmpty ActionCapabilities = 1 << (ActionCreateEmpty - 1)
	// CapabilityCreateWithValue advertises create with a value.
	CapabilityCreateWithValue ActionCapabilities = 1 << (ActionCreateWithValue - 1)
	// CapabilityWriteValue advertises value writes.
	CapabilityWriteValue ActionCapabilities = 1 << (ActionWriteValue - 1)
	// CapabilityUpdatePolicy advertises separate policy updates.
	CapabilityUpdatePolicy ActionCapabilities = 1 << (ActionUpdatePolicy - 1)
	// CapabilityDeleteOwned advertises qualified owned-instance deletion.
	CapabilityDeleteOwned ActionCapabilities = 1 << (ActionDeleteOwned - 1)
	// CapabilityDeleteReservedSlot advertises uncertain reserved-slot deletion.
	CapabilityDeleteReservedSlot ActionCapabilities = 1 << (ActionDeleteReservedSlot - 1)
	// CapabilityCreateSetsPolicy declares that every advertised create variant applies policy.
	CapabilityCreateSetsPolicy ActionCapabilities = 1 << 6
	// CapabilityWriteSetsPolicy declares that value writes apply policy.
	CapabilityWriteSetsPolicy ActionCapabilities = 1 << 7
)

// Valid checks that policy-effect flags have their corresponding action.
// Zero is a valid declaration of no actions; this is not a permission check.
func (v ActionCapabilities) Valid() bool {
	return (!v.CreateSetsPolicy() || v.Has(ActionCreateEmpty) || v.Has(ActionCreateWithValue)) &&
		(!v.WriteSetsPolicy() || v.Has(ActionWriteValue))
}

// Has reports whether a defined action is advertised; unknown actions return false.
func (v ActionCapabilities) Has(action Action) bool {
	return action >= ActionCreateEmpty && action <= ActionDeleteReservedSlot && v&(1<<(action-1)) != 0
}

// CreateSetsPolicy reports whether every advertised create action applies policy.
func (v ActionCapabilities) CreateSetsPolicy() bool { return v&CapabilityCreateSetsPolicy != 0 }

// WriteSetsPolicy reports whether the advertised write action applies policy.
func (v ActionCapabilities) WriteSetsPolicy() bool { return v&CapabilityWriteSetsPolicy != 0 }

// Capabilities builds action bits without policy-effect flags. Duplicates are
// harmless; no actions returns zero. Invalid actions wrap ErrProtocol. Add the
// policy-effect flags only when the plugin implements those effects.
func Capabilities(actions ...Action) (ActionCapabilities, error) {
	var v ActionCapabilities
	for _, action := range actions {
		if action < ActionCreateEmpty || action > ActionDeleteReservedSlot {
			return 0, fmt.Errorf("output capabilities: actions: unsupported action: %w", ErrProtocol)
		}
		v |= 1 << (action - 1)
	}
	return v, nil
}

// Destination contains plugin-owned canonical public settings and family facts.
// Its mutable bytes remain owned by its producer until a synchronous call returns.
type Destination struct {
	ConfigContractID, ServiceContractID string
	CanonicalSettings                   []byte
	Policy                              Policy
	Capabilities                        ActionCapabilities
}

// Valid checks nonempty contract strings, JSON settings, policy shape and
// capability relations. It does not establish canonical plugin-owned meaning.
func (v Destination) Valid() bool {
	return validText(v.ConfigContractID, MaximumIdentifierBytes) && validText(v.ServiceContractID, MaximumIdentifierBytes) &&
		len(v.CanonicalSettings) <= MaximumSettingsBytes && ValidCanonicalSettings(v.CanonicalSettings) && v.Policy.Valid() && v.Capabilities.Valid()
}

// Target is a self-contained public interpretation of one entry at one service.
// Contract strings name plugin-owned semantics; TargetData is opaque public data.
// LocatorRequiresCreation means ConsumerLocator is empty until acknowledgement.
// CreateValueBounds and WriteValueBounds are inclusive encoded-byte intervals;
// absent actions require zero intervals. A declared 0..0 value interval allows
// only an empty value. Constructed and decoded TargetData can alias their owner;
// keep it unchanged through synchronous borrowers.
type Target struct {
	ServiceContractID, TargetContractID string
	CanonicalTarget, ConsumerLocator    string
	TargetData                          []byte
	PayloadEncoding                     uint8
	LocatorRequiresCreation             bool
	Capabilities                        ActionCapabilities
	CreateValueBounds, WriteValueBounds PayloadBounds
}

// Valid checks bounded target facts, encoding and locator consistency, and
// payload intervals for advertised value actions. It does not authenticate the
// service target or establish permission to use it.
func (v Target) Valid() bool {
	return validText(v.ServiceContractID, MaximumIdentifierBytes) && validText(v.TargetContractID, MaximumIdentifierBytes) &&
		validText(v.CanonicalTarget, MaximumCoordinateBytes) && len(v.ConsumerLocator) <= MaximumCoordinateBytes && utf8.ValidString(v.ConsumerLocator) &&
		(v.LocatorRequiresCreation == (v.ConsumerLocator == "")) && len(v.TargetData) <= MaximumTargetDataBytes &&
		(v.PayloadEncoding == EncodingRaw || v.PayloadEncoding == EncodingBase64) && v.Capabilities.Valid() &&
		v.CreateValueBounds.validRange() && v.WriteValueBounds.validRange() &&
		(v.Capabilities.Has(ActionCreateWithValue) || v.CreateValueBounds == (PayloadBounds{})) &&
		(v.Capabilities.Has(ActionWriteValue) || v.WriteValueBounds == (PayloadBounds{}))
}

func (v Target) payloadBounds(action Action) PayloadBounds {
	switch action {
	case ActionCreateWithValue:
		return v.CreateValueBounds
	case ActionWriteValue:
		return v.WriteValueBounds
	default:
		return PayloadBounds{}
	}
}

func encodeDestination(b []byte, v Destination) []byte {
	b = appendBlob(b, []byte(v.ConfigContractID))
	b = appendBlob(b, []byte(v.ServiceContractID))
	b = appendBlob(b, v.CanonicalSettings)
	b = appendBlob(b, []byte(v.Policy.ContractID))
	b = appendBlob(b, v.Policy.Data)
	return append(b, byte(v.Capabilities))
}
func decodeDestination(r *reader) Destination {
	return Destination{ConfigContractID: string(r.blob(MaximumIdentifierBytes)), ServiceContractID: string(r.blob(MaximumIdentifierBytes)),
		CanonicalSettings: r.blob(MaximumSettingsBytes), Policy: Policy{ContractID: string(r.blob(MaximumIdentifierBytes)), Data: r.blob(MaximumPolicyBytes)}, Capabilities: ActionCapabilities(r.u8())}
}
func encodeTarget(b []byte, v Target) []byte {
	for _, s := range []string{v.ServiceContractID, v.TargetContractID, v.CanonicalTarget, v.ConsumerLocator} {
		b = appendBlob(b, []byte(s))
	}
	b = appendBlob(b, v.TargetData)
	b = append(b, v.PayloadEncoding, byte(v.Capabilities))
	if v.LocatorRequiresCreation {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint32(b, v.CreateValueBounds.Minimum)
	b = binary.BigEndian.AppendUint32(b, v.CreateValueBounds.Maximum)
	b = binary.BigEndian.AppendUint32(b, v.WriteValueBounds.Minimum)
	return binary.BigEndian.AppendUint32(b, v.WriteValueBounds.Maximum)
}
func decodeTarget(r *reader) Target {
	v := Target{ServiceContractID: string(r.blob(MaximumIdentifierBytes)), TargetContractID: string(r.blob(MaximumIdentifierBytes)),
		CanonicalTarget: string(r.blob(MaximumCoordinateBytes)), ConsumerLocator: string(r.blob(MaximumCoordinateBytes)), TargetData: r.blob(MaximumTargetDataBytes), PayloadEncoding: r.u8(), Capabilities: ActionCapabilities(r.u8())}
	flag := r.u8()
	if flag > 1 {
		r.err = ErrProtocol
	}
	v.LocatorRequiresCreation = flag == 1
	v.CreateValueBounds = PayloadBounds{Minimum: r.u32(), Maximum: r.u32()}
	v.WriteValueBounds = PayloadBounds{Minimum: r.u32(), Maximum: r.u32()}
	return v
}

// EncodeDestination validates structural facts and returns new bytes.
// Plugin-owned semantic correctness is a separate check.
func EncodeDestination(v Destination) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	return encodeDestination(nil, v), nil
}

// DecodeDestination checks the complete bounded body. CanonicalSettings and Policy.Data
// borrows b; retain b unchanged until all users finish. Strings are copied.
// Structural validity does not establish canonical plugin-owned meaning.
func DecodeDestination(b []byte) (Destination, error) {
	if len(b) > MaximumPublicResultBytes {
		return Destination{}, ErrCapacity
	}
	r := reader{b: b}
	v := decodeDestination(&r)
	if r.end() != nil || !v.Valid() {
		return Destination{}, ErrProtocol
	}
	return v, nil
}

// EncodeTarget validates structural facts and returns new bytes.
// Plugin-owned semantic correctness is a separate check.
func EncodeTarget(v Target) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	return encodeTarget(nil, v), nil
}

// DecodeTarget checks the complete bounded body. TargetData
// borrows b; retain b unchanged until all users finish. Strings are copied.
// Structural validity does not establish canonical plugin-owned meaning.
func DecodeTarget(b []byte) (Target, error) {
	if len(b) > MaximumCommandBytes {
		return Target{}, ErrCapacity
	}
	r := reader{b: b}
	v := decodeTarget(&r)
	if r.end() != nil || !v.Valid() {
		return Target{}, ErrProtocol
	}
	return v, nil
}
