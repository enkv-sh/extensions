package output

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"unicode/utf8"
)

// NormalizeRequest contains ordinary public JSON settings under schema 1.
// DeadlineUnixMillis is positive signed-range Unix milliseconds; the codec checks
// range, not current time. Settings is bounded by MaximumSettingsBytes and borrows
// the input when decoded. The plugin owns grammar and defaults.
type NormalizeRequest struct {
	Schema             uint16
	DeadlineUnixMillis uint64
	Settings           []byte
}

// NormalizeResult binds an accept/refuse claim to RequestDigest under schema 1.
// Acceptance requires a valid Destination; refusal requires an empty one.
// Nested destination bytes borrow the input when decoded.
type NormalizeResult struct {
	Schema        uint16
	RequestDigest ID
	Accepted      bool
	Destination   Destination
}

// CanonicalRequest asks the plugin to validate exact canonical destination facts.
// Schema is 1 and the deadline is positive signed-range Unix milliseconds.
// Decoded destination bytes borrow the input; acceptance does not rewrite them.
type CanonicalRequest struct {
	Schema             uint16
	DeadlineUnixMillis uint64
	Destination        Destination
}

// CanonicalResult is a schema-1 accept/refuse claim bound to a nonzero request
// digest. ValidateCanonicalResult checks the expected request binding.
type CanonicalResult struct {
	Schema        uint16
	RequestDigest ID
	Accepted      bool
}

// InterpretRequest asks for one entry target using canonical Destination facts,
// a UTF-8 EntryName of at most 256 bytes and raw/base64 PayloadEncoding.
// Schema is 1 and the deadline is positive signed-range Unix milliseconds.
// Decoded destination bytes borrow the input; EntryName is copied.
type InterpretRequest struct {
	Schema             uint16
	DeadlineUnixMillis uint64
	Destination        Destination
	EntryName          string
	PayloadEncoding    uint8
}

// InterpretResult binds a schema-1 accept/refuse claim to RequestDigest.
// Acceptance requires a valid Target; refusal requires an empty one. Decoding
// borrows TargetData; ValidateInterpretResponse also checks request correlation.
type InterpretResult struct {
	Schema        uint16
	RequestDigest ID
	Accepted      bool
	Target        Target
}

// EncodeNormalizeRequest validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeNormalizeRequest(v NormalizeRequest) ([]byte, error) {
	if v.Schema != 1 || !validDeadline(v.DeadlineUnixMillis) || len(v.Settings) > MaximumSettingsBytes || !json.Valid(v.Settings) {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	return appendBlob(b, v.Settings), nil
}

// DecodeNormalizeRequest checks complete framing and message shape, refusing trailing data.
// The returned Settings borrow b; retain it unchanged through all users.
func DecodeNormalizeRequest(b []byte) (NormalizeRequest, error) {
	if len(b) > MaximumPublicRequestBytes {
		return NormalizeRequest{}, ErrCapacity
	}
	r := reader{b: b}
	v := NormalizeRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), Settings: r.blob(MaximumSettingsBytes)}
	if r.end() != nil {
		return NormalizeRequest{}, ErrProtocol
	}
	if _, err := EncodeNormalizeRequest(v); err != nil {
		return NormalizeRequest{}, err
	}
	return v, nil
}

// EncodeNormalizeResult validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeNormalizeResult(v NormalizeResult) ([]byte, error) {
	if v.Schema != 1 || v.RequestDigest.IsZero() || v.Accepted && !v.Destination.Valid() || !v.Accepted && !emptyDestination(v.Destination) {
		return nil, ErrProtocol
	}
	b := resultHeader(v.Schema, v.RequestDigest, v.Accepted)
	if v.Accepted {
		b = encodeDestination(b, v.Destination)
	}
	if len(b) > MaximumPublicResultBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// DecodeNormalizeResult checks complete framing and message shape, refusing trailing data.
// The returned nested destination bytes borrow b; retain it unchanged through all users.
func DecodeNormalizeResult(b []byte) (NormalizeResult, error) {
	if len(b) > MaximumPublicResultBytes {
		return NormalizeResult{}, ErrCapacity
	}
	r := reader{b: b}
	s, d, a := readResultHeader(&r)
	v := NormalizeResult{Schema: s, RequestDigest: d, Accepted: a}
	if a {
		v.Destination = decodeDestination(&r)
	}
	if r.end() != nil {
		return NormalizeResult{}, ErrProtocol
	}
	if _, err := EncodeNormalizeResult(v); err != nil {
		return NormalizeResult{}, err
	}
	return v, nil
}

// EncodeCanonicalRequest validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeCanonicalRequest(v CanonicalRequest) ([]byte, error) {
	if v.Schema != 1 || !validDeadline(v.DeadlineUnixMillis) || !v.Destination.Valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	return encodeDestination(b, v.Destination), nil
}

// DecodeCanonicalRequest checks complete framing and message shape, refusing trailing data.
// The returned nested destination bytes borrow b; retain it unchanged through all users.
func DecodeCanonicalRequest(b []byte) (CanonicalRequest, error) {
	if len(b) > MaximumPublicRequestBytes {
		return CanonicalRequest{}, ErrCapacity
	}
	r := reader{b: b}
	v := CanonicalRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), Destination: decodeDestination(&r)}
	if r.end() != nil {
		return CanonicalRequest{}, ErrProtocol
	}
	if _, err := EncodeCanonicalRequest(v); err != nil {
		return CanonicalRequest{}, err
	}
	return v, nil
}

// EncodeCanonicalResult validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeCanonicalResult(v CanonicalResult) ([]byte, error) {
	if v.Schema != 1 || v.RequestDigest.IsZero() {
		return nil, ErrProtocol
	}
	return resultHeader(v.Schema, v.RequestDigest, v.Accepted), nil
}

// DecodeCanonicalResult checks complete framing and message shape, refusing trailing data.
// The result contains no borrowed byte fields.
func DecodeCanonicalResult(b []byte) (CanonicalResult, error) {
	r := reader{b: b}
	s, d, a := readResultHeader(&r)
	v := CanonicalResult{s, d, a}
	if r.end() != nil {
		return CanonicalResult{}, ErrProtocol
	}
	if _, err := EncodeCanonicalResult(v); err != nil {
		return CanonicalResult{}, err
	}
	return v, nil
}

// EncodeInterpretRequest validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeInterpretRequest(v InterpretRequest) ([]byte, error) {
	if v.Schema != 1 || !validDeadline(v.DeadlineUnixMillis) || !v.Destination.Valid() || len(v.EntryName) > 256 || !utf8.ValidString(v.EntryName) || (v.PayloadEncoding != EncodingRaw && v.PayloadEncoding != EncodingBase64) {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = encodeDestination(b, v.Destination)
	b = appendBlob(b, []byte(v.EntryName))
	return append(b, v.PayloadEncoding), nil
}

// DecodeInterpretRequest checks complete framing and message shape, refusing trailing data.
// The returned nested destination bytes borrow b; retain it unchanged through all users.
func DecodeInterpretRequest(b []byte) (InterpretRequest, error) {
	if len(b) > MaximumPublicRequestBytes {
		return InterpretRequest{}, ErrCapacity
	}
	r := reader{b: b}
	v := InterpretRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), Destination: decodeDestination(&r), EntryName: string(r.blob(256)), PayloadEncoding: r.u8()}
	if r.end() != nil {
		return InterpretRequest{}, ErrProtocol
	}
	if _, err := EncodeInterpretRequest(v); err != nil {
		return InterpretRequest{}, err
	}
	return v, nil
}

// EncodeInterpretResult validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeInterpretResult(v InterpretResult) ([]byte, error) {
	if v.Schema != 1 || v.RequestDigest.IsZero() || v.Accepted && !v.Target.Valid() || !v.Accepted && !emptyTarget(v.Target) {
		return nil, ErrProtocol
	}
	b := resultHeader(v.Schema, v.RequestDigest, v.Accepted)
	if v.Accepted {
		b = encodeTarget(b, v.Target)
	}
	return b, nil
}

// DecodeInterpretResult checks complete framing and message shape, refusing trailing data.
// The returned Target.TargetData borrow b; retain it unchanged through all users.
func DecodeInterpretResult(b []byte) (InterpretResult, error) {
	if len(b) > MaximumPublicResultBytes {
		return InterpretResult{}, ErrCapacity
	}
	r := reader{b: b}
	s, d, a := readResultHeader(&r)
	v := InterpretResult{Schema: s, RequestDigest: d, Accepted: a}
	if a {
		v.Target = decodeTarget(&r)
	}
	if r.end() != nil {
		return InterpretResult{}, ErrProtocol
	}
	if _, err := EncodeInterpretResult(v); err != nil {
		return InterpretResult{}, err
	}
	return v, nil
}

// ValidateInterpretResult checks result structure and, for acceptance, service,
// encoding and capability compatibility with the request. It does not validate
// request structure or RequestDigest; use ValidateInterpretResponse for both.
func ValidateInterpretResult(request InterpretRequest, result InterpretResult) error {
	if _, err := EncodeInterpretResult(result); err != nil {
		return err
	}
	if result.Accepted && (result.Target.ServiceContractID != request.Destination.ServiceContractID || result.Target.PayloadEncoding != request.PayloadEncoding || result.Target.Capabilities & ^request.Destination.Capabilities != 0) {
		return ErrProtocol
	}
	return nil
}
func emptyDestination(v Destination) bool {
	return v.ConfigContractID == "" && v.ServiceContractID == "" && len(v.CanonicalSettings) == 0 && !v.Policy.Present() && len(v.Policy.Data) == 0 && v.Capabilities == 0
}
func emptyTarget(v Target) bool {
	return v.ServiceContractID == "" && v.TargetContractID == "" && v.CanonicalTarget == "" && v.ConsumerLocator == "" && len(v.TargetData) == 0 && v.PayloadEncoding == 0 && !v.LocatorRequiresCreation && v.Capabilities == 0 && v.CreateValueBounds == (PayloadBounds{}) && v.WriteValueBounds == (PayloadBounds{})
}
func resultHeader(schema uint16, digest ID, accepted bool) []byte {
	b := binary.BigEndian.AppendUint16(nil, schema)
	b = append(b, digest[:]...)
	if accepted {
		return append(b, 1)
	}
	return append(b, 0)
}
func readResultHeader(r *reader) (uint16, ID, bool) {
	schema, digest, accepted := r.u16(), r.id(), r.u8()
	if accepted > 1 {
		r.err = ErrProtocol
	}
	return schema, digest, accepted == 1
}

// PublicRequestDigest binds exact captured bytes and the fresh check correlation.
func PublicRequestDigest(checkID ID, kind uint8, request, policy []byte) (ID, error) {
	if checkID.IsZero() || (kind != KindNormalizeRequest && kind != KindCanonicalRequest && kind != KindInterpretRequest && kind != KindActionCheckRequest && kind != KindPolicyActionRequest) || len(request) > MaximumPublicRequestBytes || len(policy) > MaximumPolicyBytes {
		return ID{}, ErrProtocol
	}
	b := append([]byte("ENKV/OUTPUT/PUBLIC-REQUEST/v1\x00"), checkID[:]...)
	b = append(b, kind)
	b = appendBlob(b, request)
	return sha256.Sum256(appendBlob(b, policy)), nil
}

// ActionCheckRequest carries public facts for a passive action check, with no
// credentials or payload. Schema is 1 and the deadline is positive signed-range
// Unix milliseconds. Ownership fields select create, owned or uncertain-slot
// relations. ConditionalTokenLength is bytes, not the token itself. LengthAbsent
// for a value action means unknown length; LengthExact includes exact empty values.
// Decoded TargetData borrows input; check acceptance before effect admission.
type ActionCheckRequest struct {
	Schema                                                                                                        uint16
	Action                                                                                                        Action
	DomainID, DescriptorID, PolicyDigest, OwnedInstanceDigest, UncertainCreateAttemptID, ExclusiveNamespaceDigest ID
	Target                                                                                                        Target
	OwnedInstance, PolicyContractID                                                                               string
	OwnershipMode                                                                                                 uint8
	ConditionalTokenLength                                                                                        uint16
	PayloadLengthMode                                                                                             uint8
	PayloadLength                                                                                                 uint32
	DeadlineUnixMillis                                                                                            uint64
}

// PayloadBounds is an inclusive interval of encoded value bytes.
type PayloadBounds struct{ Minimum, Maximum uint32 }

// ActionCheckResult binds a schema-1 accept/refuse claim to RequestDigest.
// Acceptance repeats the target's exact interval for the action; metadata actions
// and refused checks use zero PayloadBounds. A zero interval can also mean an
// advertised value action accepts only an empty payload. It grants no send permission.
type ActionCheckResult struct {
	Schema        uint16
	RequestDigest ID
	Accepted      bool
	PayloadBounds PayloadBounds
}

// Valid checks public action, ownership, policy, target and payload relations,
// including deadline range. It does not check current time or provider semantics.
func (v ActionCheckRequest) Valid() bool {
	if v.Schema != 1 || v.Action < ActionCreateEmpty || v.Action > ActionDeleteReservedSlot || v.DomainID.IsZero() || v.DescriptorID.IsZero() || !v.Target.Valid() || !v.Target.Capabilities.Has(v.Action) ||
		!validOptionalText(v.PolicyContractID, MaximumIdentifierBytes) || !validOptionalText(v.OwnedInstance, MaximumCoordinateBytes) || v.ConditionalTokenLength > MaximumCoordinateBytes || !validDeadline(v.DeadlineUnixMillis) ||
		(v.PolicyContractID == "") != v.PolicyDigest.IsZero() || v.Action == ActionUpdatePolicy && v.PolicyDigest.IsZero() || v.Action >= ActionDeleteOwned && !v.PolicyDigest.IsZero() {
		return false
	}
	if ValidateActionPayload(v.Action, v.Target, v.PayloadLengthMode, v.PayloadLength) != nil {
		return false
	}
	if createAction(v.Action) {
		return v.OwnershipMode == OwnershipNone && v.OwnedInstance == "" && v.OwnedInstanceDigest.IsZero() && v.UncertainCreateAttemptID.IsZero() && v.ExclusiveNamespaceDigest.IsZero()
	}
	if v.Action == ActionDeleteReservedSlot {
		return v.OwnershipMode == OwnershipUncertain && v.OwnedInstance == "" && v.OwnedInstanceDigest.IsZero() && !v.UncertainCreateAttemptID.IsZero() && !v.ExclusiveNamespaceDigest.IsZero()
	}
	return v.OwnershipMode == OwnershipQualified && v.OwnedInstance != "" && !v.OwnedInstanceDigest.IsZero() && v.UncertainCreateAttemptID.IsZero() && v.ExclusiveNamespaceDigest.IsZero()
}

// EncodeActionCheckRequest validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeActionCheckRequest(v ActionCheckRequest) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = append(b, byte(v.Action))
	for _, id := range []ID{v.DomainID, v.DescriptorID, v.PolicyDigest, v.OwnedInstanceDigest, v.UncertainCreateAttemptID, v.ExclusiveNamespaceDigest} {
		b = append(b, id[:]...)
	}
	b = encodeTarget(b, v.Target)
	b = appendBlob(b, []byte(v.OwnedInstance))
	b = appendBlob(b, []byte(v.PolicyContractID))
	b = append(b, v.OwnershipMode)
	b = binary.BigEndian.AppendUint16(b, v.ConditionalTokenLength)
	b = append(b, v.PayloadLengthMode)
	b = binary.BigEndian.AppendUint32(b, v.PayloadLength)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	if len(b) > MaximumActionCheckRequestBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// DecodeActionCheckRequest checks complete framing and message shape, refusing trailing data.
// The returned Target.TargetData borrow b; retain it unchanged through all users.
func DecodeActionCheckRequest(b []byte) (ActionCheckRequest, error) {
	if len(b) > MaximumActionCheckRequestBytes {
		return ActionCheckRequest{}, ErrCapacity
	}
	r := reader{b: b}
	v := ActionCheckRequest{Schema: r.u16(), Action: Action(r.u8()), DomainID: r.id(), DescriptorID: r.id(), PolicyDigest: r.id(), OwnedInstanceDigest: r.id(), UncertainCreateAttemptID: r.id(), ExclusiveNamespaceDigest: r.id(), Target: decodeTarget(&r), OwnedInstance: string(r.blob(MaximumCoordinateBytes)), PolicyContractID: string(r.blob(MaximumIdentifierBytes)), OwnershipMode: r.u8(), ConditionalTokenLength: r.u16(), PayloadLengthMode: r.u8(), PayloadLength: r.u32(), DeadlineUnixMillis: r.u64()}
	if r.end() != nil || !v.Valid() {
		return ActionCheckRequest{}, ErrProtocol
	}
	return v, nil
}
func (v PayloadBounds) validRange() bool {
	return v.Minimum <= v.Maximum && v.Maximum <= MaximumPayloadBytes
}
func (v PayloadBounds) contains(length uint32) bool {
	return length >= v.Minimum && length <= v.Maximum
}

// ValidatePayloadBounds checks bounds against this admitted action check.
func ValidatePayloadBounds(r ActionCheckRequest, v PayloadBounds) error {
	if !r.Valid() || v != r.Target.payloadBounds(r.Action) ||
		valueAction(r.Action) && r.PayloadLengthMode != LengthAbsent && !v.contains(r.PayloadLength) {
		return ErrProtocol
	}
	return nil
}

// EncodeActionCheckResult validates message shape and returns a new body.
// It does not retain inputs or perform plugin-owned semantic validation.
func EncodeActionCheckResult(v ActionCheckResult) ([]byte, error) {
	if v.Schema != 1 || v.RequestDigest.IsZero() || !v.PayloadBounds.validRange() || !v.Accepted && v.PayloadBounds != (PayloadBounds{}) {
		return nil, ErrProtocol
	}
	b := resultHeader(v.Schema, v.RequestDigest, v.Accepted)
	b = binary.BigEndian.AppendUint32(b, v.PayloadBounds.Minimum)
	return binary.BigEndian.AppendUint32(b, v.PayloadBounds.Maximum), nil
}

// DecodeActionCheckResult checks complete framing and message shape, refusing trailing data.
// The result contains no borrowed byte fields.
func DecodeActionCheckResult(b []byte) (ActionCheckResult, error) {
	if len(b) > MaximumActionCheckResultBytes {
		return ActionCheckResult{}, ErrCapacity
	}
	r := reader{b: b}
	s, d, a := readResultHeader(&r)
	v := ActionCheckResult{s, d, a, PayloadBounds{r.u32(), r.u32()}}
	if r.end() != nil {
		return ActionCheckResult{}, ErrProtocol
	}
	if _, err := EncodeActionCheckResult(v); err != nil {
		return ActionCheckResult{}, err
	}
	return v, nil
}

// ValidateActionCheckPolicy binds exact policy identity and bytes to a structurally
// valid request. The plugin remains responsible for policy meaning.
func ValidateActionCheckPolicy(v ActionCheckRequest, p Policy) error {
	d, err := PolicyDigest(v.DomainID, p)
	if err != nil || !v.Valid() || v.PolicyContractID != p.ContractID || v.PolicyDigest != d {
		return ErrProtocol
	}
	return nil
}

// ValidateActionCheckResult checks result structure and accepted payload bounds.
// It does not bind RequestDigest and does not validate a refused request; use
// ValidateActionCheckResponse for request, policy and response binding.
func ValidateActionCheckResult(request ActionCheckRequest, result ActionCheckResult) error {
	if _, err := EncodeActionCheckResult(result); err != nil {
		return err
	}
	if result.Accepted && ValidatePayloadBounds(request, result.PayloadBounds) != nil {
		return ErrProtocol
	}
	return nil
}

// ActionCheck returns a public action-check projection without validating v.
// The returned TargetData still aliases the command; retain it unchanged through use.
func (v Command) ActionCheck() ActionCheckRequest {
	mode := uint8(OwnershipQualified)
	if createAction(v.Action) {
		mode = OwnershipNone
	} else if v.Action == ActionDeleteReservedSlot {
		mode = OwnershipUncertain
	}
	return ActionCheckRequest{Schema: 1, Action: v.Action, DomainID: v.DomainID, DescriptorID: v.DescriptorID, PolicyDigest: v.PolicyDigest, OwnedInstanceDigest: v.OwnedInstanceDigest(), UncertainCreateAttemptID: v.UncertainCreateAttemptID, ExclusiveNamespaceDigest: v.ExclusiveNamespaceDigest,
		Target: v.Target, OwnedInstance: v.OwnedInstance, PolicyContractID: v.PolicyContractID, OwnershipMode: mode, ConditionalTokenLength: uint16(len(v.ConditionalToken)), PayloadLengthMode: v.PayloadLengthMode, PayloadLength: v.PayloadLength, DeadlineUnixMillis: v.DeadlineUnixMillis}
}

// ValidateNormalizeResult validates request/result structure and the exact request
// digest for checkID. It does not establish canonical plugin-owned semantics.
func ValidateNormalizeResult(checkID ID, request NormalizeRequest, result NormalizeResult) error {
	b, err := EncodeNormalizeRequest(request)
	if err != nil {
		return err
	}
	digest, err := PublicRequestDigest(checkID, KindNormalizeRequest, b, nil)
	if err != nil {
		return err
	}
	if _, err = EncodeNormalizeResult(result); err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return ErrProtocol
	}
	return nil
}

// ValidateCanonicalResult validates request/result structure and the exact request
// digest for checkID. It does not establish the truth of plugin acceptance.
func ValidateCanonicalResult(checkID ID, request CanonicalRequest, result CanonicalResult) error {
	b, err := EncodeCanonicalRequest(request)
	if err != nil {
		return err
	}
	digest, err := PublicRequestDigest(checkID, KindCanonicalRequest, b, nil)
	if err != nil {
		return err
	}
	if _, err = EncodeCanonicalResult(result); err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return ErrProtocol
	}
	return nil
}

// ValidateInterpretResponse validates the request, result compatibility and exact
// request digest for checkID. It does not prove target semantics or service access.
func ValidateInterpretResponse(checkID ID, request InterpretRequest, result InterpretResult) error {
	b, err := EncodeInterpretRequest(request)
	if err != nil {
		return err
	}
	digest, err := PublicRequestDigest(checkID, KindInterpretRequest, b, nil)
	if err != nil {
		return err
	}
	if err = ValidateInterpretResult(request, result); err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return ErrProtocol
	}
	return nil
}

// ValidateActionCheckResponse validates request, policy, result bounds and exact
// request digest for checkID, including policy bytes. It grants no effect permission.
func ValidateActionCheckResponse(checkID ID, request ActionCheckRequest, policy Policy, result ActionCheckResult) error {
	b, err := EncodeActionCheckRequest(request)
	if err != nil {
		return err
	}
	if ValidateActionCheckPolicy(request, policy) != nil {
		return ErrProtocol
	}
	digest, err := PublicRequestDigest(checkID, KindActionCheckRequest, b, policy.Data)
	if err != nil {
		return err
	}
	if err = ValidateActionCheckResult(request, result); err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return ErrProtocol
	}
	return nil
}

// ValidateActionPayload preserves unknown length, exact empty value and metadata absence.
func ValidateActionPayload(action Action, target Target, mode uint8, length uint32) error {
	if !action.Valid() || !target.Valid() || !target.Capabilities.Has(action) || mode != LengthAbsent && mode != LengthExact || mode == LengthAbsent && length != 0 || mode == LengthExact && (!valueAction(action) || !target.payloadBounds(action).contains(length)) {
		return ErrProtocol
	}
	return nil
}
