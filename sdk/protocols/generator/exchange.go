package generator

import "encoding/binary"

// NormalizeRequest carries Schema, a positive signed-range Unix-millisecond
// deadline, nonzero configuration contract and bounded public JSON Settings.
// Set InputDigest with NormalizeInputDigest before encoding. Decoding borrows Settings.
type NormalizeRequest struct {
	Schema                        uint16
	DeadlineUnixMillis            uint64
	ConfigContractID, InputDigest ID
	Settings                      []byte
}

// NormalizeInputDigest validates the request inputs and hashes schema, deadline,
// configuration contract and exact settings bytes. InputDigest itself is excluded.
// It checks deadline range, not wall-clock expiry or plugin semantics.
func NormalizeInputDigest(v NormalizeRequest) (ID, error) {
	if v.Schema != Schema || !deadlineValid(v.DeadlineUnixMillis) || v.ConfigContractID.IsZero() || !validJSON(v.Settings) {
		return ID{}, ErrProtocol
	}
	if len(v.Settings) > MaximumSettingsInputLength {
		return ID{}, ErrCapacity
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, v.ConfigContractID[:]...)
	b = appendBlob(b, v.Settings)
	return digest("ENKV/GENERATOR/v1/normalize-input-v1\x00", b), nil
}

// EncodeNormalizeRequest validates the complete message and returns a new encoded body.
// The supplied input digest must equal the digest of the captured inputs.
func EncodeNormalizeRequest(v NormalizeRequest) ([]byte, error) {
	id, err := NormalizeInputDigest(v)
	if err != nil {
		return nil, err
	}
	if v.InputDigest != id {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, v.ConfigContractID[:]...)
	b = append(b, v.InputDigest[:]...)
	return appendBlob(b, v.Settings), nil
}

// DecodeNormalizeRequest rejects malformed or trailing bytes and checks message relations.
// Settings borrows b; retain b unchanged until all users finish.
func DecodeNormalizeRequest(b []byte) (NormalizeRequest, error) {
	if len(b) > MaximumPublicBody {
		return NormalizeRequest{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := NormalizeRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), ConfigContractID: r.id(), InputDigest: r.id(), Settings: r.blob(MaximumSettingsInputLength)}
	if err := r.end(); err != nil {
		return NormalizeRequest{}, err
	}
	id, err := NormalizeInputDigest(v)
	if err != nil {
		return NormalizeRequest{}, err
	}
	if v.InputDigest != id {
		return NormalizeRequest{}, ErrProtocol
	}
	return v, nil
}

// NormalizeResponse binds an accept/refuse claim to a nonzero InputDigest.
// Accepted requires a structurally valid encoded Intent; refusal requires empty
// Intent. Decoding borrows Intent. The caller compares the expected input digest.
type NormalizeResponse struct {
	Schema      uint16
	InputDigest ID
	Accepted    bool
	Intent      []byte
}

// EncodeNormalizeResponse validates the complete message and returns a new encoded body.
// The caller must bind InputDigest to the corresponding request.
func EncodeNormalizeResponse(v NormalizeResponse) ([]byte, error) {
	if v.Schema != Schema || v.InputDigest.IsZero() || v.Accepted != (len(v.Intent) > 0) {
		return nil, ErrProtocol
	}
	if v.Accepted {
		if _, err := DecodeIntent(v.Intent); err != nil {
			return nil, err
		}
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = append(b, v.InputDigest[:]...)
	b = append(b, boolByte(v.Accepted))
	return appendBlob(b, v.Intent), nil
}

// DecodeNormalizeResponse rejects malformed or trailing bytes and checks message relations.
// Intent borrows b; retain b unchanged until all users finish.
func DecodeNormalizeResponse(b []byte) (NormalizeResponse, error) {
	if len(b) > MaximumPublicBody {
		return NormalizeResponse{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := NormalizeResponse{Schema: r.u16(), InputDigest: r.id()}
	tag := r.u8()
	v.Accepted = tag == 1
	v.Intent = r.blob(MaximumIntentLength)
	if err := r.end(); err != nil {
		return NormalizeResponse{}, err
	}
	if tag > 1 {
		return NormalizeResponse{}, ErrProtocol
	}
	if _, err := EncodeNormalizeResponse(v); err != nil {
		return NormalizeResponse{}, err
	}
	return v, nil
}

// CanonicalPurpose identifies the semantic claim requested for exact intent.
type CanonicalPurpose uint8

const (
	// CanonicalHistorical checks exact intent without requiring effect callbacks.
	CanonicalHistorical CanonicalPurpose = 1
	// CanonicalFreshCreate also checks the callbacks needed for a new CREATE.
	CanonicalFreshCreate CanonicalPurpose = 2
)

// CanonicalRequest asks whether exact encoded Intent is acceptable. Use Schema
// and a positive signed-range Unix-millisecond deadline, then set InputDigest with
// CanonicalInputDigest. Decoding borrows Intent; acceptance must not rewrite it.
type CanonicalRequest struct {
	Schema             uint16
	DeadlineUnixMillis uint64
	Purpose            CanonicalPurpose
	InputDigest        ID
	Intent             []byte
}

// CanonicalInputDigest validates schema, purpose, deadline range and encoded
// intent, then hashes those inputs without InputDigest. It does not check current time.
func CanonicalInputDigest(v CanonicalRequest) (ID, error) {
	if v.Schema != Schema || !deadlineValid(v.DeadlineUnixMillis) || v.Purpose != CanonicalHistorical && v.Purpose != CanonicalFreshCreate {
		return ID{}, ErrProtocol
	}
	if _, err := DecodeIntent(v.Intent); err != nil {
		return ID{}, err
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, byte(v.Purpose))
	b = appendBlob(b, v.Intent)
	return digest("ENKV/GENERATOR/v1/canonical-input-v2\x00", b), nil
}

// EncodeCanonicalRequest validates the complete message and returns a new encoded body.
// The supplied input digest must equal the digest of the captured inputs.
func EncodeCanonicalRequest(v CanonicalRequest) ([]byte, error) {
	id, err := CanonicalInputDigest(v)
	if err != nil {
		return nil, err
	}
	if v.InputDigest != id {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, byte(v.Purpose))
	b = append(b, v.InputDigest[:]...)
	return appendBlob(b, v.Intent), nil
}

// DecodeCanonicalRequest rejects malformed or trailing bytes and checks message relations.
// Intent borrows b; retain b unchanged until all users finish.
func DecodeCanonicalRequest(b []byte) (CanonicalRequest, error) {
	if len(b) > MaximumPublicBody {
		return CanonicalRequest{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := CanonicalRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), Purpose: CanonicalPurpose(r.u8()), InputDigest: r.id(), Intent: r.blob(MaximumIntentLength)}
	if err := r.end(); err != nil {
		return CanonicalRequest{}, err
	}
	id, err := CanonicalInputDigest(v)
	if err != nil {
		return CanonicalRequest{}, err
	}
	if v.InputDigest != id {
		return CanonicalRequest{}, ErrProtocol
	}
	return v, nil
}

// ValidationResponse carries Schema, a nonzero InputDigest and an accept/refuse
// claim. The caller must compare its expected input digest; no effect is permitted.
type ValidationResponse struct {
	Schema      uint16
	InputDigest ID
	Accepted    bool
}

// EncodeValidationResponse validates the complete message and returns a new encoded body.
// The caller must bind InputDigest to the corresponding request.
func EncodeValidationResponse(v ValidationResponse) ([]byte, error) {
	if v.Schema != Schema || v.InputDigest.IsZero() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = append(b, v.InputDigest[:]...)
	return append(b, boolByte(v.Accepted)), nil
}

// DecodeValidationResponse rejects malformed or trailing bytes and checks message relations.
// The result contains no borrowed byte fields; compare the expected InputDigest.
func DecodeValidationResponse(b []byte) (ValidationResponse, error) {
	r := messageReader{body: b}
	v := ValidationResponse{Schema: r.u16(), InputDigest: r.id()}
	tag := r.u8()
	v.Accepted = tag == 1
	if err := r.end(); err != nil {
		return ValidationResponse{}, err
	}
	if tag > 1 {
		return ValidationResponse{}, ErrProtocol
	}
	if _, err := EncodeValidationResponse(v); err != nil {
		return ValidationResponse{}, err
	}
	return v, nil
}

// RetirementCompatibilityRequest asks whether the exact managed Intent and
// OriginalFacts can support the selected completion class. Use Schema and a
// positive signed-range Unix-millisecond deadline, then set InputDigest with
// RetirementCompatibilityInputDigest. Decoding borrows both byte fields.
type RetirementCompatibilityRequest struct {
	Schema                uint16
	DeadlineUnixMillis    uint64
	InputDigest           ID
	CompletionClass       uint8
	Intent, OriginalFacts []byte
}

// RetirementCompatibilityInputDigest validates managed create facts against the
// intent and completion class, then hashes the exact inputs except InputDigest.
// It checks structure, not provider compatibility or current time.
func RetirementCompatibilityInputDigest(v RetirementCompatibilityRequest) (ID, error) {
	if v.Schema != Schema || !deadlineValid(v.DeadlineUnixMillis) || (v.CompletionClass != CompletionAcknowledged && v.CompletionClass != CompletionConfirmed) {
		return ID{}, ErrProtocol
	}
	intent, err := DecodeIntent(v.Intent)
	if err != nil {
		return ID{}, err
	}
	facts, err := DecodeSafeFacts(v.OriginalFacts)
	if err != nil {
		return ID{}, err
	}
	id, err := IntentDigest(v.Intent)
	if err != nil || intent.LifecycleMode != LifecycleManaged || facts.Action != ActionCreate || facts.LifecycleMode != LifecycleManaged || facts.ResourceContractID != intent.ResourceContractID || facts.IntentDigest != id || (facts.Disposition != DispositionCompleteCreate && facts.Disposition != DispositionOwnedUnusableCreate) {
		return ID{}, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, v.CompletionClass)
	b = appendBlob(b, v.Intent)
	b = appendBlob(b, v.OriginalFacts)
	return digest("ENKV/GENERATOR/v1/retirement-compatibility-v1\x00", b), nil
}

// EncodeRetirementCompatibilityRequest validates the complete message and returns a new encoded body.
// The supplied input digest must equal the digest of the captured inputs.
func EncodeRetirementCompatibilityRequest(v RetirementCompatibilityRequest) ([]byte, error) {
	id, err := RetirementCompatibilityInputDigest(v)
	if err != nil {
		return nil, err
	}
	if v.InputDigest != id {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, v.InputDigest[:]...)
	b = append(b, v.CompletionClass)
	b = appendBlob(b, v.Intent)
	return appendBlob(b, v.OriginalFacts), nil
}

// DecodeRetirementCompatibilityRequest rejects malformed or trailing bytes and checks message relations.
// Intent and OriginalFacts borrows b; retain b unchanged until all users finish.
func DecodeRetirementCompatibilityRequest(b []byte) (RetirementCompatibilityRequest, error) {
	if len(b) > MaximumPublicBody {
		return RetirementCompatibilityRequest{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := RetirementCompatibilityRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), InputDigest: r.id(), CompletionClass: r.u8(), Intent: r.blob(MaximumIntentLength), OriginalFacts: r.blob(MaximumSafeFactsBody)}
	if err := r.end(); err != nil {
		return RetirementCompatibilityRequest{}, err
	}
	id, err := RetirementCompatibilityInputDigest(v)
	if err != nil {
		return RetirementCompatibilityRequest{}, err
	}
	if v.InputDigest != id {
		return RetirementCompatibilityRequest{}, ErrProtocol
	}
	return v, nil
}
func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
