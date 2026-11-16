package generator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	// Schema is the generator message-body schema version.
	Schema uint16 = 1
	// ActionCreate requests generation of one value.
	ActionCreate uint8 = 1
	// ActionRetire requests retirement of one exact managed resource.
	ActionRetire uint8 = 2
	// LifecycleNone declares no managed external resource; its resource contract is zero.
	LifecycleNone uint8 = 1
	// LifecycleManaged declares a managed resource with a nonzero resource contract.
	LifecycleManaged uint8 = 2
	// CompletionAcknowledged requires retirement acknowledgement, not controlled invalidation proof.
	CompletionAcknowledged uint8 = 1
	// CompletionConfirmed names controlled confirmation required by the host; a native result alone cannot prove it.
	CompletionConfirmed uint8 = 2
)

const (
	// DispositionCompleteCreate claims a usable generated value and any required managed resource facts.
	DispositionCompleteCreate uint8 = 1
	// DispositionOwnedUnusableCreate claims an owned managed resource without a usable value.
	DispositionOwnedUnusableCreate uint8 = 2
	// DispositionConfirmedNoEffect claims no effect and carries neither value nor owned resource.
	DispositionConfirmedNoEffect uint8 = 3
	// DispositionRetirementAcknowledged claims retirement acknowledgement, not confirmed invalidation.
	DispositionRetirementAcknowledged uint8 = 4
	// DispositionUnknown preserves an unknown effect outcome; it grants no retry.
	DispositionUnknown uint8 = 5
)

const (
	// ReasonNone means no failure reason accompanies the result.
	ReasonNone uint8 = iota
	// ReasonMissingValue reports an owned create with no returned value.
	ReasonMissingValue
	// ReasonInvalidValue reports an unusable returned value.
	ReasonInvalidValue
	// ReasonControls reports resource controls that prevent use.
	ReasonControls
	// ReasonInactive reports an inactive created resource.
	ReasonInactive
	// ReasonMalformed reports malformed effect output.
	ReasonMalformed
	// ReasonOverflow reports a result capacity failure.
	ReasonOverflow
	// ReasonRejected reports a rejected provider operation.
	ReasonRejected
	// ReasonTransport reports a transport failure.
	ReasonTransport
	// ReasonDeadline reports deadline expiry.
	ReasonDeadline
	// ReasonIdentityConflict reports conflicting identity facts.
	ReasonIdentityConflict
)

const (
	// StatusStageHandshake identifies the handshake transport stage.
	StatusStageHandshake uint8 = 1
	// StatusStageEnvironment identifies the private-environment stage.
	StatusStageEnvironment uint8 = 2
	// StatusStageCommand identifies command delivery.
	StatusStageCommand uint8 = 3
	// StatusStageResponse identifies result delivery.
	StatusStageResponse uint8 = 4
	// StatusStageReturn identifies final serving return.
	StatusStageReturn uint8 = 5
	// StatusOK reports no transport failure at the stated stage.
	StatusOK uint16 = 0
	// StatusInvalid reports invalid serving input.
	StatusInvalid uint16 = 1
	// StatusUnavailable reports an unavailable serving dependency.
	StatusUnavailable uint16 = 2
	// StatusCancelled reports serving cancellation.
	StatusCancelled uint16 = 3
	// StatusProtocol reports an invalid exchange.
	StatusProtocol uint16 = 4
)

const (
	// HelloBodyLength is the exact encoded Hello length in bytes.
	HelloBodyLength = 96
	// MaximumIntentLength bounds the complete encoded intent in bytes.
	MaximumIntentLength = 393216
	// MaximumSettingsLength bounds JSON settings bytes inside an encoded intent.
	MaximumSettingsLength = MaximumIntentLength - 71
	// MaximumSettingsInputLength bounds ordinary normalization JSON input bytes.
	MaximumSettingsInputLength = MaximumIntentLength
	// MaximumCommandBody bounds the complete command body, including intent and original facts.
	MaximumCommandBody = 397812
	// MaximumSafeFactsBody bounds all encoded public result facts, including shared framing.
	MaximumSafeFactsBody = 4096
	// SafeFactsFixedLength is the complete common facts framing without variable fields.
	SafeFactsFixedLength = 2 + 4 + 3*32 + 3*4 + 1
	// MaximumSecretLength bounds retained private result bytes. The host enforces
	// the declared input representation and the independent logical content limit.
	MaximumSecretLength = 87384
	// MaximumResultBody bounds the complete result, including facts and private value.
	MaximumResultBody = 138 + MaximumSafeFactsBody + MaximumSecretLength
	// MaximumEnvironmentBody bounds the complete private environment body in bytes.
	MaximumEnvironmentBody = 65536
	// MaximumControlBody bounds a body on the public control channel.
	MaximumControlBody = MaximumCommandBody
	// MaximumPublicBody bounds a passive public-exchange body.
	MaximumPublicBody = MaximumCommandBody
	// MaximumStatusBody is the status-channel read ceiling in bytes, including Hello-sized bodies.
	MaximumStatusBody = HelloBodyLength
	// StatusBodyLength is the exact encoded Status length in bytes.
	StatusBodyLength = 3
)

// Hello binds the protocol, pre-build descriptor and final artifact contract.
// All three identities must be nonzero; the peer must compare expected identities.
type Hello struct{ ProtocolID, DescriptorID, ArtifactContractID ID }

// EncodeHello validates all three nonzero handshake identities and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeHello(v Hello) ([]byte, error) {
	if !idsValid(v.ProtocolID, v.DescriptorID, v.ArtifactContractID) {
		return nil, ErrProtocol
	}
	b := make([]byte, 0, HelloBodyLength)
	for _, id := range [...]ID{v.ProtocolID, v.DescriptorID, v.ArtifactContractID} {
		b = append(b, id[:]...)
	}
	return b, nil
}

// DecodeHello checks the complete body, including trailing-byte refusal.
// The returned value does not retain b.
func DecodeHello(b []byte) (Hello, error) {
	r := messageReader{body: b}
	v := Hello{r.id(), r.id(), r.id()}
	if r.end() != nil || !idsValid(v.ProtocolID, v.DescriptorID, v.ArtifactContractID) {
		return Hello{}, ErrProtocol
	}
	return v, nil
}

// Intent contains semantic settings only. Schema is Schema; ConfigContractID is
// nonzero. LifecycleNone requires a zero ResourceContractID; LifecycleManaged
// requires a nonzero one. Settings is valid UTF-8 JSON bounded by
// MaximumSettingsLength. Decoding borrows Settings; build and credential route
// are separate from intent.
type Intent struct {
	Schema             uint16
	ConfigContractID   ID
	LifecycleMode      uint8
	ResourceContractID ID
	Settings           []byte
}

func (v Intent) valid() bool {
	return v.Schema == Schema && !v.ConfigContractID.IsZero() && lifecycleValid(v.LifecycleMode, v.ResourceContractID) && ValidCanonicalSettings(v.Settings)
}

// EncodeIntent validates schema, lifecycle and bounded JSON settings and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeIntent(v Intent) ([]byte, error) {
	if len(v.Settings) > MaximumSettingsLength {
		return nil, ErrCapacity
	}
	if !v.valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 71+len(v.Settings)), v.Schema)
	b = append(b, v.ConfigContractID[:]...)
	b = append(b, v.LifecycleMode)
	b = append(b, v.ResourceContractID[:]...)
	return appendBlob(b, v.Settings), nil
}

// DecodeIntent checks the complete body, including trailing-byte refusal. Settings borrows b.
// Retain b unchanged through all borrowers; clear private bytes after use.
func DecodeIntent(b []byte) (Intent, error) {
	if len(b) > MaximumIntentLength {
		return Intent{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := Intent{Schema: r.u16(), ConfigContractID: r.id(), LifecycleMode: r.u8(), ResourceContractID: r.id(), Settings: r.blob(MaximumSettingsLength)}
	if err := r.end(); err != nil {
		return Intent{}, err
	}
	if !v.valid() {
		return Intent{}, ErrProtocol
	}
	return v, nil
}

// IntentDigest validates an encoded intent and returns its domain-separated
// identity over the exact bytes. It does not normalize plugin-owned JSON settings.
func IntentDigest(b []byte) (ID, error) {
	if _, err := DecodeIntent(b); err != nil {
		return ID{}, err
	}
	return digest("ENKV/GENERATOR/v1/intent-v3\x00", b), nil
}

// ProtocolID returns the exact identity of generator wire version 5.
func ProtocolID() ID {
	return digest("ENKV/GENERATOR/v1/meaning\x00", appendBlob(nil, []byte("ENKV-GENERATOR-WIRE/v5")))
}

// Command carries admitted public create or retire facts. Schema is Schema and
// DeadlineUnixMillis is a positive signed-range Unix-millisecond deadline. Intent
// and OriginalFacts borrow their backing when constructed or decoded. Intent
// identity, lifecycle and resource contract must agree; retire requires matching
// managed create facts, while create forbids original facts. Structural validity
// does not grant effect permission or establish provider credentials.
type Command struct {
	Schema                                                                          uint16
	Action                                                                          uint8
	DeadlineUnixMillis                                                              uint64
	DomainID, OperationID, RequestIdentityDigest, PlanGraphID, LineageID, AttemptID ID
	TransmissionID, ResultID, ResultContractID, DescriptorID, ExecutorID            ID
	RequestDigest, IntentDigest, ResourceContractID, CredentialRouteID              ID
	LifecycleMode                                                                   uint8
	Intent, OriginalFacts                                                           []byte
}

func commandError(field, condition string, cause error) error {
	return fmt.Errorf("generator command: %s: %s: %w", field, condition, cause)
}

// ValidateCommand checks structural command facts before encoding or execution.
// It checks required identities, deadline range, canonical-intent digest and
// create/retire resource relations. It does not check wall-clock expiry or provider
// semantics. Errors identify safe fields and support errors.Is with ErrProtocol
// or ErrCapacity.
func ValidateCommand(v Command) error {
	if len(v.Intent) > MaximumIntentLength {
		return commandError("intent", "exceeds limit", ErrCapacity)
	}
	if len(v.OriginalFacts) > MaximumSafeFactsBody {
		return commandError("original_facts", "exceeds limit", ErrCapacity)
	}
	if v.Schema != Schema {
		return commandError("schema", "unsupported", ErrProtocol)
	}
	if !deadlineValid(v.DeadlineUnixMillis) {
		return commandError("deadline_unix_millis", "invalid", ErrProtocol)
	}
	for _, field := range []struct {
		name string
		id   ID
	}{
		{"domain_id", v.DomainID}, {"operation_id", v.OperationID}, {"request_identity_digest", v.RequestIdentityDigest},
		{"plan_graph_id", v.PlanGraphID}, {"lineage_id", v.LineageID}, {"attempt_id", v.AttemptID},
		{"transmission_id", v.TransmissionID}, {"result_id", v.ResultID}, {"result_contract_id", v.ResultContractID},
		{"descriptor_id", v.DescriptorID}, {"executor_id", v.ExecutorID}, {"request_digest", v.RequestDigest},
		{"intent_digest", v.IntentDigest}, {"credential_route_id", v.CredentialRouteID},
	} {
		if field.id.IsZero() {
			return commandError(field.name, "required", ErrProtocol)
		}
	}
	intent, err := DecodeIntent(v.Intent)
	if err != nil {
		return commandError("intent", "invalid encoding", ErrProtocol)
	}
	if intent.LifecycleMode != v.LifecycleMode {
		return commandError("lifecycle_mode", "differs from intent", ErrProtocol)
	}
	if intent.ResourceContractID != v.ResourceContractID {
		return commandError("resource_contract_id", "differs from intent", ErrProtocol)
	}
	intentDigest, err := IntentDigest(v.Intent)
	if err != nil || intentDigest != v.IntentDigest {
		return commandError("intent_digest", "differs from intent", ErrProtocol)
	}
	switch v.Action {
	case ActionCreate:
		if len(v.OriginalFacts) != 0 {
			return commandError("original_facts", "not allowed for create", ErrProtocol)
		}
	case ActionRetire:
		if v.LifecycleMode != LifecycleManaged {
			return commandError("lifecycle_mode", "retirement requires managed resource", ErrProtocol)
		}
		facts, err := DecodeSafeFacts(v.OriginalFacts)
		if err != nil {
			return commandError("original_facts", "invalid encoding", ErrProtocol)
		}
		if facts.Action != ActionCreate || facts.LifecycleMode != LifecycleManaged || facts.IntentDigest != v.IntentDigest || facts.ResourceContractID != v.ResourceContractID || (facts.Disposition != DispositionCompleteCreate && facts.Disposition != DispositionOwnedUnusableCreate) {
			return commandError("original_facts", "not a matching created resource", ErrProtocol)
		}
	default:
		return commandError("action", "unsupported", ErrProtocol)
	}
	return nil
}

// EncodeCommand validates the command relations checked by ValidateCommand and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeCommand(v Command) ([]byte, error) {
	if err := ValidateCommand(v); err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 500+len(v.Intent)+len(v.OriginalFacts)), v.Schema)
	b = append(b, v.Action)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	for _, id := range [...]ID{v.DomainID, v.OperationID, v.RequestIdentityDigest, v.PlanGraphID, v.LineageID, v.AttemptID, v.TransmissionID, v.ResultID, v.ResultContractID, v.DescriptorID, v.ExecutorID, v.RequestDigest, v.IntentDigest, v.ResourceContractID, v.CredentialRouteID} {
		b = append(b, id[:]...)
	}
	b = append(b, v.LifecycleMode)
	b = appendBlob(b, v.Intent)
	return appendBlob(b, v.OriginalFacts), nil
}

// DecodeCommand checks the complete body, including trailing-byte refusal. Intent and OriginalFacts borrow b.
// Retain b unchanged through all borrowers; clear private bytes after use.
func DecodeCommand(b []byte) (Command, error) {
	if len(b) > MaximumCommandBody {
		return Command{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := Command{Schema: r.u16(), Action: r.u8(), DeadlineUnixMillis: r.u64()}
	for _, id := range []*ID{&v.DomainID, &v.OperationID, &v.RequestIdentityDigest, &v.PlanGraphID, &v.LineageID, &v.AttemptID, &v.TransmissionID, &v.ResultID, &v.ResultContractID, &v.DescriptorID, &v.ExecutorID, &v.RequestDigest, &v.IntentDigest, &v.ResourceContractID, &v.CredentialRouteID} {
		*id = r.id()
	}
	v.LifecycleMode = r.u8()
	v.Intent = r.blob(MaximumIntentLength)
	v.OriginalFacts = r.blob(MaximumSafeFactsBody)
	if err := r.end(); err != nil {
		return Command{}, err
	}
	if err := ValidateCommand(v); err != nil {
		return Command{}, err
	}
	return v, nil
}

// SafeFacts carries public claims with no private value or provider-specific union.
// Schema is Schema; action, lifecycle, disposition and reason use the closed
// constants. The three variable fields share MaximumSafeFactsBody with framing.
// Managed complete/owned-unusable creates retain Target and ResourceData; no-effect
// facts retain neither. Retirement acknowledgement carries the exact original
// resource. Decoding borrows all byte fields. ProviderFacts cannot change the
// disposition, grant an effect or supply controlled observation proof.
type SafeFacts struct {
	Schema                                          uint16
	Action, LifecycleMode, Disposition, Reason      uint8
	RequestDigest, IntentDigest, ResourceContractID ID
	Target, ResourceData, ProviderFacts             []byte
}

func (v SafeFacts) valid() bool {
	if v.Schema != Schema || !idsValid(v.RequestDigest, v.IntentDigest) || !lifecycleValid(v.LifecycleMode, v.ResourceContractID) || v.Reason > ReasonIdentityConflict {
		return false
	}
	if v.LifecycleMode == LifecycleNone && (len(v.Target) != 0 || len(v.ResourceData) != 0) {
		return false
	}
	switch v.Action {
	case ActionCreate:
		switch v.Disposition {
		case DispositionCompleteCreate:
			return v.Reason == ReasonNone && (v.LifecycleMode == LifecycleNone || len(v.Target) > 0 && len(v.ResourceData) > 0)
		case DispositionOwnedUnusableCreate:
			return v.LifecycleMode == LifecycleManaged && len(v.Target) > 0 && len(v.ResourceData) > 0 && v.Reason >= ReasonMissingValue && v.Reason <= ReasonInactive
		case DispositionConfirmedNoEffect:
			return len(v.Target) == 0 && len(v.ResourceData) == 0
		case DispositionUnknown:
			return v.Reason >= ReasonMalformed
		}
	case ActionRetire:
		return v.LifecycleMode == LifecycleManaged && len(v.Target) > 0 && len(v.ResourceData) > 0 && (v.Disposition == DispositionRetirementAcknowledged && v.Reason == ReasonNone || v.Disposition == DispositionUnknown && v.Reason >= ReasonMalformed)
	}
	return false
}

// EncodeSafeFacts validates closed disposition/reason and aggregate public-fact bounds and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeSafeFacts(v SafeFacts) ([]byte, error) {
	if len(v.Target)+len(v.ResourceData)+len(v.ProviderFacts) > MaximumSafeFactsBody-SafeFactsFixedLength {
		return nil, ErrCapacity
	}
	if !v.valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(make([]byte, 0, SafeFactsFixedLength+len(v.Target)+len(v.ResourceData)+len(v.ProviderFacts)), v.Schema)
	b = append(b, v.Action, v.LifecycleMode, v.Disposition, v.Reason)
	for _, id := range [...]ID{v.RequestDigest, v.IntentDigest, v.ResourceContractID} {
		b = append(b, id[:]...)
	}
	b = appendBlob(b, v.Target)
	b = appendBlob(b, v.ResourceData)
	b = appendBlob(b, v.ProviderFacts)
	return append(b, 0), nil
}

// DecodeSafeFacts checks the complete body, including trailing-byte refusal. Target, ResourceData and ProviderFacts borrow b.
// Retain b unchanged through all borrowers; clear private bytes after use.
func DecodeSafeFacts(b []byte) (SafeFacts, error) {
	if len(b) > MaximumSafeFactsBody {
		return SafeFacts{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := SafeFacts{Schema: r.u16(), Action: r.u8(), LifecycleMode: r.u8(), Disposition: r.u8(), Reason: r.u8(), RequestDigest: r.id(), IntentDigest: r.id(), ResourceContractID: r.id(), Target: r.blob(MaximumSafeFactsBody - SafeFactsFixedLength), ResourceData: r.blob(MaximumSafeFactsBody - SafeFactsFixedLength), ProviderFacts: r.blob(MaximumSafeFactsBody - SafeFactsFixedLength)}
	if r.u8() != 0 {
		return SafeFacts{}, ErrProtocol
	}
	if err := r.end(); err != nil {
		return SafeFacts{}, err
	}
	if !v.valid() {
		return SafeFacts{}, ErrProtocol
	}
	return v, nil
}

// NewFacts copies command bindings into otherwise incomplete result facts.
// Set the disposition-specific public fields and validate before use; this
// constructor alone does not validate the command or establish effect evidence.
func (v Command) NewFacts(disposition, reason uint8) SafeFacts {
	return SafeFacts{Schema: Schema, Action: v.Action, LifecycleMode: v.LifecycleMode, Disposition: disposition, Reason: reason, RequestDigest: v.RequestDigest, IntentDigest: v.IntentDigest, ResourceContractID: v.ResourceContractID}
}

// Result binds one attempt and executor to public SafeFacts and a private Value.
// Value is nonempty only for a complete create, with at most MaximumSecretLength
// bytes. Decoded byte fields borrow the encoded body; retain it through all users
// and clear it after they finish. Use ValidateResult to bind a result to its command.
type Result struct {
	Schema                                            uint16
	AttemptID, ResultID, ResultContractID, ExecutorID ID
	SafeFacts                                         SafeFacts
	Value                                             []byte
}

// NewResult copies command bindings and borrows facts byte fields and value.
// It performs no validation or copy; retain backing through encoding or execution
// and clear private value bytes after all borrowers finish.
func (v Command) NewResult(facts SafeFacts, value []byte) Result {
	return Result{Schema: Schema, AttemptID: v.AttemptID, ResultID: v.ResultID, ResultContractID: v.ResultContractID, ExecutorID: v.ExecutorID, SafeFacts: facts, Value: value}
}

// EncodeResult validates result shape, facts and private-value bounds and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeResult(v Result) ([]byte, error) {
	if len(v.Value) > MaximumSecretLength {
		return nil, ErrCapacity
	}
	if v.Schema != Schema || !idsValid(v.AttemptID, v.ResultID, v.ResultContractID, v.ExecutorID) || (v.SafeFacts.Disposition == DispositionCompleteCreate) != (len(v.Value) > 0) {
		return nil, ErrProtocol
	}
	facts, err := EncodeSafeFacts(v.SafeFacts)
	if err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 138+len(facts)+len(v.Value)), v.Schema)
	for _, id := range [...]ID{v.AttemptID, v.ResultID, v.ResultContractID, v.ExecutorID} {
		b = append(b, id[:]...)
	}
	b = appendBlob(b, facts)
	return appendBlob(b, v.Value), nil
}

// DecodeResult checks the complete body, including trailing-byte refusal. Value and nested fact byte fields borrow b.
// Retain b unchanged through all borrowers; clear private bytes after use.
func DecodeResult(b []byte) (Result, error) {
	if len(b) > MaximumResultBody {
		return Result{}, ErrCapacity
	}
	r := messageReader{body: b}
	v := Result{Schema: r.u16(), AttemptID: r.id(), ResultID: r.id(), ResultContractID: r.id(), ExecutorID: r.id()}
	facts := r.blob(MaximumSafeFactsBody)
	v.Value = r.blob(MaximumSecretLength)
	if err := r.end(); err != nil {
		return Result{}, err
	}
	var err error
	v.SafeFacts, err = DecodeSafeFacts(facts)
	if err != nil {
		return Result{}, err
	}
	if v.Schema != Schema || !idsValid(v.AttemptID, v.ResultID, v.ResultContractID, v.ExecutorID) || (v.SafeFacts.Disposition == DispositionCompleteCreate) != (len(v.Value) > 0) {
		return Result{}, ErrProtocol
	}
	return v, nil
}

// ValidateResult checks structure, command correlation and the exact original
// resource on retirement. Refusals support errors.Is with ErrProtocol or ErrCapacity.
// A valid provider claim does not establish controlled observation proof.
func ValidateResult(command Command, v Result) error {
	if err := ValidateCommand(command); err != nil {
		return fmt.Errorf("generator result: command: invalid: %w: %w", ErrProtocol, err)
	}
	if len(v.Value) > MaximumSecretLength {
		return ErrCapacity
	}
	if v.Schema != Schema || !idsValid(v.AttemptID, v.ResultID, v.ResultContractID, v.ExecutorID) || (v.SafeFacts.Disposition == DispositionCompleteCreate) != (len(v.Value) > 0) {
		return ErrProtocol
	}
	if _, err := EncodeSafeFacts(v.SafeFacts); err != nil {
		return err
	}
	f := v.SafeFacts
	if v.AttemptID != command.AttemptID || v.ResultID != command.ResultID || v.ResultContractID != command.ResultContractID || v.ExecutorID != command.ExecutorID || f.Action != command.Action || f.LifecycleMode != command.LifecycleMode || f.RequestDigest != command.RequestDigest || f.IntentDigest != command.IntentDigest || f.ResourceContractID != command.ResourceContractID {
		return ErrProtocol
	}
	if command.Action == ActionRetire {
		original, err := DecodeSafeFacts(command.OriginalFacts)
		if err != nil || !bytes.Equal(f.Target, original.Target) || !bytes.Equal(f.ResourceData, original.ResourceData) {
			return ErrProtocol
		}
	}
	return nil
}

// Status reports a closed transport stage and category. It carries no provider
// result or resource evidence; Category StatusOK alone does not establish success.
type Status struct {
	Stage    uint8
	Category uint16
}

// EncodeStatus validates closed stage and category values and returns a new body.
// It does not retain input buffers or establish provider semantics.
func EncodeStatus(v Status) ([]byte, error) {
	if v.Stage < StatusStageHandshake || v.Stage > StatusStageReturn || v.Category > StatusProtocol {
		return nil, ErrProtocol
	}
	return []byte{v.Stage, byte(v.Category >> 8), byte(v.Category)}, nil
}

// DecodeStatus checks the complete body, including trailing-byte refusal.
// The returned value does not retain b.
func DecodeStatus(b []byte) (Status, error) {
	if len(b) != StatusBodyLength {
		return Status{}, ErrProtocol
	}
	v := Status{b[0], binary.BigEndian.Uint16(b[1:])}
	if _, err := EncodeStatus(v); err != nil {
		return Status{}, err
	}
	return v, nil
}

func idsValid(ids ...ID) bool {
	for _, id := range ids {
		if id.IsZero() {
			return false
		}
	}
	return true
}
func deadlineValid(n uint64) bool { return n > 0 && n <= math.MaxInt64 }
func lifecycleValid(mode uint8, resource ID) bool {
	return mode == LifecycleNone && resource.IsZero() || mode == LifecycleManaged && !resource.IsZero()
}
func validJSON(b []byte) bool { return len(b) > 0 && utf8.Valid(b) && json.Valid(b) }
func digest(domain string, b []byte) ID {
	preimage := appendBlob([]byte(domain), b)
	return ID(sha256.Sum256(preimage))
}

type messageReader struct {
	body   []byte
	offset int
	err    error
}

func (r *messageReader) take(n int) []byte {
	if n == 0 && r.err == nil {
		return nil
	}
	if r.err != nil || n < 0 || n > len(r.body)-r.offset {
		r.err = ErrProtocol
		return nil
	}
	b := r.body[r.offset : r.offset+n : r.offset+n]
	r.offset += n
	return b
}
func (r *messageReader) u8() uint8 {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *messageReader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *messageReader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *messageReader) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *messageReader) id() ID { var id ID; copy(id[:], r.take(32)); return id }
func (r *messageReader) blob(max int) []byte {
	n := r.u32()
	if uint64(n) > uint64(max) {
		r.err = ErrCapacity
		return nil
	}
	return r.take(int(n))
}
func (r *messageReader) end() error {
	if r.err != nil {
		return r.err
	}
	if r.offset != len(r.body) {
		return ErrProtocol
	}
	return nil
}
func appendBlob(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}
