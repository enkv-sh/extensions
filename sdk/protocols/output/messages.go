package output

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unicode/utf8"
)

const (
	// ResultSchema is the closed result-body schema, independent of the frame version.
	ResultSchema uint16 = 1
	// HelloBytes is the exact encoded Hello body size in bytes.
	HelloBytes = 96
	// MaximumIdentifierBytes bounds each semantic identifier in UTF-8 bytes.
	MaximumIdentifierBytes = 256
	// MaximumCoordinateBytes bounds each coordinate, instance, token or locator in UTF-8 bytes.
	MaximumCoordinateBytes = 1024
	// MaximumSafeIDBytes bounds each public safe provider identifier in UTF-8 bytes.
	MaximumSafeIDBytes = 1024
	// ActionCreateEmpty creates a target without a value payload.
	ActionCreateEmpty Action = 1
	// ActionCreateWithValue creates a target with an exact value payload.
	ActionCreateWithValue Action = 2
	// ActionWriteValue writes an exact value to an owned target.
	ActionWriteValue Action = 3
	// ActionUpdatePolicy updates policy on an owned target.
	ActionUpdatePolicy Action = 4
	// ActionDeleteOwned deletes one qualified owned instance.
	ActionDeleteOwned Action = 5
	// ActionDeleteReservedSlot deletes a qualified reserved slot after uncertain creation.
	ActionDeleteReservedSlot Action = 6
	// EntryNotEntered claims that provider-effect entry did not occur.
	EntryNotEntered EntryState = 1
	// EntryMayHaveEntered records that provider-effect entry may have occurred.
	EntryMayHaveEntered EntryState = 2
	// ClassUnproved carries no qualified provider evidence; status and safe fields are empty.
	ClassUnproved OutcomeClass = 0
	// ClassAcknowledged claims provider acknowledgement; it does not prove a selected state change.
	ClassAcknowledged OutcomeClass = 1
	// ClassQualifiedNoEffect claims qualified no effect under the plugin response contract.
	ClassQualifiedNoEffect OutcomeClass = 2
	// LengthAbsent means no payload for metadata actions, or unknown length in passive value checks.
	LengthAbsent uint8 = 0
	// LengthExact declares exact encoded payload bytes, including an empty value.
	LengthExact uint8 = 1
	// OwnershipNone is the create action-check ownership arm.
	OwnershipNone uint8 = 0
	// OwnershipQualified is the qualified owned-instance action-check arm.
	OwnershipQualified uint8 = 1
	// OwnershipUncertain is the uncertain reserved-slot action-check arm.
	OwnershipUncertain uint8 = 2
)

// Hello binds nonzero protocol, descriptor and artifact-contract identities.
// The peer must compare them with its independently expected identities.
type Hello struct{ ProtocolID, DescriptorID, ArtifactContractID ID }

// EncodeHello validates message structure and returns a new bounded body.
// Input buffers are not retained; no provider semantics or effect is verified.
func EncodeHello(v Hello) ([]byte, error) {
	if v.ProtocolID.IsZero() || v.DescriptorID.IsZero() || v.ArtifactContractID.IsZero() {
		return nil, ErrProtocol
	}
	b := append([]byte(nil), v.ProtocolID[:]...)
	b = append(b, v.DescriptorID[:]...)
	return append(b, v.ArtifactContractID[:]...), nil
}

// DecodeHello validates the complete bounded body and refuses trailing bytes.
// The returned value does not retain b.
func DecodeHello(b []byte) (Hello, error) {
	if len(b) != HelloBytes {
		return Hello{}, ErrProtocol
	}
	r := reader{b: b}
	v := Hello{r.id(), r.id(), r.id()}
	if _, err := EncodeHello(v); err != nil {
		return Hello{}, err
	}
	return v, nil
}

// Command contains admitted public facts only. Schema is 1; DeadlineUnixMillis
// is a positive signed-range Unix-millisecond deadline. Value actions require
// LengthExact and a value-basis digest; metadata actions require LengthAbsent.
// Create, owned and reserved-slot actions use distinct birth/ownership fields.
// Target, policy and credential identities bind separately. Decoding borrows
// Target.TargetData. A command grants no send permission by itself.
type Command struct {
	Schema                                                                                                          uint16
	Action                                                                                                          Action
	DomainID, OperationID, AttemptID, CoordinateID                                                                  ID
	ProjectionCommitment, DispatchContextDigest                                                                     ID
	RequestContractDigest, ResponseContractDigest, DescriptorID, CredentialRouteID                                  ID
	PolicyDigest, BindingIncarnationID, EntryIncarnationID, TargetRowDigest                                         ID
	BirthTargetRowDigest, OwnedBirthAttemptID, UncertainCreateAttemptID, ExclusiveNamespaceDigest, ValueBasisDigest ID
	DeadlineUnixMillis                                                                                              uint64
	PayloadLengthMode                                                                                               uint8
	PayloadLength                                                                                                   uint32
	BindingDestinationID, OwnedInstance, ConditionalToken                                                           string
	PolicyContractID                                                                                                string
	Target                                                                                                          Target
}

func validText(s string, maximum int) bool {
	return len(s) > 0 && len(s) <= maximum && utf8.ValidString(s)
}
func validOptionalText(s string, maximum int) bool { return len(s) <= maximum && utf8.ValidString(s) }
func validDeadline(v uint64) bool                  { return v > 0 && v <= math.MaxInt64 }
func valueAction(v Action) bool                    { return v == ActionCreateWithValue || v == ActionWriteValue }
func createAction(v Action) bool                   { return v == ActionCreateEmpty || v == ActionCreateWithValue }

// Valid checks schema 1, deadline range, identities, action/ownership relations,
// target capabilities, policy presence and exact payload bounds. It does not
// check current time, credentials, permission or plugin-owned target semantics.
func (v Command) Valid() bool {
	if v.Schema != 1 || v.Action < ActionCreateEmpty || v.Action > ActionDeleteReservedSlot || !validDeadline(v.DeadlineUnixMillis) || !v.Target.Valid() || !v.Target.Capabilities.Has(v.Action) ||
		!validText(v.BindingDestinationID, MaximumIdentifierBytes) || !validOptionalText(v.OwnedInstance, MaximumCoordinateBytes) || !validOptionalText(v.ConditionalToken, MaximumCoordinateBytes) ||
		!validOptionalText(v.PolicyContractID, MaximumIdentifierBytes) || v.PayloadLength > MaximumPayloadBytes {
		return false
	}
	for _, id := range []ID{v.DomainID, v.OperationID, v.AttemptID, v.CoordinateID, v.ProjectionCommitment, v.DispatchContextDigest, v.RequestContractDigest,
		v.ResponseContractDigest, v.DescriptorID, v.CredentialRouteID, v.BindingIncarnationID, v.EntryIncarnationID, v.TargetRowDigest} {
		if id.IsZero() {
			return false
		}
	}
	value, create, reserved := valueAction(v.Action), createAction(v.Action), v.Action == ActionDeleteReservedSlot
	if value && v.PayloadLengthMode != LengthExact || !value && (v.PayloadLengthMode != LengthAbsent || v.PayloadLength != 0) || value != !v.ValueBasisDigest.IsZero() || value && !v.Target.payloadBounds(v.Action).contains(v.PayloadLength) {
		return false
	}
	if (create || reserved) != (v.OwnedInstance == "") || (create || reserved) != v.OwnedBirthAttemptID.IsZero() || (create || reserved) != v.BirthTargetRowDigest.IsZero() ||
		reserved != (!v.UncertainCreateAttemptID.IsZero() && !v.ExclusiveNamespaceDigest.IsZero()) || !reserved && (!v.UncertainCreateAttemptID.IsZero() || !v.ExclusiveNamespaceDigest.IsZero()) {
		return false
	}
	if (v.PolicyContractID == "") != v.PolicyDigest.IsZero() || v.Action == ActionUpdatePolicy && v.PolicyDigest.IsZero() || v.Action >= ActionDeleteOwned && !v.PolicyDigest.IsZero() {
		return false
	}
	return true
}
func commandIDs(v Command) []ID {
	return []ID{v.DomainID, v.OperationID, v.AttemptID, v.CoordinateID, v.ProjectionCommitment, v.DispatchContextDigest, v.RequestContractDigest,
		v.ResponseContractDigest, v.DescriptorID, v.CredentialRouteID, v.PolicyDigest, v.BindingIncarnationID, v.EntryIncarnationID, v.TargetRowDigest, v.BirthTargetRowDigest,
		v.OwnedBirthAttemptID, v.UncertainCreateAttemptID, v.ExclusiveNamespaceDigest, v.ValueBasisDigest}
}

// EncodeCommand validates message structure and returns a new bounded body.
// Input buffers are not retained; no provider semantics or effect is verified.
func EncodeCommand(v Command) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = append(b, byte(v.Action))
	for _, id := range commandIDs(v) {
		b = append(b, id[:]...)
	}
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	b = append(b, v.PayloadLengthMode)
	b = binary.BigEndian.AppendUint32(b, v.PayloadLength)
	for _, s := range []string{v.BindingDestinationID, v.OwnedInstance, v.ConditionalToken, v.PolicyContractID} {
		b = appendBlob(b, []byte(s))
	}
	b = encodeTarget(b, v.Target)
	if len(b) > MaximumCommandBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// DecodeCommand validates the complete bounded body and refuses trailing bytes.
// Target.TargetData borrows b; retain b unchanged through all borrowers.
func DecodeCommand(b []byte) (Command, error) {
	if len(b) > MaximumCommandBytes {
		return Command{}, ErrCapacity
	}
	r := reader{b: b}
	v := Command{Schema: r.u16(), Action: Action(r.u8())}
	for _, id := range []*ID{&v.DomainID, &v.OperationID, &v.AttemptID, &v.CoordinateID, &v.ProjectionCommitment, &v.DispatchContextDigest, &v.RequestContractDigest,
		&v.ResponseContractDigest, &v.DescriptorID, &v.CredentialRouteID, &v.PolicyDigest, &v.BindingIncarnationID, &v.EntryIncarnationID, &v.TargetRowDigest, &v.BirthTargetRowDigest,
		&v.OwnedBirthAttemptID, &v.UncertainCreateAttemptID, &v.ExclusiveNamespaceDigest, &v.ValueBasisDigest} {
		*id = r.id()
	}
	v.DeadlineUnixMillis = r.u64()
	v.PayloadLengthMode = r.u8()
	v.PayloadLength = r.u32()
	v.BindingDestinationID = string(r.blob(MaximumIdentifierBytes))
	v.OwnedInstance = string(r.blob(MaximumCoordinateBytes))
	v.ConditionalToken = string(r.blob(MaximumCoordinateBytes))
	v.PolicyContractID = string(r.blob(MaximumIdentifierBytes))
	v.Target = decodeTarget(&r)
	if r.end() != nil || !v.Valid() {
		return Command{}, ErrProtocol
	}
	return v, nil
}

// OwnedInstanceDigest binds the owned instance to its domain, coordinate and
// birth/incarnation facts. An absent OwnedInstance returns zero. It does not
// validate the command or prove current service ownership.
func (v Command) OwnedInstanceDigest() ID {
	if v.OwnedInstance == "" {
		return ID{}
	}
	b := []byte("ENKV/PUBLICATION/OWNED-INSTANCE/v2\x00")
	for _, id := range []ID{v.DomainID, v.CoordinateID, v.BindingIncarnationID, v.EntryIncarnationID, v.BirthTargetRowDigest, v.OwnedBirthAttemptID} {
		b = append(b, id[:]...)
	}
	return sha256.Sum256(appendBlob(b, []byte(v.OwnedInstance)))
}

// Policy data is canonical and opaque to the family. Empty ContractID is absence.
type Policy struct {
	ContractID string
	Data       []byte
}

// Present reports whether the policy has a contract identity.
func (v Policy) Present() bool { return v.ContractID != "" }

// Valid checks bounded UTF-8 identity, byte capacity and absence consistency.
// It does not interpret or canonicalize policy bytes. The zero policy is absent.
func (v Policy) Valid() bool {
	return validOptionalText(v.ContractID, MaximumIdentifierBytes) && len(v.Data) <= MaximumPolicyBytes && (v.Present() || len(v.Data) == 0)
}

// EncodePolicy returns only data; its contract identity and digest travel in the command.
func EncodePolicy(v Policy) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	return append([]byte{}, v.Data...), nil
}

// DecodePolicy validates the contract and bounded opaque data without copying b.
// Retain b unchanged until every user of the returned policy has finished.
// It checks shape only; canonical policy meaning belongs to the plugin.
func DecodePolicy(contract string, b []byte) (Policy, error) {
	v := Policy{contract, b}
	if len(b) > MaximumPolicyBytes {
		return Policy{}, ErrCapacity
	}
	if !v.Valid() {
		return Policy{}, ErrProtocol
	}
	return v, nil
}

// PolicyDigest validates the domain and policy shape, then hashes the exact
// contract and opaque bytes. An absent policy returns zero; canonical meaning
// remains the plugin's responsibility.
func PolicyDigest(domain ID, v Policy) (ID, error) {
	if domain.IsZero() || !v.Valid() {
		return ID{}, ErrProtocol
	}
	if !v.Present() {
		return ID{}, nil
	}
	b := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domain[:]...)
	b = appendBlob(b, []byte(v.ContractID))
	return sha256.Sum256(appendBlob(b, v.Data)), nil
}

// ValidatePolicy checks command structure and binds the exact policy contract and
// digest to it. It does not interpret policy or establish permission to apply it.
func ValidatePolicy(c Command, p Policy) error {
	d, err := PolicyDigest(c.DomainID, p)
	if err != nil || !c.Valid() || p.ContractID != c.PolicyContractID || d != c.PolicyDigest {
		return ErrProtocol
	}
	return nil
}

// Result contains closed evidence only. Schema is 1 and all correlation fields
// must be nonzero. ClassUnproved carries no status or IDs; acknowledgement
// requires EntryMayHaveEntered and a nonzero normalized status. SafeRequestID and
// SafeResourceID must contain only public safe data. ConsumerLocator is valid only
// for an acknowledged create after ValidateResult. Result grants no retry, adoption
// or state authority and does not prove a service effect.
type Result struct {
	Schema                                                              uint16
	DomainID, OperationID, AttemptID, CoordinateID                      ID
	ProjectionCommitment, DispatchContextDigest, ResponseContractDigest ID
	Entry                                                               EntryState
	Class                                                               OutcomeClass
	NormalizedStatus                                                    uint16
	SafeRequestID, SafeResourceID, ConsumerLocator                      string
}

// NewResult copies command correlation into an incomplete result without
// validating the command. Set entry, class and evidence fields before validation.
func (v Command) NewResult() Result {
	return Result{Schema: ResultSchema, DomainID: v.DomainID, OperationID: v.OperationID, AttemptID: v.AttemptID, CoordinateID: v.CoordinateID,
		ProjectionCommitment: v.ProjectionCommitment, DispatchContextDigest: v.DispatchContextDigest, ResponseContractDigest: v.ResponseContractDigest}
}

// Valid checks closed outcome shape and nonzero result bindings. It does not
// compare a command or verify the truth of provider evidence.
func (v Result) Valid() bool {
	if v.Schema != ResultSchema || !ValidOutcome(v.Entry, v.Class, v.NormalizedStatus, v.SafeRequestID, v.SafeResourceID, v.ConsumerLocator) {
		return false
	}
	for _, id := range []ID{v.DomainID, v.OperationID, v.AttemptID, v.CoordinateID, v.ProjectionCommitment, v.DispatchContextDigest, v.ResponseContractDigest} {
		if id.IsZero() {
			return false
		}
	}
	return true
}

// ValidOutcome checks the closed service evidence shared by author and wire results.
func ValidOutcome(entry EntryState, class OutcomeClass, status uint16, requestID, resourceID, locator string) bool {
	if !entry.Valid() || !class.Valid() || !validOptionalText(requestID, MaximumSafeIDBytes) || !validOptionalText(resourceID, MaximumSafeIDBytes) || !validOptionalText(locator, MaximumCoordinateBytes) {
		return false
	}
	if class == ClassUnproved && (status != 0 || requestID != "" || resourceID != "" || locator != "") {
		return false
	}
	if class != ClassAcknowledged && locator != "" {
		return false
	}
	return class != ClassAcknowledged || entry == EntryMayHaveEntered && status != 0
}

// EncodeResult validates message structure and returns a new bounded body.
// Input buffers are not retained; no provider semantics or effect is verified.
func EncodeResult(v Result) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	for _, id := range []ID{v.DomainID, v.OperationID, v.AttemptID, v.CoordinateID, v.ProjectionCommitment, v.DispatchContextDigest, v.ResponseContractDigest} {
		b = append(b, id[:]...)
	}
	b = append(b, byte(v.Entry), byte(v.Class))
	b = binary.BigEndian.AppendUint16(b, v.NormalizedStatus)
	for _, s := range []string{v.SafeRequestID, v.SafeResourceID, v.ConsumerLocator} {
		b = appendBlob(b, []byte(s))
	}
	if len(b) > MaximumResultBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// DecodeResult validates the complete bounded body and refuses trailing bytes.
// The returned value does not retain b.
func DecodeResult(b []byte) (Result, error) {
	if len(b) > MaximumResultBytes {
		return Result{}, ErrCapacity
	}
	r := reader{b: b}
	v := Result{Schema: r.u16()}
	for _, id := range []*ID{&v.DomainID, &v.OperationID, &v.AttemptID, &v.CoordinateID, &v.ProjectionCommitment, &v.DispatchContextDigest, &v.ResponseContractDigest} {
		*id = r.id()
	}
	v.Entry = EntryState(r.u8())
	v.Class = OutcomeClass(r.u8())
	v.NormalizedStatus = r.u16()
	v.SafeRequestID = string(r.blob(MaximumSafeIDBytes))
	v.SafeResourceID = string(r.blob(MaximumSafeIDBytes))
	v.ConsumerLocator = string(r.blob(MaximumCoordinateBytes))
	if r.end() != nil || !v.Valid() {
		return Result{}, ErrProtocol
	}
	return v, nil
}

// ValidateResult checks command/result structure and exact correlation. An
// acknowledged create requires a nonempty safe resource ID and a consumer
// locator consistent with its target;
// other actions cannot return a locator. This validates a claim, not its truth.
func ValidateResult(c Command, v Result) error {
	if !c.Valid() || !v.Valid() || v.DomainID != c.DomainID || v.OperationID != c.OperationID || v.AttemptID != c.AttemptID || v.CoordinateID != c.CoordinateID ||
		v.ProjectionCommitment != c.ProjectionCommitment || v.DispatchContextDigest != c.DispatchContextDigest || v.ResponseContractDigest != c.ResponseContractDigest {
		return ErrProtocol
	}
	createAck := createAction(c.Action) && v.Class == ClassAcknowledged
	if createAck {
		if !validText(v.SafeResourceID, MaximumSafeIDBytes) || !validText(v.ConsumerLocator, MaximumCoordinateBytes) || !c.Target.LocatorRequiresCreation && v.ConsumerLocator != c.Target.ConsumerLocator {
			return ErrProtocol
		}
	} else if v.ConsumerLocator != "" {
		return ErrProtocol
	}
	return nil
}

func appendBlob(b, body []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.i {
		r.err = ErrProtocol
		return nil
	}
	b := r.b[r.i : r.i+n : r.i+n]
	r.i += n
	return b
}
func (r *reader) u8() uint8 {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *reader) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *reader) id() ID { var id ID; copy(id[:], r.take(32)); return id }
func (r *reader) blob(maximum int) []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(maximum) {
		r.err = ErrCapacity
		return nil
	}
	return r.take(int(n))
}
func (r *reader) end() error {
	if r.err != nil {
		return r.err
	}
	if r.i != len(r.b) {
		return ErrProtocol
	}
	return nil
}
