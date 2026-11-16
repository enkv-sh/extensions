package output

import protocol "enkv.sh/sdk/protocols/output"

// TargetRequest supplies public facts for one entry's target interpretation.
// Destination byte slices are read-only borrows until InterpretTarget returns.
// PayloadEncoding describes the bytes Crypto will prepare, not provider framing.
type TargetRequest struct {
	Destination     protocol.Destination
	EntryName       string
	PayloadEncoding uint8
}

// ActionCheck contains public facts for one prospective action, with no private
// conditional token or payload. ConditionalTokenLength describes the withheld
// token; the ownership IDs describe admitted evidence, not a new service right.
// Target byte slices are read-only borrows until CheckAction returns. Value
// actions require exact target bounds; metadata actions return zero bounds.
type ActionCheck struct {
	Action                                                                  protocol.Action
	Target                                                                  protocol.Target
	OwnedInstance                                                           string
	OwnershipMode                                                           uint8
	OwnedInstanceDigest, UncertainCreateAttemptID, ExclusiveNamespaceDigest protocol.ID
	ConditionalTokenLength                                                  uint16
	PayloadLengthMode                                                       uint8
	PayloadLength                                                           uint32
}

// PolicyActionSelection contains public facts for choosing an action after value
// equality and a policy change. PreviousPolicyDigest is absent when its owner
// cannot be qualified; a nonmatching digest does not identify its policy grammar.
// Target and the accompanying policy are read-only borrows until return.
type PolicyActionSelection struct {
	DomainID                protocol.ID
	Target                  protocol.Target
	HasPreviousPolicyDigest bool
	PreviousPolicyDigest    protocol.ID
}

// Preparation contains the admitted service facts needed by Prepare and Send.
// AttemptID identifies this attempt; it grants no retry. OwnedInstance and
// ConditionalToken are the exact admitted ownership/condition values. Do not log
// ConditionalToken. PayloadLengthMode distinguishes an absent payload from an
// exact length, which can be zero.
//
// Target byte slices, the accompanying policy bytes and private input values are
// read-only borrows through the returned Prepared.Close. They may be used by that
// prepared invocation, but must not outlive it. If no Prepared is returned, their
// use ends at Prepare return. Copy any data needed for a separate lifetime and
// dispose private copies yourself. No payload is available during Prepare.
type Preparation struct {
	Action                          protocol.Action
	Target                          protocol.Target
	AttemptID                       protocol.ID
	OwnedInstance, ConditionalToken string
	PayloadLengthMode               uint8
	PayloadLength                   uint32
}

// Outcome is the author's reduced service evidence; the SDK adds exact command
// correlation. Entry records whether a request may have entered the service and
// Class records the strength of the available evidence. The zero value is invalid.
// NormalizedStatus and the safe IDs must contain only public service evidence,
// never credentials, payloads or raw error text. Unproved outcomes carry none.
// NormalizedStatus is an opaque plugin-owned acknowledgement code, not
// necessarily an HTTP status. Acknowledgement requires a nonzero code.
// Acknowledged creates also require a nonempty SafeResourceID; the SDK enforces
// that requirement when it correlates the outcome with the admitted action.
//
// AssignedLocator is only for acknowledged creates whose target requires an
// assigned locator. Leave it empty for static locators and all other actions.
// Valid checks shape only. The author must establish the service facts; neither
// a valid shape nor a constructor proves that the provider performed an effect.
type Outcome struct {
	Entry                                          protocol.EntryState
	Class                                          protocol.OutcomeClass
	NormalizedStatus                               uint16
	SafeRequestID, SafeResourceID, AssignedLocator string
}

// Acknowledged constructs evidence of service acknowledgement with possible
// effect entry. status must be nonzero; IDs and assignedLocator must satisfy the
// protocol's bounded public-text rules. The SDK checks locator use against the
// admitted action later and requires a nonempty resourceID for acknowledged
// creates. Other actions may omit it. Invalid shape returns a zero Outcome and
// protocol.ErrProtocol.
func Acknowledged(status uint16, requestID, resourceID, assignedLocator string) (Outcome, error) {
	return checkedOutcome(Outcome{Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged, NormalizedStatus: status, SafeRequestID: requestID, SafeResourceID: resourceID, AssignedLocator: assignedLocator})
}

// QualifiedNoEffect constructs an author-qualified no-effect result for entry.
// The author must have service evidence that supports this class; lack of a reply
// alone does not qualify. Invalid shape returns a zero Outcome and protocol.ErrProtocol.
// This result grants no automatic retry, adoption or deletion authority.
func QualifiedNoEffect(entry protocol.EntryState, status uint16, requestID, resourceID string) (Outcome, error) {
	return checkedOutcome(Outcome{Entry: entry, Class: protocol.ClassQualifiedNoEffect, NormalizedStatus: status, SafeRequestID: requestID, SafeResourceID: resourceID})
}

// Unknown constructs an unproved result for entry, with no status, safe IDs or
// locator. entry must be a valid EntryState; otherwise it returns a zero Outcome
// and protocol.ErrProtocol. Unknown grants no resend right.
func Unknown(entry protocol.EntryState) (Outcome, error) {
	return checkedOutcome(Outcome{Entry: entry, Class: protocol.ClassUnproved})
}
func checkedOutcome(v Outcome) (Outcome, error) {
	if !v.Valid() {
		return Outcome{}, protocol.ErrProtocol
	}
	return v, nil
}

// Valid checks the closed outcome shape, including bounds and class relations.
// It checks neither command correlation nor the truth of service evidence.
func (v Outcome) Valid() bool {
	return protocol.ValidOutcome(v.Entry, v.Class, v.NormalizedStatus, v.SafeRequestID, v.SafeResourceID, v.AssignedLocator)
}

func actionFacts(v protocol.ActionCheckRequest) ActionCheck {
	return ActionCheck{Action: v.Action, Target: v.Target, OwnedInstance: v.OwnedInstance, OwnershipMode: v.OwnershipMode, OwnedInstanceDigest: v.OwnedInstanceDigest, UncertainCreateAttemptID: v.UncertainCreateAttemptID, ExclusiveNamespaceDigest: v.ExclusiveNamespaceDigest, ConditionalTokenLength: v.ConditionalTokenLength, PayloadLengthMode: v.PayloadLengthMode, PayloadLength: v.PayloadLength}
}
func preparationFacts(v protocol.Command) Preparation {
	return Preparation{Action: v.Action, Target: v.Target, AttemptID: v.AttemptID, OwnedInstance: v.OwnedInstance, ConditionalToken: v.ConditionalToken, PayloadLengthMode: v.PayloadLengthMode, PayloadLength: v.PayloadLength}
}
func correlateOutcome(c protocol.Command, v Outcome) (protocol.Result, error) {
	if !v.Valid() {
		return protocol.Result{}, protocol.ErrProtocol
	}
	r := c.NewResult()
	r.Entry, r.Class, r.NormalizedStatus, r.SafeRequestID, r.SafeResourceID = v.Entry, v.Class, v.NormalizedStatus, v.SafeRequestID, v.SafeResourceID
	create := c.Action == protocol.ActionCreateEmpty || c.Action == protocol.ActionCreateWithValue
	if v.Class == protocol.ClassAcknowledged && create {
		if c.Target.LocatorRequiresCreation {
			r.ConsumerLocator = v.AssignedLocator
		} else {
			if v.AssignedLocator != "" {
				return protocol.Result{}, protocol.ErrProtocol
			}
			r.ConsumerLocator = c.Target.ConsumerLocator
		}
	} else if v.AssignedLocator != "" {
		return protocol.Result{}, protocol.ErrProtocol
	}
	if err := protocol.ValidateResult(c, r); err != nil {
		return protocol.Result{}, err
	}
	return r, nil
}
