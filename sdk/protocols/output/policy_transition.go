package output

import "encoding/binary"

// PolicyActionRequest asks which existing action can apply a changed policy
// when the owned value is equal. PreviousPolicyDigest is optional qualified
// evidence, not an assertion about its policy language. The policy is carried
// in a separate frame. TargetData borrows the decoded request until return.
type PolicyActionRequest struct {
	Schema                                                     uint16
	DeadlineUnixMillis                                         uint64
	DomainID, DescriptorID, PreviousPolicyDigest, PolicyDigest ID
	HasPreviousPolicyDigest                                    bool
	PolicyContractID                                           string
	Target                                                     Target
}

// PolicyActionResult binds a closed action choice or refusal to RequestDigest.
// Acceptance grants no authority to prepare or send the chosen action.
type PolicyActionResult struct {
	Schema        uint16
	RequestDigest ID
	Accepted      bool
	Action        Action
}

// Valid checks framing facts and canonical optional evidence, not policy meaning.
func (v PolicyActionRequest) Valid() bool {
	return v.Schema == 1 && validDeadline(v.DeadlineUnixMillis) && !v.DomainID.IsZero() && !v.DescriptorID.IsZero() &&
		v.HasPreviousPolicyDigest == !v.PreviousPolicyDigest.IsZero() && !v.PolicyDigest.IsZero() &&
		validText(v.PolicyContractID, MaximumIdentifierBytes) && v.Target.Valid()
}

// EncodePolicyActionRequest validates structure and returns owned request bytes.
func EncodePolicyActionRequest(v PolicyActionRequest) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrProtocol
	}
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = binary.BigEndian.AppendUint64(b, v.DeadlineUnixMillis)
	for _, id := range []ID{v.DomainID, v.DescriptorID, v.PreviousPolicyDigest, v.PolicyDigest} {
		b = append(b, id[:]...)
	}
	if v.HasPreviousPolicyDigest {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendBlob(b, []byte(v.PolicyContractID))
	b = encodeTarget(b, v.Target)
	if len(b) > MaximumPolicyActionRequestBytes {
		return nil, ErrCapacity
	}
	return b, nil
}

// DecodePolicyActionRequest refuses malformed, noncanonical or trailing bytes.
// TargetData borrows b and must remain unchanged through all users.
func DecodePolicyActionRequest(b []byte) (PolicyActionRequest, error) {
	if len(b) > MaximumPolicyActionRequestBytes {
		return PolicyActionRequest{}, ErrCapacity
	}
	r := reader{b: b}
	v := PolicyActionRequest{Schema: r.u16(), DeadlineUnixMillis: r.u64(), DomainID: r.id(), DescriptorID: r.id(), PreviousPolicyDigest: r.id(), PolicyDigest: r.id()}
	present := r.u8()
	v.HasPreviousPolicyDigest = present == 1
	v.PolicyContractID, v.Target = string(r.blob(MaximumIdentifierBytes)), decodeTarget(&r)
	if present > 1 || r.end() != nil || !v.Valid() {
		return PolicyActionRequest{}, ErrProtocol
	}
	return v, nil
}

// EncodePolicyActionResult returns a canonical accepted action or empty refusal.
func EncodePolicyActionResult(v PolicyActionResult) ([]byte, error) {
	if v.Schema != 1 || v.RequestDigest.IsZero() || v.Accepted && v.Action != ActionUpdatePolicy && v.Action != ActionWriteValue || !v.Accepted && v.Action != 0 {
		return nil, ErrProtocol
	}
	return append(resultHeader(v.Schema, v.RequestDigest, v.Accepted), byte(v.Action)), nil
}

// DecodePolicyActionResult checks the exact result width and closed action set.
func DecodePolicyActionResult(b []byte) (PolicyActionResult, error) {
	if len(b) > MaximumPolicyActionResultBytes {
		return PolicyActionResult{}, ErrCapacity
	}
	r := reader{b: b}
	s, d, a := readResultHeader(&r)
	v := PolicyActionResult{Schema: s, RequestDigest: d, Accepted: a, Action: Action(r.u8())}
	if r.end() != nil {
		return PolicyActionResult{}, ErrProtocol
	}
	if _, err := EncodePolicyActionResult(v); err != nil {
		return PolicyActionResult{}, err
	}
	return v, nil
}

// ValidatePolicyActionPolicy binds exact current policy bytes and identity.
func ValidatePolicyActionPolicy(v PolicyActionRequest, p Policy) error {
	d, err := PolicyDigest(v.DomainID, p)
	if err != nil || !v.Valid() || !p.Present() || v.PolicyContractID != p.ContractID || v.PolicyDigest != d {
		return ErrProtocol
	}
	return nil
}

// ValidatePolicyActionResult checks the closed choice and required capabilities.
// Use ValidatePolicyActionResponse to also bind request, policy and correlation.
func ValidatePolicyActionResult(request PolicyActionRequest, result PolicyActionResult) error {
	if !request.Valid() {
		return ErrProtocol
	}
	if _, err := EncodePolicyActionResult(result); err != nil {
		return err
	}
	if result.Accepted && (!request.Target.Capabilities.Has(result.Action) || result.Action == ActionWriteValue && !request.Target.Capabilities.WriteSetsPolicy()) {
		return ErrProtocol
	}
	return nil
}

// ValidatePolicyActionResponse checks exact public request and policy correlation.
func ValidatePolicyActionResponse(checkID ID, request PolicyActionRequest, policy Policy, result PolicyActionResult) error {
	body, err := EncodePolicyActionRequest(request)
	if err != nil {
		return err
	}
	if ValidatePolicyActionPolicy(request, policy) != nil {
		return ErrProtocol
	}
	digest, err := PublicRequestDigest(checkID, KindPolicyActionRequest, body, policy.Data)
	if err != nil {
		return err
	}
	if err = ValidatePolicyActionResult(request, result); err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return ErrProtocol
	}
	return nil
}
