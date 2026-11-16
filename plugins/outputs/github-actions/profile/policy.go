package profile

import (
	"encoding/binary"
	protocol "enkv.sh/sdk/protocols/output"
)

// Policy modes encode absent, all-repository, private-repository and explicit
// selected-repository visibility. Only organization destinations have policy.
const (
	PolicyNone uint8 = iota
	PolicyWholeScope
	PolicyRestrictedScope
	PolicyExplicitSet
)

// Subject kinds distinguish no subjects from numeric IDs. Text subjects are
// not accepted. MaximumSelectedRepositories is a local encoding bound.
const (
	SubjectNone uint8 = iota
	SubjectNumber
	SubjectText
	MaximumSelectedRepositories = 65535
)

// Policy is the GitHub organization visibility rule, owned by this plugin.
// The zero value means no policy. Organization policy uses ClassID
// github-actions/org-visibility and one nonzero mode. Explicit sets use
// SubjectNumber and sorted, distinct positive NumberSubjects; other modes use
// SubjectNone and no subjects. TextSubjects are unsupported. Struct copies share
// slice storage; treat policy input as immutable during calls.
type Policy struct {
	ClassID           string
	Mode, SubjectKind uint8
	NumberSubjects    []uint64
	TextSubjects      []string
}

// EncodePolicy returns owned canonical bytes, or nil for the zero policy. It
// borrows input slices only for the call; invalid policies return ErrProfile.
func EncodePolicy(v Policy) ([]byte, error) {
	if v.ClassID == "" && v.Mode == 0 && v.SubjectKind == 0 && len(v.NumberSubjects) == 0 && len(v.TextSubjects) == 0 {
		return nil, nil
	}
	if v.ClassID != orgPolicyClass || len(v.TextSubjects) != 0 || len(v.NumberSubjects) > MaximumSelectedRepositories {
		return nil, ErrProfile
	}
	switch v.Mode {
	case PolicyWholeScope, PolicyRestrictedScope:
		if v.SubjectKind != SubjectNone || len(v.NumberSubjects) != 0 {
			return nil, ErrProfile
		}
	case PolicyExplicitSet:
		if v.SubjectKind != SubjectNumber || len(v.NumberSubjects) == 0 {
			return nil, ErrProfile
		}
	default:
		return nil, ErrProfile
	}
	b := []byte{0, 1, v.Mode}
	b = binary.BigEndian.AppendUint16(b, uint16(len(v.NumberSubjects)))
	for i, id := range v.NumberSubjects {
		if id == 0 || i > 0 && v.NumberSubjects[i-1] >= id {
			return nil, ErrProfile
		}
		b = binary.BigEndian.AppendUint64(b, id)
	}
	return b, nil
}

// PublicPolicy wraps newly encoded bytes with PolicyContractID, or returns an
// absent protocol policy for the zero value. Refusals return ErrProfile.
func PublicPolicy(v Policy) (protocol.Policy, error) {
	b, err := EncodePolicy(v)
	if err != nil {
		return protocol.Policy{}, err
	}
	if len(b) == 0 {
		return protocol.Policy{}, nil
	}
	return protocol.Policy{ContractID: PolicyContractID, Data: b}, nil
}

// ParsePolicy validates the exact public policy and allocates independent
// numeric subjects. It retains no input aliases. An absent policy returns zero;
// invalid identities, lengths or order return ErrProfile.
func ParsePolicy(v protocol.Policy) (Policy, error) {
	if v.ContractID == "" && len(v.Data) == 0 {
		return Policy{}, nil
	}
	b := v.Data
	if v.ContractID != PolicyContractID || len(b) < 5 || binary.BigEndian.Uint16(b) != 1 {
		return Policy{}, ErrProfile
	}
	mode := b[2]
	count := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) != 5+count*8 {
		return Policy{}, ErrProfile
	}
	p := Policy{ClassID: orgPolicyClass, Mode: mode}
	if mode == PolicyExplicitSet {
		p.SubjectKind = SubjectNumber
	}
	if count > 0 {
		p.NumberSubjects = make([]uint64, count)
	}
	for n := range count {
		p.NumberSubjects[n] = binary.BigEndian.Uint64(b[5+n*8:])
	}
	if _, err := EncodePolicy(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// SelectPolicyAction chooses the existing action needed for the desired
// organization policy. A zero prior digest means no qualified prior evidence.
// Only a positive fixed-policy match identifies prior all/private visibility;
// other selected inputs retain the guarded selected-repository operation.
func SelectPolicyAction(domain, previousDigest protocol.ID, current protocol.Policy) (protocol.Action, error) {
	policy, err := ParsePolicy(current)
	if err != nil || domain.IsZero() || policy.Mode == PolicyNone {
		return 0, ErrProfile
	}
	if policy.Mode == PolicyWholeScope || policy.Mode == PolicyRestrictedScope {
		return protocol.ActionWriteValue, nil
	}
	for _, mode := range []uint8{PolicyWholeScope, PolicyRestrictedScope} {
		known, err := PublicPolicy(Policy{ClassID: orgPolicyClass, Mode: mode, SubjectKind: SubjectNone})
		if err != nil {
			return 0, err
		}
		digest, err := protocol.PolicyDigest(domain, known)
		if err != nil {
			return 0, err
		}
		if previousDigest == digest {
			return protocol.ActionWriteValue, nil
		}
	}
	return protocol.ActionUpdatePolicy, nil
}
