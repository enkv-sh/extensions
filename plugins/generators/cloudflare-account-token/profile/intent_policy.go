package profile

import "slices"

// Policy is one independent copy of an already validated intent policy.
// Effect uses EffectAllow or EffectDeny; PermissionGroups contain ASCII hex
// IDs. Callers may mutate the returned slices without changing the intent.
type Policy struct {
	Effect           uint8
	PermissionGroups [][32]byte
	Resources        []Resource
}

// Resource pairs a ResourceAccount, ResourceZone or ResourceAccountZones kind
// with a 32-byte lowercase ASCII hex tag.
type Resource struct {
	Kind uint8
	ID   [32]byte
}

// CopyPolicy exposes public intent facts without sharing the intent's arrays.
func (v Intent) CopyPolicy(index int) (Policy, bool) {
	if index < 0 || index >= len(v.policies) {
		return Policy{}, false
	}
	row := v.policies[index]
	out := Policy{Effect: row.effect, PermissionGroups: slices.Clone(row.permissions), Resources: make([]Resource, len(row.resources))}
	for i, resource := range row.resources {
		out.Resources[i] = Resource{Kind: resource.kind, ID: resource.tag}
	}
	return out, true
}
