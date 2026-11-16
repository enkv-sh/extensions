package manifest

import (
	"context"
	"unicode/utf8"
)

func textFailure(s string, limit int, empty bool) Failure {
	if len(s) > limit {
		return LimitExceeded
	}
	if !utf8.ValidString(s) {
		return InvalidUTF8
	}
	if !empty && s == "" {
		return InvalidInput
	}
	return ""
}

// Validate enforces the common projection grammar and finite bounds. It does
// not authenticate the input or interpret service, target, policy or format data.
// It borrows p unchanged and returns InvalidInput for a nil context/projection.
// Cancellation returns Cancelled; deadline expiry returns Expired.
func Validate(ctx context.Context, p *Projection) Failure {
	if f := contextFailure(ctx); f != "" {
		return f
	}
	if p == nil || p.Schema != Schema || !p.Selection.Valid() || p.Entries == nil || p.ExcludedEntries == nil || p.ResolvedEntries == nil {
		return InvalidInput
	}
	if f := ValidateSettingsRequest(SettingsRequest{FormatContractID: p.FormatContractID, ConfigContractID: p.ConfigContractID, Canonical: true, Settings: p.Settings}); f != "" {
		return f
	}
	if p.ServiceFilter != nil {
		if f := textFailure(*p.ServiceFilter, MaxContractBytes, false); f != "" {
			return f
		}
	}
	if len(p.Entries) > MaxEntries || len(p.ExcludedEntries) > MaxEntries-len(p.Entries) || len(p.ResolvedEntries) > MaxEntries {
		return LimitExceeded
	}
	if p.Observation.DomainID.IsZero() || p.Observation.HEADRevisionID.IsZero() || p.Observation.SnapshotID.IsZero() || p.TargetRecipientID.IsZero() {
		return InvalidInput
	}
	raw, targets, output := 0, 0, 0
	for i := range p.Entries {
		if f := contextFailure(ctx); f != "" {
			return f
		}
		e := &p.Entries[i]
		if f := textFailure(e.Name, MaxNameBytes, true); f != "" {
			return f
		}
		if e.EntryIncarnationID.IsZero() || i > 0 && p.Entries[i-1].Name >= e.Name {
			return InvalidInput
		}
		switch e.Kind {
		case Plain:
			if e.Destinations != nil {
				return InvalidInput
			}
			if len(e.PlainValue) > MaxRawValue || len(e.PlainValue) > MaxRawSet-raw {
				return LimitExceeded
			}
			raw += len(e.PlainValue)
		case Secret:
			if e.PlainValue != nil || len(e.Destinations) == 0 {
				return InvalidInput
			}
			if len(e.Destinations) > MaxEntryDestinations || len(e.Destinations) > MaxDestinations-targets {
				return LimitExceeded
			}
			targets += len(e.Destinations)
			for j := range e.Destinations {
				d := &e.Destinations[j]
				if d.EntryIncarnationID != e.EntryIncarnationID || d.BindingIncarnationID.IsZero() || j > 0 && e.Destinations[j-1].DestinationID >= d.DestinationID || p.ServiceFilter != nil && d.ServiceContractID != *p.ServiceFilter {
					return InvalidInput
				}
				for _, s := range []string{d.DestinationID, d.ServiceContractID, d.TargetContractID} {
					if f := textFailure(s, MaxContractBytes, false); f != "" {
						return f
					}
					output += len(s)
				}
				for _, s := range []string{d.ConsumerLocator, d.CanonicalTarget} {
					if f := textFailure(s, MaxLocatorBytes, false); f != "" {
						return f
					}
					output += len(s)
				}
				if len(d.TargetData) > MaxTargetDataBytes || len(d.PolicyData) > MaxPolicyBytes {
					return LimitExceeded
				}
				if d.PayloadEncoding != EncodingRaw && d.PayloadEncoding != EncodingBase64 {
					return InvalidInput
				}
				if !d.PolicyPresent {
					if d.PolicyContractID != "" || len(d.PolicyData) != 0 || !d.PolicyDigest.IsZero() {
						return InvalidInput
					}
				} else {
					if f := textFailure(d.PolicyContractID, MaxContractBytes, false); f != "" {
						return f
					}
					if d.PolicyDigest.IsZero() {
						return InvalidInput
					}
				}
				output += len(d.TargetData) + len(d.PolicyContractID) + len(d.PolicyData)
				if output > MaxOutputBytes {
					return LimitExceeded
				}
			}
		default:
			return InvalidInput
		}
	}
	for i, e := range p.ExcludedEntries {
		if f := contextFailure(ctx); f != "" {
			return f
		}
		if f := textFailure(e.Name, MaxNameBytes, true); f != "" {
			return f
		}
		if e.EntryIncarnationID.IsZero() || i > 0 && p.ExcludedEntries[i-1].Name >= e.Name || e.Reason != NoOutput && e.Reason != NoMatchingService || e.Reason == NoMatchingService && p.ServiceFilter == nil {
			return InvalidInput
		}
	}
	if !partitionMatches(p) {
		return InvalidInput
	}
	return contextFailure(ctx)
}

// Merge the sorted included/excluded rows to require an exact resolved partition;
// matching counts alone would permit a missing row to hide behind a duplicate.
func partitionMatches(p *Projection) bool {
	if len(p.ResolvedEntries) != len(p.Entries)+len(p.ExcludedEntries) {
		return false
	}
	included, excluded := 0, 0
	for i, resolved := range p.ResolvedEntries {
		if resolved.EntryIncarnationID.IsZero() || i > 0 && p.ResolvedEntries[i-1].Name >= resolved.Name {
			return false
		}
		for j := 0; j < i; j++ {
			if p.ResolvedEntries[j].EntryIncarnationID == resolved.EntryIncarnationID {
				return false
			}
		}
		var actual EntryIdentity
		if included < len(p.Entries) && (excluded == len(p.ExcludedEntries) || p.Entries[included].Name < p.ExcludedEntries[excluded].Name) {
			e := p.Entries[included]
			actual = EntryIdentity{e.Name, e.EntryIncarnationID}
			included++
		} else {
			e := p.ExcludedEntries[excluded]
			actual = EntryIdentity{e.Name, e.EntryIncarnationID}
			excluded++
		}
		if actual != resolved {
			return false
		}
	}
	return true
}
