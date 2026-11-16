package manifest

import "context"

// View borrows one frozen projection during a synchronous callback. It and its
// child views must not outlive that borrow. Accessors expose scalar facts or copy
// into caller-owned storage; they do not validate the complete projection.
// The zero value has no owner: counts and metadata are zero, indexed lookups
// fail, and copying or validation returns InvalidInput.
type View struct{ owner *Projection }

// EntryView borrows one included entry for the lifetime of its parent View.
// Check Metadata().Kind before using plain-value or destination accessors.
type EntryView struct {
	owner *Projection
	entry int
}

// DestinationView borrows one secret destination for the lifetime of its View.
type DestinationView struct {
	owner              *Projection
	entry, destination int
}

// Header contains immutable header facts by value. HasServiceFilter distinguishes
// an absent filter from ServiceFilter. EvidenceLimit is the common runtime label,
// not a claim that these facts were authenticated by this package.
type Header struct {
	Schema, FormatContractID, ConfigContractID, EvidenceLimit string
	Selection                                                 Selection
	ServiceFilter                                             string
	HasServiceFilter                                          bool
	Observation                                               Observation
	TargetRecipientID                                         ID
}

// EntryMetadata identifies an included entry and its Plain or Secret kind.
type EntryMetadata struct {
	Name               string
	EntryIncarnationID ID
	Kind               uint8
}

// DestinationMetadata contains scalar public destination facts. Use PolicyPresent
// to distinguish an absent policy from a present policy with empty data.
type DestinationMetadata struct {
	DestinationID, ServiceContractID, ConsumerLocator, TargetContractID, CanonicalTarget, PolicyContractID string
	BindingIncarnationID, EntryIncarnationID, PolicyDigest                                                 ID
	PayloadEncoding                                                                                        uint8
	PolicyPresent                                                                                          bool
}

// Borrow creates a view without copying or validating p. The caller keeps p
// and all its backing unchanged until every synchronous borrower returns.
func Borrow(p *Projection) View { return View{p} }

// Validate checks the same common grammar and bounds as Validate on the owner.
func (v View) Validate(ctx context.Context) Failure { return Validate(ctx, v.owner) }

// Header returns scalar header facts, or zero facts for a missing owner/schema.
func (v View) Header() Header {
	if v.owner == nil || v.owner.Schema == "" {
		return Header{}
	}
	p := v.owner
	h := Header{Schema: p.Schema, FormatContractID: p.FormatContractID, ConfigContractID: p.ConfigContractID, EvidenceLimit: EvidenceLimit, Selection: p.Selection, Observation: p.Observation, TargetRecipientID: p.TargetRecipientID}
	if p.ServiceFilter != nil {
		h.ServiceFilter = *p.ServiceFilter
		h.HasServiceFilter = true
	}
	return h
}
func copyWindow(body []byte, offset int, dst []byte) (int, Failure) {
	if offset < 0 || offset > len(body) {
		return 0, InvalidInput
	}
	if len(dst) > PlainWindowBytes {
		return 0, LimitExceeded
	}
	return copy(dst, body[offset:]), ""
}

// SettingsLength returns the settings byte length, or zero for an invalid view.
func (v View) SettingsLength() int {
	if v.owner == nil {
		return 0
	}
	return len(v.owner.Settings)
}

// CopySettings copies a settings window using the CopyPlain offset and buffer
// rules. It does not validate or canonicalize the copied JSON.
func (v View) CopySettings(offset int, dst []byte) (int, Failure) {
	if v.owner == nil {
		return 0, InvalidInput
	}
	return copyWindow(v.owner.Settings, offset, dst)
}

// EntryCount returns the number of included entries, or zero for an invalid view.
func (v View) EntryCount() int {
	if v.owner == nil {
		return 0
	}
	return len(v.owner.Entries)
}

// Entry borrows included entry i. It returns false for an invalid view or index.
func (v View) Entry(i int) (EntryView, bool) {
	if v.owner == nil || i < 0 || i >= len(v.owner.Entries) {
		return EntryView{}, false
	}
	return EntryView{v.owner, i}, true
}

// ExcludedCount returns the number of exclusions, or zero for an invalid view.
func (v View) ExcludedCount() int {
	if v.owner == nil {
		return 0
	}
	return len(v.owner.ExcludedEntries)
}

// Excluded returns exclusion i by value, or false for an invalid view or index.
func (v View) Excluded(i int) (ExcludedEntry, bool) {
	if v.owner == nil || i < 0 || i >= len(v.owner.ExcludedEntries) {
		return ExcludedEntry{}, false
	}
	return v.owner.ExcludedEntries[i], true
}
func (e EntryView) row() *Entry {
	if e.owner == nil || e.entry < 0 || e.entry >= len(e.owner.Entries) {
		return nil
	}
	return &e.owner.Entries[e.entry]
}

// Metadata returns the entry identity and kind, or zero facts for an invalid view.
func (e EntryView) Metadata() EntryMetadata {
	r := e.row()
	if r == nil {
		return EntryMetadata{}
	}
	return EntryMetadata{r.Name, r.EntryIncarnationID, r.Kind}
}

// PlainLength returns the plain-value length. Zero can also mean a Secret entry
// or invalid view; check Metadata().Kind to distinguish an empty plain value.
func (e EntryView) PlainLength() int {
	r := e.row()
	if r == nil || r.Kind != Plain {
		return 0
	}
	return len(r.PlainValue)
}

// CopyPlain copies at most len(dst) plain bytes starting at offset. The entry
// must be Plain, offset must be in [0, PlainLength()], and len(dst) must be at
// most PlainWindowBytes. It returns InvalidInput for an invalid kind/view/offset
// or LimitExceeded for an oversized buffer, before writing. End-of-value returns
// zero with no failure. The unused destination tail is unchanged; no backing is
// allocated. The caller owns and clears dst after its last user returns.
func (e EntryView) CopyPlain(offset int, dst []byte) (int, Failure) {
	r := e.row()
	if r == nil || r.Kind != Plain {
		return 0, InvalidInput
	}
	return copyWindow(r.PlainValue, offset, dst)
}

// CopyPlainValue copies the complete plain value into caller-owned storage.
// Invalid kinds and short destinations refuse before any write. An unused
// destination tail stays unchanged; no backing is allocated. Values above
// MaxRawValue return LimitExceeded before writing. Unlike CopyPlain, dst may
// exceed PlainWindowBytes and must fit the whole value. The caller owns and
// clears dst; the helper does not encode the value or construct an artifact.
func (e EntryView) CopyPlainValue(dst []byte) (int, Failure) {
	r := e.row()
	if r == nil || r.Kind != Plain {
		return 0, InvalidInput
	}
	length := len(r.PlainValue)
	if length > MaxRawValue {
		return 0, LimitExceeded
	}
	if len(dst) < length {
		return 0, InvalidInput
	}
	for at := 0; at < length; {
		end := min(at+PlainWindowBytes, length)
		n, failure := e.CopyPlain(at, dst[at:end])
		if failure != "" {
			return 0, failure
		}
		if n != end-at {
			return 0, InvalidInput
		}
		at = end
	}
	return length, ""
}

// DestinationCount returns the destination count, or zero for an invalid view.
// A valid Plain entry has none; validate the projection before interpreting kind.
func (e EntryView) DestinationCount() int {
	r := e.row()
	if r == nil {
		return 0
	}
	return len(r.Destinations)
}

// Destination borrows destination i, or returns false for an invalid view/index.
// It does not independently enforce the entry-kind grammar.
func (e EntryView) Destination(i int) (DestinationView, bool) {
	r := e.row()
	if r == nil || i < 0 || i >= len(r.Destinations) {
		return DestinationView{}, false
	}
	return DestinationView{e.owner, e.entry, i}, true
}
func (d DestinationView) row() *Destination {
	e := (EntryView{d.owner, d.entry}).row()
	if e == nil || d.destination < 0 || d.destination >= len(e.Destinations) {
		return nil
	}
	return &e.Destinations[d.destination]
}

// Metadata returns scalar destination facts, or zero facts for an invalid view.
func (d DestinationView) Metadata() DestinationMetadata {
	r := d.row()
	if r == nil {
		return DestinationMetadata{}
	}
	return DestinationMetadata{r.DestinationID, r.ServiceContractID, r.ConsumerLocator, r.TargetContractID, r.CanonicalTarget, r.PolicyContractID, r.BindingIncarnationID, r.EntryIncarnationID, r.PolicyDigest, r.PayloadEncoding, r.PolicyPresent}
}

// TargetDataLength returns opaque target-data length, or zero for an invalid view.
func (d DestinationView) TargetDataLength() int {
	r := d.row()
	if r == nil {
		return 0
	}
	return len(r.TargetData)
}

// CopyTargetData copies opaque target bytes using the CopyPlain offset and
// buffer rules. An invalid destination returns InvalidInput before writing.
func (d DestinationView) CopyTargetData(offset int, dst []byte) (int, Failure) {
	r := d.row()
	if r == nil {
		return 0, InvalidInput
	}
	return copyWindow(r.TargetData, offset, dst)
}

// PolicyLength returns opaque policy-data length, or zero for an invalid view.
// Check Metadata().PolicyPresent to determine whether a policy is present.
func (d DestinationView) PolicyLength() int {
	r := d.row()
	if r == nil {
		return 0
	}
	return len(r.PolicyData)
}

// CopyPolicy copies opaque policy bytes using the CopyPlain offset and buffer
// rules. An invalid destination returns InvalidInput before writing.
func (d DestinationView) CopyPolicy(offset int, dst []byte) (int, Failure) {
	r := d.row()
	if r == nil {
		return 0, InvalidInput
	}
	return copyWindow(r.PolicyData, offset, dst)
}
