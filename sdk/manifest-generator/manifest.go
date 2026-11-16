// Package manifest defines bounded consumption projections, borrowed renderer
// views and author callbacks. A projection grants no Reader authority or provider
// capability. Common validation does not establish format correctness.
//
// Callbacks run synchronously. They must leave borrowed input unchanged, retain
// no input aliases and join all users before return. Successful settings and
// artifact results transfer independent complete allocations to the caller,
// which clears their full capacity after use. Contexts must be nonnil.
package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"unicode/utf8"
)

// Common schema, evidence label and byte/count ceilings apply to all formats.
// MaxRawSet and MaxOutputBytes bound aggregate plain and destination data;
// PlainWindowBytes bounds each indexed copy, not a complete plain value.
const (
	Schema                      = "ENKV/CONSUMPTION-PROJECTION/v1"
	EvidenceLimit               = "authorized-input-and-exact-bytes"
	MaxArtifactBytes     uint64 = 246313668
	MaxEntries                  = 512
	MaxNameBytes                = 256
	MaxContractBytes            = 256
	MaxSettingsBytes            = 16384
	MaxRawValue                 = 65536
	MaxRawSet                   = 8 << 20
	MaxDestinations             = 1024
	MaxEntryDestinations        = 8
	MaxTargetDataBytes          = 4096
	MaxLocatorBytes             = 1024
	MaxPolicyBytes              = 524546
	MaxOutputBytes              = 36 << 20
	PlainWindowBytes            = 49152
	MaxQuotedTextBytes          = 2048
	QuotedTokenBytes            = 12290
)

// ID is a 32-byte identity. Required identities must be nonzero.
type ID [32]byte

// IsZero reports whether all identity bytes are zero.
func (id ID) IsZero() bool { return id == ID{} }

// TargetMode records how the target Recipient was selected.
type TargetMode string

// EntryMode records whether selection used all authorized entries or exact names.
type EntryMode string

// ExclusionReason records why a resolved entry is absent from Entries.
type ExclusionReason string

// Selection modes, exclusion reasons, entry kinds and payload encodings are
// closed values. Secret entries contain destination references, not secret bytes.
const (
	CurrentAuthority  TargetMode      = "current-authority"
	ExactRecipient    TargetMode      = "exact-recipient"
	AllAuthorized     EntryMode       = "all-authorized"
	ExactNames        EntryMode       = "exact-names"
	NoOutput          ExclusionReason = "no-output"
	NoMatchingService ExclusionReason = "no-matching-service"
	Plain             uint8           = 1
	Secret            uint8           = 2
	EncodingRaw       uint8           = 1
	EncodingBase64    uint8           = 2
)

// Selection records the request modes; it does not grant authorization.
// Its zero value is invalid.
type Selection struct {
	TargetMode TargetMode `json:"target_mode"`
	EntryMode  EntryMode  `json:"entry_mode"`
}

// Valid reports whether both selection modes are supported.
func (s Selection) Valid() bool {
	return (s.TargetMode == CurrentAuthority || s.TargetMode == ExactRecipient) && (s.EntryMode == AllAuthorized || s.EntryMode == ExactNames)
}

// Observation identifies the observed domain, HEAD revision and snapshot.
// All three identities must be nonzero in a valid projection.
type Observation struct{ DomainID, HEADRevisionID, SnapshotID ID }

// EntryIdentity identifies one resolved entry by exact name and incarnation.
type EntryIdentity struct {
	Name               string
	EntryIncarnationID ID
}

// ExcludedEntry records one resolved entry omitted from the included partition.
// NoMatchingService requires a service filter in the projection.
type ExcludedEntry struct {
	Name               string
	EntryIncarnationID ID
	Reason             ExclusionReason
}

// Destination owns public reference, target and policy facts for one secret
// entry. The plugin owns the meaning of its contract IDs and opaque byte fields.
// EntryIncarnationID must match the containing entry. When PolicyPresent is
// false, policy contract, bytes and digest must be empty or zero.
type Destination struct {
	DestinationID, ServiceContractID, ConsumerLocator, TargetContractID, CanonicalTarget string
	TargetData                                                                           []byte
	PolicyContractID                                                                     string
	PolicyData                                                                           []byte
	BindingIncarnationID, EntryIncarnationID, PolicyDigest                               ID
	PayloadEncoding                                                                      uint8
	PolicyPresent                                                                        bool
}

// Entry owns either a Plain value with nil Destinations, or Secret destination
// references with nil PlainValue. An empty plain value is valid.
type Entry struct {
	Name               string
	EntryIncarnationID ID
	Kind               uint8
	PlainValue         []byte
	Destinations       []Destination
}

// Projection owns all mutable backing, including Settings, ServiceFilter and
// nested entry/destination slices. Freeze it through each synchronous borrower,
// then clear and release owned backing only after those borrowers have returned.
// Settings holds plugin-canonical JSON. ResolvedEntries is the exact sorted union
// of Entries and ExcludedEntries; all three slices must be nonnil, even if empty.
// Entries and exclusions are sorted by name; destinations are sorted by ID.
// ServiceFilter is nil when absent; a present filter applies to secret destinations.
// The zero value is invalid. These facts contain no secret values or credentials.
type Projection struct {
	Schema, FormatContractID, ConfigContractID string
	Settings                                   []byte
	Selection                                  Selection
	ServiceFilter                              *string
	Observation                                Observation
	TargetRecipientID                          ID
	ResolvedEntries                            []EntryIdentity
	Entries                                    []Entry
	ExcludedEntries                            []ExcludedEntry
}

// Failure is a closed failure code. The empty value means success; it carries
// no arbitrary error text and does not implement error.
type Failure string

// Failure codes distinguish invalid structure, invalid text, finite bounds,
// cancellation, deadline expiry and invalid callback returns.
const (
	InvalidInput  Failure = "invalid-input"
	InvalidUTF8   Failure = "invalid-utf8"
	LimitExceeded Failure = "limit-exceeded"
	Cancelled     Failure = "cancelled"
	Expired       Failure = "expired"
	InvalidResult Failure = "invalid-result"
)

// Valid reports whether f is success or a supported failure code.
func (f Failure) Valid() bool {
	return f == "" || f == InvalidInput || f == InvalidUTF8 || f == LimitExceeded || f == Cancelled || f == Expired || f == InvalidResult
}

// Identity binds the family protocol and canonical pre-build descriptor. It
// does not identify the final executable or authorize installation.
type Identity struct{ ProtocolID, DescriptorID ID }

// SettingsRequest borrows JSON settings for the synchronous validator call.
// The callback must not change or retain Settings. Canonical requires validation
// of the exact existing bytes, with no new defaults or replacement spelling.
// Contract IDs declare the plugin-owned format and settings semantics.
type SettingsRequest struct {
	FormatContractID, ConfigContractID string
	Canonical                          bool
	Settings                           []byte
}

// SettingsResult transfers owned canonical JSON settings with len == cap.
// The callback must not return or retain an alias of borrowed request settings.
// On failure, Settings must be nil. The zero value is not a valid result.
// The receiver clears the full returned capacity, including on invalid results.
type SettingsResult struct {
	Settings []byte
	Failure  Failure
}

// SettingsValidator validates plugin settings and applies defaults only to
// noncanonical input. It obeys SettingsRequest borrowing and SettingsResult
// transfer rules and returns Cancelled or Expired when its context ends.
type SettingsValidator func(context.Context, SettingsRequest) SettingsResult

// Renderer borrows a frozen View until return and constructs a complete
// format-specific artifact. It must join all work and retain no view or result
// aliases. It returns Cancelled or Expired when its context ends.
type Renderer func(context.Context, View) Result

// Implementation supplies both required author callbacks. Use native.Bind to
// attach checked startup identity before native serving. Its zero value cannot serve.
type Implementation struct {
	ValidateFormatSettings SettingsValidator
	Render                 Renderer
}

// Result transfers one complete artifact with 1 through MaxArtifactBytes bytes
// and len == cap, or a supported Failure with nil Artifact. Its zero value is
// invalid. The author retains no aliases and joins all users before returning.
// The receiver clears the full returned capacity, including on invalid results.
// A valid result shape does not prove format validity or correspondence.
type Result struct {
	Artifact []byte
	Failure  Failure
}

// Metadata records the exact byte length and SHA-256 digest of an artifact.
// It carries no format or semantic evidence.
type Metadata struct {
	Length uint64
	Digest [32]byte
}

// ValidateSettings checks the JSON encoding, UTF-8 and MaxSettingsBytes bound.
// It does not check plugin grammar, canonical spelling or defaults, and does not
// change or retain the borrowed bytes. Empty input is invalid.
func ValidateSettings(settings []byte) Failure {
	if len(settings) > MaxSettingsBytes {
		return LimitExceeded
	}
	if !utf8.Valid(settings) {
		return InvalidUTF8
	}
	if !json.Valid(settings) {
		return InvalidInput
	}
	return ""
}

// ValidateSettingsRequest checks nonempty bounded contract IDs and the common
// settings encoding. It does not check supported contracts or interpret Canonical.
func ValidateSettingsRequest(r SettingsRequest) Failure {
	for _, s := range []string{r.FormatContractID, r.ConfigContractID} {
		if f := textFailure(s, MaxContractBytes, false); f != "" {
			return f
		}
	}
	return ValidateSettings(r.Settings)
}

// ValidateSettingsResult checks the closed result shape, exact capacity and common
// JSON encoding. It does not check plugin semantics, input equality or hidden aliases.
func ValidateSettingsResult(r SettingsResult) Failure {
	if !r.Failure.Valid() {
		return InvalidResult
	}
	if r.Failure != "" {
		if r.Settings != nil {
			return InvalidResult
		}
		return ""
	}
	if len(r.Settings) != cap(r.Settings) {
		return InvalidResult
	}
	if ValidateSettings(r.Settings) != "" {
		return InvalidResult
	}
	return ""
}

// ValidateResult checks return shape only. It does not establish format validity
// or semantic correspondence, or reveal hidden aliases and allocations.
func ValidateResult(r Result) Failure {
	if !r.Failure.Valid() {
		return InvalidResult
	}
	if r.Failure != "" {
		if r.Artifact != nil {
			return InvalidResult
		}
		return ""
	}
	if len(r.Artifact) == 0 || len(r.Artifact) != cap(r.Artifact) || uint64(len(r.Artifact)) > MaxArtifactBytes {
		return InvalidResult
	}
	return ""
}

// MeasureArtifact borrows unchanged artifact bytes and derives exact delivery
// metadata without interpreting a format. It checks nonempty length and the common
// ceiling, but not capacity or ownership. It returns zero metadata on failure,
// including InvalidInput for a nil context, Cancelled or Expired.
func MeasureArtifact(ctx context.Context, artifact []byte) (Metadata, Failure) {
	if f := contextFailure(ctx); f != "" {
		return Metadata{}, f
	}
	if len(artifact) == 0 || uint64(len(artifact)) > MaxArtifactBytes {
		return Metadata{}, InvalidResult
	}
	h := sha256.New()
	for at := 0; at < len(artifact); {
		if f := contextFailure(ctx); f != "" {
			return Metadata{}, f
		}
		end := min(at+PlainWindowBytes, len(artifact))
		_, _ = h.Write(artifact[at:end])
		at = end
	}
	if f := contextFailure(ctx); f != "" {
		return Metadata{}, f
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return Metadata{Length: uint64(len(artifact)), Digest: digest}, ""
}
func contextFailure(ctx context.Context) Failure {
	if ctx == nil {
		return InvalidInput
	}
	value := reflect.ValueOf(ctx)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return InvalidInput
	}
	return FailureFromContextError(ctx.Err())
}

// FailureFromContextError maps a context Err result to the closed cancellation
// failure. It compares the original context sentinels directly: a wrapped or
// other nonnil error means Cancelled. Callers retain their own nil-context policy.
func FailureFromContextError(err error) Failure {
	switch err {
	case nil:
		return ""
	case context.DeadlineExceeded:
		return Expired
	default:
		return Cancelled
	}
}
