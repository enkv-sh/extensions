package artifact

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// ArchiveFile binds a portable .tar.gz filename to compressed bytes and byte length.
type ArchiveFile struct {
	Filename string `json:"filename"`
	SHA256   Digest `json:"sha256"`
	Length   uint64 `json:"length"`
}

// ArchiveMember binds an allowed top-level archive member name to its exact bytes.
type ArchiveMember struct {
	Name   string `json:"name"`
	Length uint64 `json:"length"`
	SHA256 Digest `json:"sha256"`
}

// ArchiveRecord describes one compressed archive and its sorted unique member set.
// Schema is "enkv/plugin-archive/v1", Purpose is "plugin-archive", and Artifact
// is the canonical metadata digest. Record validation requires plugin, metadata
// and dependency members; extraction and signing trust are separate checks.
type ArchiveRecord struct {
	Schema   string          `json:"schema"`
	Purpose  string          `json:"purpose"`
	Artifact Digest          `json:"artifact"`
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Platform string          `json:"platform"`
	Archive  ArchiveFile     `json:"archive"`
	Members  []ArchiveMember `json:"members"`
}

// Release selects an exact version/platform pair and its metadata identity.
type Release struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Artifact Digest `json:"artifact"`
}

// ReleaseIndex lists at most 256 exact releases for one portable plugin name.
// Schema is "enkv/plugin-index/v1". Releases must be nonnil, ordered by semantic
// version, platform and artifact, with a unique version/platform pair.
type ReleaseIndex struct {
	Schema   string    `json:"schema"`
	Name     string    `json:"name"`
	Releases []Release `json:"releases"`
}

// BuildMarker selects a complete local build. Schema is "enkv/plugin-build/v1"
// and Directory must be "builds/" plus the lowercase Artifact digest.
type BuildMarker struct {
	Schema    string `json:"schema"`
	Artifact  Digest `json:"artifact"`
	Directory string `json:"directory"`
}

// OfficialProof binds an artifact, archive record and both detached signatures by
// digest. Schema is "enkv/plugin-official-proof/v1"; every digest must be nonzero.
// The record does not verify signatures or establish trust roots.
type OfficialProof struct {
	Schema            string `json:"schema"`
	Artifact          Digest `json:"artifact"`
	ArchiveRecord     Digest `json:"archive_record"`
	MetadataSignature Digest `json:"metadata_signature"`
	ArchiveSignature  Digest `json:"archive_signature"`
}

// LocalPlugin maps a portable plugin name to a clean absolute local build directory.
type LocalPlugin struct {
	Name      string `json:"name"`
	Directory string `json:"directory"`
}

// Application lists local plugin overrides for one clean absolute directory.
// Plugins must be nonnil, sorted by unique name, and contain at most 64 entries.
type Application struct {
	Directory string        `json:"directory"`
	Plugins   []LocalPlugin `json:"plugins"`
}

// Settings contains at most 256 application override records under
// "enkv/plugin-settings/v1". Applications must be nonnil and sorted by unique directory.
type Settings struct {
	Schema       string        `json:"schema"`
	Applications []Application `json:"applications"`
}

// Selection binds one named version/platform to its artifact and official proof
// digests. Both digests must be nonzero; decoding does not authenticate the proof.
type Selection struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Artifact Digest `json:"artifact"`
	Proof    Digest `json:"proof"`
}

// SelectionRecord stores at most 64 installed selections for a clean absolute
// Directory under "enkv/plugin-selection/v1". Selections must be nonnil and sorted
// by unique plugin name. It grants no permission to invoke them.
type SelectionRecord struct {
	Schema     string      `json:"schema"`
	Directory  string      `json:"directory"`
	Selections []Selection `json:"selections"`
}

func safeBasename(s string) bool {
	if len(s) == 0 || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
func validMemberName(s string) bool {
	switch s {
	case "plugin", "metadata.json", "metadata.sig", "dependencies.bin", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md":
		return true
	}
	return false
}
func validArchiveRecord(v ArchiveRecord) bool {
	if v.Schema != "enkv/plugin-archive/v1" || v.Purpose != "plugin-archive" || v.Artifact.IsZero() || !ValidVersion(v.Version) || !validPlatform(v.Platform) || !safeArchiveFilename(v.Archive.Filename) || v.Archive.SHA256.IsZero() || v.Archive.Length == 0 || v.Archive.Length > MaxArchiveBytes || v.Members == nil || len(v.Members) > maxArchiveMembers {
		return false
	}
	if !safeBasename(v.Name) {
		return false
	}
	var total uint64
	plugin, metadata, dependency := false, false, false
	for i, r := range v.Members {
		if !validMemberName(r.Name) || r.SHA256.IsZero() || i > 0 && v.Members[i-1].Name >= r.Name || r.Length > MaxArchiveBytes-total {
			return false
		}
		total += r.Length
		switch r.Name {
		case "plugin":
			plugin = true
			if r.Length == 0 || r.Length > MaxExecutableBytes {
				return false
			}
		case "metadata.json":
			metadata = true
			if r.Length == 0 || r.Length > MaxMetadataBytes {
				return false
			}
		case "metadata.sig":
			if r.Length != 64 {
				return false
			}
		case "dependencies.bin":
			dependency = true
			if r.Length == 0 || r.Length > MaxDependencyBytes {
				return false
			}
		}
	}
	return plugin && metadata && dependency
}

// EncodeArchiveRecord validates the bounded ArchiveRecord shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeArchiveRecord(v ArchiveRecord) ([]byte, error) {
	return encodeRecord(v, MaxRecordBytes, validArchiveRecord(v))
}

// DecodeArchiveRecord validates bounded JSON and requires exact canonical bytes.
// Disregard the value on error. Refusals support errors.Is(err, ErrRecord);
// success does not authenticate records or grant operational permission.
func DecodeArchiveRecord(body []byte) (ArchiveRecord, error) {
	var v ArchiveRecord
	if err := decodeRecord(body, MaxRecordBytes, &v); err != nil {
		return v, err
	}
	b, err := EncodeArchiveRecord(v)
	if canonical(body, b, err) != nil {
		return ArchiveRecord{}, ErrRecord
	}
	return v, nil
}
func validReleaseIndex(v ReleaseIndex) bool {
	if v.Schema != "enkv/plugin-index/v1" || v.Releases == nil || len(v.Releases) > maxReleases {
		return false
	}
	if !safeBasename(v.Name) {
		return false
	}
	seen := map[string]bool{}
	for i, r := range v.Releases {
		key := r.Version + "\x00" + r.Platform
		if !ValidVersion(r.Version) || !validPlatform(r.Platform) || r.Artifact.IsZero() || seen[key] {
			return false
		}
		seen[key] = true
		if i > 0 {
			p := v.Releases[i-1]
			c, _ := CompareVersions(p.Version, r.Version)
			if c > 0 || c == 0 && (p.Platform > r.Platform || p.Platform == r.Platform && p.Artifact.String() >= r.Artifact.String()) {
				return false
			}
		}
	}
	return true
}

// EncodeReleaseIndex validates the bounded ReleaseIndex shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeReleaseIndex(v ReleaseIndex) ([]byte, error) {
	return encodeRecord(v, MaxRecordBytes, validReleaseIndex(v))
}

// DecodeReleaseIndex validates bounded JSON and requires exact canonical bytes.
// Disregard the value on error. Refusals support errors.Is(err, ErrRecord);
// success does not authenticate records or grant operational permission.
func DecodeReleaseIndex(body []byte) (ReleaseIndex, error) {
	var v ReleaseIndex
	if err := decodeRecord(body, MaxRecordBytes, &v); err != nil {
		return v, err
	}
	b, err := EncodeReleaseIndex(v)
	if canonical(body, b, err) != nil {
		return ReleaseIndex{}, ErrRecord
	}
	return v, nil
}

// EncodeBuildMarker validates the bounded BuildMarker shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeBuildMarker(v BuildMarker) ([]byte, error) {
	return encodeRecord(v, MaxMarkerBytes, v.Schema == "enkv/plugin-build/v1" && !v.Artifact.IsZero() && v.Directory == "builds/"+v.Artifact.String())
}

// DecodeBuildMarker validates bounded JSON and requires exact canonical bytes.
// Disregard the value on error. Refusals support errors.Is(err, ErrRecord);
// success does not authenticate records or grant operational permission.
func DecodeBuildMarker(body []byte) (BuildMarker, error) {
	var v BuildMarker
	if err := decodeRecord(body, MaxMarkerBytes, &v); err != nil {
		return v, err
	}
	b, err := EncodeBuildMarker(v)
	if canonical(body, b, err) != nil {
		return BuildMarker{}, ErrRecord
	}
	return v, nil
}

// EncodeOfficialProof validates the bounded OfficialProof shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeOfficialProof(v OfficialProof) ([]byte, error) {
	return encodeRecord(v, MaxProofBytes, v.Schema == "enkv/plugin-official-proof/v1" && !v.Artifact.IsZero() && !v.ArchiveRecord.IsZero() && !v.MetadataSignature.IsZero() && !v.ArchiveSignature.IsZero())
}

// DecodeOfficialProof validates bounded JSON and requires exact canonical bytes.
// Disregard the value on error. Refusals support errors.Is(err, ErrRecord);
// success does not authenticate records or grant operational permission.
func DecodeOfficialProof(body []byte) (OfficialProof, error) {
	var v OfficialProof
	if err := decodeRecord(body, MaxProofBytes, &v); err != nil {
		return v, err
	}
	b, err := EncodeOfficialProof(v)
	if canonical(body, b, err) != nil {
		return OfficialProof{}, ErrRecord
	}
	return v, nil
}
func validDirectory(s string) bool {
	return s != "" && len(s) <= 4096 && utf8.ValidString(s) && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsRune(s, 0)
}
func validSettings(v Settings) bool {
	if v.Schema != "enkv/plugin-settings/v1" || v.Applications == nil || len(v.Applications) > maxApplications {
		return false
	}
	for i, a := range v.Applications {
		if !validDirectory(a.Directory) || a.Plugins == nil || len(a.Plugins) > maxApplicationPlugins || i > 0 && v.Applications[i-1].Directory >= a.Directory {
			return false
		}
		for j, p := range a.Plugins {
			if !safeBasename(p.Name) {
				return false
			}
			if !validDirectory(p.Directory) || j > 0 && a.Plugins[j-1].Name >= p.Name {
				return false
			}
		}
	}
	return true
}

// EncodeSettings validates the bounded Settings shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeSettings(v Settings) ([]byte, error) {
	return encodeRecord(v, MaxRecordBytes, validSettings(v))
}

// SettingsLocation identifies a bounded position in an editable settings file.
// Precision is exact for a known token origin or context for an enclosing position.
type SettingsLocation struct {
	Byte      uint32 `json:"byte"`
	Line      uint32 `json:"line"`
	Column    uint32 `json:"column"`
	Precision string `json:"precision"`
}

// SettingsError reports a closed safe content reason without retaining input.
// Location is nil when the decoder did not establish a position.
type SettingsError struct {
	Reason   string
	Location *SettingsLocation
	cause    *recordDecodeFailure
}

func (e *SettingsError) Error() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return "plugin settings invalid"
}
func (e *SettingsError) Unwrap() error {
	if e.cause != nil {
		return e.cause
	}
	return ErrRecord
}

func settingsDecodeError(body []byte, err error) *SettingsError {
	failure := &SettingsError{Reason: "invalid-value"}
	var decode *recordDecodeFailure
	if !errors.As(err, &decode) {
		return failure
	}
	failure.cause = decode
	switch decode.condition {
	case "record exceeds limit", "depth exceeds limit", "string exceeds limit", "vector exceeds limit", "field name exceeds limit":
		failure.Reason = "limit-exceeded"
	case "duplicate field":
		failure.Reason = "duplicate-key"
	case "unknown field":
		failure.Reason = "unknown-field"
	case "invalid JSON", "invalid object", "invalid array", "invalid field name", "trailing data":
		failure.Reason = "invalid-json"
	}
	if decode.offset < 0 || decode.offset > int64(len(body)) || decode.offset > MaxRecordBytes {
		return failure
	}
	line, column := uint32(1), uint32(1)
	for _, b := range body[:decode.offset] {
		if b == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	failure.Location = &SettingsLocation{Byte: uint32(decode.offset), Line: line, Column: column, Precision: decode.precision}
	return failure
}

// DecodeSettings strictly validates editable JSON and normalizes only the owned
// application/plugin list order. Formatting and field order do not change trust.
// Disregard the value on error; refusals support errors.Is(err, ErrRecord).
func DecodeSettings(body []byte) (Settings, error) {
	var v Settings
	if err := decodeRecord(body, MaxRecordBytes, &v); err != nil {
		return Settings{}, settingsDecodeError(body, err)
	}
	slices.SortFunc(v.Applications, func(a, b Application) int { return strings.Compare(a.Directory, b.Directory) })
	for i := range v.Applications {
		slices.SortFunc(v.Applications[i].Plugins, func(a, b LocalPlugin) int { return strings.Compare(a.Name, b.Name) })
	}
	if !validSettings(v) {
		reason := "invalid-value"
		for i, a := range v.Applications {
			if i > 0 && v.Applications[i-1].Directory == a.Directory {
				reason = "duplicate-application"
				break
			}
			for j, p := range a.Plugins {
				if j > 0 && a.Plugins[j-1].Name == p.Name {
					reason = "duplicate-plugin"
					break
				}
			}
			if reason == "duplicate-plugin" {
				break
			}
		}
		return Settings{}, &SettingsError{Reason: reason}
	}
	return v, nil
}
func validSelectionRecord(v SelectionRecord) bool {
	if v.Schema != "enkv/plugin-selection/v1" || !validDirectory(v.Directory) || v.Selections == nil || len(v.Selections) > maxSelections {
		return false
	}
	for i, r := range v.Selections {
		if !safeBasename(r.Name) {
			return false
		}
		if !ValidVersion(r.Version) || !validPlatform(r.Platform) || r.Artifact.IsZero() || r.Proof.IsZero() || i > 0 && v.Selections[i-1].Name >= r.Name {
			return false
		}
	}
	return true
}

// EncodeSelectionRecord validates the bounded SelectionRecord shape and returns canonical JSON.
// Invalid fields or ordering return ErrRecord; inputs are not retained.
func EncodeSelectionRecord(v SelectionRecord) ([]byte, error) {
	return encodeRecord(v, MaxRecordBytes, validSelectionRecord(v))
}

// DecodeSelectionRecord validates bounded JSON and requires exact canonical bytes.
// Disregard the value on error. Refusals support errors.Is(err, ErrRecord);
// success does not authenticate records or grant operational permission.
func DecodeSelectionRecord(body []byte) (SelectionRecord, error) {
	var v SelectionRecord
	if err := decodeRecord(body, MaxRecordBytes, &v); err != nil {
		return v, err
	}
	b, err := EncodeSelectionRecord(v)
	if canonical(body, b, err) != nil {
		return SelectionRecord{}, ErrRecord
	}
	return v, nil
}
