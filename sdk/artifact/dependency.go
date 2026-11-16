package artifact

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"enkv.sh/sdk/artifact/credentialroute"
)

const (
	maxBuildOptions       = 64
	maxContracts          = 64
	maxSourceOwners       = 256
	maxResolvedModules    = 256
	maxCompiledModules    = 256
	maxArchiveMembers     = 8
	maxReleases           = 256
	maxApplications       = 256
	maxApplicationPlugins = 64
	maxSelections         = 64
)

func recordVectorLimit(field string) int {
	switch field {
	case "build_options":
		return maxBuildOptions
	case "contracts":
		return maxContracts
	case "sources":
		return maxSourceOwners
	case "resolved":
		return maxResolvedModules
	case "compiled":
		return maxCompiledModules
	case "members":
		return maxArchiveMembers
	case "releases":
		return maxReleases
	case "applications":
		return maxApplications
	case "plugins":
		return maxApplicationPlugins
	case "selections":
		return maxSelections
	default:
		return 256
	}
}

func encodeRecord(v any, limit int, valid bool) ([]byte, error) {
	if !valid || !boundedValue(reflect.ValueOf(v), "") {
		return nil, ErrRecord
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > limit {
		return nil, ErrRecord
	}
	return b, nil
}

type recordDecodeFailure struct {
	path, condition string
	offset          int64
	precision       string
}

func (e *recordDecodeFailure) Error() string {
	return fmt.Sprintf("artifact decode: %s: %s: %v", e.path, e.condition, ErrRecord)
}
func (e *recordDecodeFailure) Unwrap() error { return ErrRecord }

func recordDecodeError(path, condition string) error {
	return &recordDecodeFailure{path: path, condition: condition, offset: -1}
}
func recordDecodeAt(path, condition string, offset int64, precision string) error {
	return &recordDecodeFailure{path: path, condition: condition, offset: offset, precision: precision}
}
func decodeRecord(body []byte, limit int, v any) error {
	if len(body) > limit {
		return recordDecodeError("record", "record exceeds limit")
	}
	if len(body) == 0 {
		return recordDecodeError("record", "invalid JSON")
	}
	if !utf8.Valid(body) {
		return recordDecodeError("record", "invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := preflight(d, body, reflect.TypeOf(v), "", "record", 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return recordDecodeAt("record", "trailing data", d.InputOffset(), "context")
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return recordDecodeError("record", "invalid typed value")
	}
	if d.Decode(new(any)) != io.EOF {
		return recordDecodeError("record", "trailing data")
	}
	return nil
}

func recordTokenOrigin(body []byte, offset int64) int64 {
	for offset < int64(len(body)) {
		switch body[offset] {
		case ' ', '\t', '\r', '\n', ',', ':':
			offset++
		default:
			return offset
		}
	}
	return offset
}

// encoding/json replaces unpaired surrogate escapes with U+FFFD. Inspect the
// string span consumed by the strict decoder before accepting that conversion.
func validRecordString(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		code, ok := recordHex(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, ok := recordHex(raw[i+3 : i+7])
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
func recordHex(raw []byte) (uint16, bool) {
	var value uint16
	for _, b := range raw {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value += uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			value += uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
func jsonField(t reflect.Type, key string) (reflect.Type, string) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				if typ, canonical := jsonField(embedded, key); typ != nil {
					return typ, canonical
				}
			}
			continue
		}
		if name == "" {
			name = field.Name
		}
		if strings.EqualFold(name, key) {
			return field.Type, name
		}
	}
	return nil, ""
}
func preflight(d *json.Decoder, body []byte, typ reflect.Type, key, path string, depth int) error {
	if depth > 16 {
		return recordDecodeError(path, "depth exceeds limit")
	}
	if typ != nil {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ == reflect.TypeFor[json.RawMessage]() {
			typ = nil
		}
	}
	origin := recordTokenOrigin(body, d.InputOffset())
	token, err := d.Token()
	if err != nil {
		return recordDecodeAt(path, "invalid JSON", origin, "context")
	}
	if _, ok := token.(string); ok && !validRecordString(body[origin:d.InputOffset()]) {
		return recordDecodeAt(path, "invalid Unicode", origin, "exact")
	}
	if value, ok := token.(string); ok && (!utf8.ValidString(value) || len(value) > 4096) {
		return recordDecodeAt(path, "string exceeds limit", origin, "exact")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			fieldOrigin := recordTokenOrigin(body, d.InputOffset())
			token, err := d.Token()
			name, ok := token.(string)
			if err != nil || !ok {
				return recordDecodeError(path, "invalid field name")
			}
			if !validRecordString(body[fieldOrigin:d.InputOffset()]) {
				return recordDecodeAt(path, "invalid Unicode", fieldOrigin, "exact")
			}
			if len(name) > 1024 {
				return recordDecodeAt(path, "field name exceeds limit", fieldOrigin, "exact")
			}
			var fieldType reflect.Type
			fieldPath := path
			if typ != nil {
				if typ.Kind() != reflect.Struct {
					return recordDecodeError(path, "object not allowed")
				}
				var canonical string
				fieldType, canonical = jsonField(typ, name)
				if fieldType == nil {
					return recordDecodeAt(path, "unknown field", fieldOrigin, "exact")
				}
				fieldPath += "." + canonical
				if canonical != name {
					return recordDecodeAt(fieldPath, "noncanonical field", fieldOrigin, "exact")
				}
			}
			if seen[name] {
				return recordDecodeAt(fieldPath, "duplicate field", fieldOrigin, "exact")
			}
			seen[name] = true
			if err := preflight(d, body, fieldType, name, fieldPath, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim('}') {
			return recordDecodeError(path, "invalid object")
		}
	case '[':
		limit := recordVectorLimit(key)
		var element reflect.Type
		if typ != nil {
			if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Array {
				return recordDecodeError(path, "array not allowed")
			}
			element = typ.Elem()
		}
		count := 0
		for d.More() {
			count++
			if count > limit {
				return recordDecodeAt(path, "vector exceeds limit", recordTokenOrigin(body, d.InputOffset()), "exact")
			}
			if err := preflight(d, body, element, key, path, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim(']') {
			return recordDecodeError(path, "invalid array")
		}
	default:
		return recordDecodeError(path, "invalid JSON")
	}
	return nil
}
func boundedValue(v reflect.Value, key string) bool {
	if v.Kind() == reflect.Pointer {
		return v.IsNil() || boundedValue(v.Elem(), key)
	}
	if v.Type() == reflect.TypeFor[json.RawMessage]() {
		return len(v.Bytes()) > 0 && len(v.Bytes()) <= MaxMetadataBytes
	}
	if v.Type() == reflect.TypeFor[[]byte]() {
		return key == "credential_route" && len(v.Bytes()) > 0 && len(v.Bytes()) <= credentialroute.MaxRouteBytes
	}
	switch v.Kind() {
	case reflect.String:
		limit := 1024
		if key == "directory" {
			limit = 4096
		}
		return utf8.ValidString(v.String()) && len(v.String()) <= limit
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !boundedValue(v.Field(i), v.Type().Field(i).Tag.Get("json")) {
				return false
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			return false
		}
		limit := recordVectorLimit(key)
		if v.Len() > limit {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if !boundedValue(v.Index(i), key) {
				return false
			}
		}
	}
	return true
}
func canonical(body, encoded []byte, err error) error {
	if err != nil || !bytes.Equal(body, encoded) {
		return ErrRecord
	}
	return nil
}
func text(s string) bool {
	return s != "" && len(s) <= 1024 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func validPlatform(s string) bool { return s == "darwin/arm64" || s == "linux/amd64" }
func validRole(s string) bool     { return s == "generator" || s == "output" || s == "manifest-generator" }
func validBuildFacts(v BuildFacts) bool {
	if !validRole(v.Role) || !text(v.MainModule) || !text(v.Command) || !validPlatform(v.Platform) || !text(v.Toolchain) || v.BuildOptions == nil || v.Contracts == nil || v.Sources == nil || v.Resolved == nil || v.Compiled == nil || len(v.Compiled) == 0 || len(v.Compiled) > maxCompiledModules || len(v.Resolved) > maxResolvedModules || len(v.Sources) > maxSourceOwners || len(v.Contracts) > maxContracts || len(v.BuildOptions) > maxBuildOptions {
		return false
	}
	for i, r := range v.BuildOptions {
		if !text(r.Name) || !utf8.ValidString(r.Value) || i > 0 && v.BuildOptions[i-1].Name >= r.Name {
			return false
		}
	}
	for i, r := range v.Contracts {
		if !text(r.Identity) || r.Version == 0 || r.Kind != "wire" {
			return false
		}
		d, err := ParseDigest(r.Identity)
		if err != nil || d.IsZero() {
			return false
		}
		if i > 0 {
			p := v.Contracts[i-1]
			if p.Kind > r.Kind || p.Kind == r.Kind && (p.Identity > r.Identity || p.Identity == r.Identity && p.Version >= r.Version) {
				return false
			}
		}
	}
	source := map[string]Digest{}
	for i, r := range v.Sources {
		if !text(r.Module) || r.Digest.IsZero() || i > 0 && v.Sources[i-1].Module >= r.Module {
			return false
		}
		source[r.Module] = r.Digest
	}
	resolved := map[string]Dependency{}
	for i, r := range v.Resolved {
		if !validDependency(r, false) || i > 0 && v.Resolved[i-1].Path >= r.Path {
			return false
		}
		resolved[r.Path] = r
	}
	for path, digest := range source {
		row, ok := resolved[path]
		if !ok {
			return false
		}
		if row.Replacement != nil && row.Replacement.Version == "" && row.Replacement.SourceDigest != digest {
			return false
		}
	}
	for _, row := range v.Resolved {
		if row.Replacement != nil && row.Replacement.Version == "" {
			digest, ok := source[row.Path]
			if !ok || digest != row.Replacement.SourceDigest {
				return false
			}
		}
	}
	hasMain := false
	for i, r := range v.Compiled {
		if !validDependency(r, true) || i > 0 && v.Compiled[i-1].Path >= r.Path {
			return false
		}
		p, ok := resolved[r.Path]
		if !ok || !sameDependency(p, r, r.Path == v.MainModule) {
			return false
		}
		digest, ok := source[r.Path]
		if !ok {
			return false
		}
		if r.Replacement != nil && r.Replacement.Version == "(devel)" && r.Replacement.SourceDigest != digest {
			return false
		}
		if r.Path == v.MainModule {
			hasMain = true
		}
	}
	return hasMain
}
func validDependency(r Dependency, compiled bool) bool {
	if !text(r.Path) || len(r.Version) > 1024 || len(r.Sum) > 1024 {
		return false
	}
	if compiled && r.Version == "" {
		return false
	}
	if r.Version == "(devel)" && !compiled {
		return false
	}
	if r.Version == "" || r.Version == "(devel)" {
		if r.Sum != "" {
			return false
		}
	}
	if r.Replacement != nil {
		p := r.Replacement
		if !text(p.Path) {
			return false
		}
		switch p.Version {
		case "":
			if compiled || p.Sum != "" || p.SourceDigest.IsZero() {
				return false
			}
		case "(devel)":
			if !compiled || p.Sum != "" || p.SourceDigest.IsZero() {
				return false
			}
		default:
			if !text(p.Version) || !text(p.Sum) || !p.SourceDigest.IsZero() {
				return false
			}
		}
	}
	return true
}
func sameDependency(a, b Dependency, main bool) bool {
	if a.Path != b.Path || a.Sum != b.Sum {
		return false
	}
	if a.Version != b.Version && (a.Version != "" || b.Version != "(devel)" || a.Sum != "" || a.Replacement != nil && !main) {
		return false
	}
	if (a.Replacement == nil) != (b.Replacement == nil) {
		return false
	}
	if a.Replacement == nil {
		return true
	}
	x, y := a.Replacement, b.Replacement
	return x.Path == y.Path && x.Sum == y.Sum && x.SourceDigest == y.SourceDigest && (x.Version == y.Version || x.Version == "" && y.Version == "(devel)")
}

// EncodeDependency validates build-fact relations and returns their canonical
// version-3 dependency encoding with a length prefix. It does not measure sources.
func EncodeDependency(v BuildFacts) ([]byte, error) {
	b, err := encodeRecord(v, MaxDependencyBytes-6, validBuildFacts(v))
	if err != nil {
		return nil, err
	}
	body := binary.BigEndian.AppendUint16(nil, 3)
	body = binary.BigEndian.AppendUint32(body, uint32(len(b)))
	return append(body, b...), nil
}

// DecodeDependency checks version, length, canonical encoding and build-fact
// relations. It returns owned record data; refusals support errors.Is(err, ErrRecord).
func DecodeDependency(body []byte) (BuildFacts, error) {
	var v BuildFacts
	if len(body) < 6 || len(body) > MaxDependencyBytes || binary.BigEndian.Uint16(body) != 3 || uint64(binary.BigEndian.Uint32(body[2:])) != uint64(len(body)-6) {
		return v, ErrRecord
	}
	if err := decodeRecord(body[6:], MaxDependencyBytes-6, &v); err != nil {
		return BuildFacts{}, err
	}
	b, err := EncodeDependency(v)
	if canonical(body, b, err) != nil {
		return BuildFacts{}, ErrRecord
	}
	return v, nil
}

// DependencyID validates body for the specified family role and returns its
// domain-separated identity. It differs from Hash(body), the raw member-byte binding.
func DependencyID(role string, body []byte) (Digest, error) {
	if !validRole(role) {
		return Digest{}, ErrRecord
	}
	v, err := DecodeDependency(body)
	if err != nil || v.Role != role {
		return Digest{}, ErrRecord
	}
	b := append([]byte("ENKV/"+strings.ToUpper(role)+"/v3/dependency-manifest\x00"), blob(nil, body)...)
	return Hash(b), nil
}
func blob(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)))
	return append(dst, body...)
}
