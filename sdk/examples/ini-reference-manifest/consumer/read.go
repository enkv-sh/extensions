// Package consumer reads the quoted INI reference format without ENKV or its SDKs.
// It extracts plain bytes and secret reference locations; it does not fetch
// secrets, authenticate the input or validate every manifest field.
package consumer

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
)

// ErrManifest identifies malformed reference-format syntax or fields. Callers
// can use errors.Is; Read can also return an underlying scanner/read error.
var ErrManifest = errors.New("INI reference manifest invalid")

// Document owns decoded quoted strings indexed by section and field. Prefix
// is the section prefix from the first manifest section. Sections is mutable;
// callers must keep it unchanged during accessor calls. Its zero value is invalid.
type Document struct {
	Prefix   string
	Sections map[string]map[string]string
}

// Reference identifies one secret destination and its consumer locator. It
// supplies reference data only; it grants no service access or secret value.
type Reference struct{ EntryName, DestinationID, ServiceContract, Locator string }

// Read borrows source and parses quoted fields, unique sections/keys, the
// format marker and bounded entry counts. It does not close source. It returns
// zero Document on error. Successful parsing does not validate every field or
// prove correspondence to an authorized projection; use independent expected
// values in tests. Scanner tokens have a 1 MiB limit.
func Read(source io.Reader) (Document, error) {
	if source == nil {
		return Document{}, ErrManifest
	}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	document := Document{Sections: make(map[string]map[string]string)}
	var current map[string]string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := line[1 : len(line)-1]
			if _, exists := document.Sections[name]; exists || name == "" {
				return Document{}, ErrManifest
			}
			if current == nil {
				if !strings.HasSuffix(name, ".manifest") {
					return Document{}, ErrManifest
				}
				document.Prefix = strings.TrimSuffix(name, ".manifest")
				if document.Prefix == "" {
					return Document{}, ErrManifest
				}
			}
			current = make(map[string]string)
			document.Sections[name] = current
			continue
		}
		key, encoded, ok := strings.Cut(line, "=")
		if !ok || current == nil || key == "" {
			return Document{}, ErrManifest
		}
		if _, exists := current[key]; exists {
			return Document{}, ErrManifest
		}
		value, err := strconv.Unquote(encoded)
		if err != nil {
			return Document{}, ErrManifest
		}
		current[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Document{}, err
	}
	header := document.Sections[document.Prefix+".manifest"]
	if header["format"] != "example/ini-reference/v1" {
		return Document{}, ErrManifest
	}
	if _, err := count(header, "included_count", 512); err != nil {
		return Document{}, err
	}
	if _, err := count(header, "excluded_count", 512); err != nil {
		return Document{}, err
	}
	return document, nil
}
func count(values map[string]string, key string, maximum int) (int, error) {
	value, present := values[key]
	if !present {
		return 0, ErrManifest
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > maximum {
		return 0, ErrManifest
	}
	return n, nil
}
func decode(values map[string]string, key string) ([]byte, error) {
	text, present := values[key]
	if !present {
		return nil, ErrManifest
	}
	value, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, ErrManifest
	}
	return value, nil
}

// PlainValues decodes included plain entries into a new caller-owned map and
// byte slices, skipping secret entries. It rejects invalid kinds, missing/bad
// Base64 and duplicate plain names with ErrManifest. On error it returns nil.
func (d Document) PlainValues() (map[string][]byte, error) {
	header := d.Sections[d.Prefix+".manifest"]
	n, err := count(header, "included_count", 512)
	if err != nil {
		return nil, err
	}
	values := make(map[string][]byte)
	for i := 0; i < n; i++ {
		entry := d.Sections[d.Prefix+".entry."+strconv.Itoa(i)]
		if entry["kind"] == "secret" {
			continue
		}
		if entry["kind"] != "plain" {
			return nil, ErrManifest
		}
		name, err := decode(entry, "name_base64")
		if err != nil {
			return nil, err
		}
		value, err := decode(entry, "value_base64")
		if err != nil {
			return nil, err
		}
		if _, exists := values[string(name)]; exists {
			return nil, ErrManifest
		}
		values[string(name)] = value
	}
	return values, nil
}

// References extracts included secret destinations in entry/destination order,
// skipping plain entries. It requires bounded positive destination counts and
// decodable fields with nonempty locators. It returns ErrManifest and nil on
// invalid fields, and a nil slice for no references. It does not resolve locators.
func (d Document) References() ([]Reference, error) {
	n, err := count(d.Sections[d.Prefix+".manifest"], "included_count", 512)
	if err != nil {
		return nil, err
	}
	var references []Reference
	for i := 0; i < n; i++ {
		prefix := d.Prefix + ".entry." + strconv.Itoa(i)
		entry := d.Sections[prefix]
		if entry["kind"] == "plain" {
			continue
		}
		if entry["kind"] != "secret" {
			return nil, ErrManifest
		}
		name, err := decode(entry, "name_base64")
		if err != nil {
			return nil, err
		}
		count, err := count(entry, "destination_count", 8)
		if err != nil || count == 0 {
			return nil, ErrManifest
		}
		for j := 0; j < count; j++ {
			destination := d.Sections[prefix+".destination."+strconv.Itoa(j)]
			id, err := decode(destination, "destination_id_base64")
			if err != nil {
				return nil, err
			}
			service, err := decode(destination, "service_contract_base64")
			if err != nil {
				return nil, err
			}
			locator, err := decode(destination, "consumer_locator_base64")
			if err != nil {
				return nil, err
			}
			if len(locator) == 0 {
				return nil, ErrManifest
			}
			references = append(references, Reference{string(name), string(id), string(service), string(locator)})
		}
	}
	return references, nil
}
