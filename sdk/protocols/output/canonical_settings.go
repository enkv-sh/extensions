package output

import (
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"
)

// ValidCanonicalSettings checks JSON syntax, unique decoded object keys and
// Unicode scalar strings without changing the input. The owning record applies
// its byte limit. JSON's existing nesting limit applies independently of source
// configuration envelopes.
func ValidCanonicalSettings(body []byte) bool {
	if !utf8.Valid(body) || !json.Valid(body) {
		return false
	}
	type frame struct {
		object int
		key    bool
	}
	type key struct {
		object int
		name   string
	}
	// A member consumes at least four bytes. Exact-capacity backing avoids
	// unaccounted hash-table growth; sorting keeps each object's check bounded.
	keys := make([]key, 0, len(body)/4)
	stack := make([]frame, 0, min(10000, len(body)/2))
	nextObject := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			stack = append(stack, frame{object: nextObject, key: true})
			nextObject++
		case '[':
			stack = append(stack, frame{object: -1})
		case '}', ']':
			stack = stack[:len(stack)-1]
		case ':':
			stack[len(stack)-1].key = false
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].object >= 0 {
				stack[len(stack)-1].key = true
			}
		case '"':
			end, valid := canonicalStringEnd(body, i)
			if !valid {
				return false
			}
			if len(stack) > 0 {
				current := stack[len(stack)-1]
				if current.object >= 0 && current.key {
					var name string
					if len(keys) == cap(keys) || json.Unmarshal(body[i:end], &name) != nil {
						return false
					}
					keys = append(keys, key{object: current.object, name: name})
				}
			}
			i = end - 1
		}
	}
	slices.SortFunc(keys, func(a, b key) int {
		if a.object < b.object {
			return -1
		}
		if a.object > b.object {
			return 1
		}
		return strings.Compare(a.name, b.name)
	})
	for i := 1; i < len(keys); i++ {
		if keys[i-1] == keys[i] {
			return false
		}
	}

	return true
}

// encoding/json accepts lone surrogate escapes by replacing them. Check each
// original string span before that lossy conversion can erase the distinction.
func canonicalStringEnd(body []byte, start int) (int, bool) {
	for i := start + 1; i < len(body); i++ {
		switch body[i] {
		case '"':
			return i + 1, true
		case '\\':
			i++
			if body[i] != 'u' {
				continue
			}
			code := canonicalHex(body[i+1 : i+5])
			i += 4
			if code >= 0xdc00 && code <= 0xdfff {
				return 0, false
			}
			if code < 0xd800 || code > 0xdbff {
				continue
			}
			if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
				return 0, false
			}
			low := canonicalHex(body[i+3 : i+7])
			if low < 0xdc00 || low > 0xdfff {
				return 0, false
			}
			i += 6
		}
	}
	return 0, false
}

func canonicalHex(body []byte) uint16 {
	var value uint16
	for _, b := range body {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b - 'a' + 10)
		default:
			value |= uint16(b - 'A' + 10)
		}
	}
	return value
}
