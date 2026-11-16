package artifact

import "strings"

type semanticVersion struct {
	core [3]string
	pre  []string
}

func versionParts(s string) (semanticVersion, bool) {
	var v semanticVersion
	if len(s) == 0 || len(s) > 128 {
		return v, false
	}
	for _, c := range s {
		if c > 127 {
			return v, false
		}
	}
	base, build, hasBuild := strings.Cut(s, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return v, false
	}
	core, pre, hasPre := strings.Cut(base, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if !numeric(p) || len(p) > 1 && p[0] == '0' {
			return v, false
		}
		v.core[i] = p
	}
	if hasPre {
		if !validIdentifiers(pre, true) {
			return v, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}
func numeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validIdentifiers(s string, pre bool) bool {
	for _, p := range strings.Split(s, ".") {
		if p == "" {
			return false
		}
		for _, c := range p {
			if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' {
				return false
			}
		}
		if pre && numeric(p) && len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	return true
}

// ValidVersion accepts an ASCII semantic version of at most 128 bytes without a
// leading v. Numeric core and prerelease identifiers must not have leading zeroes.
func ValidVersion(s string) bool { _, ok := versionParts(s); return ok }

// StableVersion reports whether s is valid and has no prerelease identifiers.
// Build metadata is permitted and does not make a version unstable.
func StableVersion(s string) bool { v, ok := versionParts(s); return ok && len(v.pre) == 0 }
func numberCompare(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions returns -1, 0 or 1 by semantic-version precedence, ignoring
// build metadata. Invalid input returns ErrRecord.
func CompareVersions(a, b string) (int, error) {
	x, ok := versionParts(a)
	if !ok {
		return 0, ErrRecord
	}
	y, ok := versionParts(b)
	if !ok {
		return 0, ErrRecord
	}
	for i := range x.core {
		if c := numberCompare(x.core[i], y.core[i]); c != 0 {
			return c, nil
		}
	}
	if len(x.pre) == 0 && len(y.pre) == 0 {
		return 0, nil
	}
	if len(x.pre) == 0 {
		return 1, nil
	}
	if len(y.pre) == 0 {
		return -1, nil
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		p, q := x.pre[i], y.pre[i]
		var c int
		switch {
		case numeric(p) && numeric(q):
			c = numberCompare(p, q)
		case numeric(p):
			c = -1
		case numeric(q):
			c = 1
		default:
			c = strings.Compare(p, q)
		}
		if c != 0 {
			return c, nil
		}
	}
	if len(x.pre) < len(y.pre) {
		return -1, nil
	}
	if len(x.pre) > len(y.pre) {
		return 1, nil
	}
	return 0, nil
}
