// Package profile owns canonical public settings and target semantics.
package profile

import (
	"bytes"
	"encoding/json"
	protocol "enkv.sh/sdk/protocols/output"
	"errors"
	"io"
	"strconv"
	"strings"
)

// ErrProfile identifies refused public settings, targets or action semantics.
// Callers may use errors.Is; this is not a live permission check.
var ErrProfile = errors.New("gcp-secret-manager public request refused")

// Contract identities name this plugin's settings, service and target semantics.
const (
	ConfigContractID  = "ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1"
	ServiceContractID = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"
	TargetContractID  = "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
)
const actions protocol.ActionCapabilities = protocol.CapabilityCreateEmpty | protocol.CapabilityWriteValue | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot

// Actions returns the fixed create-empty, write and deletion capabilities.
// It grants no authority or permission to execute them.
func Actions() protocol.ActionCapabilities { return actions }

func decodeObject(raw []byte, fields map[string]*string) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrProfile
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		dst, known := fields[key]
		if err != nil || !ok || !known || seen[key] || d.Decode(dst) != nil {
			return ErrProfile
		}
		seen[key] = true
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') || d.Decode(new(any)) != io.EOF || len(seen) != len(fields) {
		return ErrProfile
	}
	return nil
}
func writeBounds(caps protocol.ActionCapabilities) protocol.PayloadBounds {
	if !caps.Has(protocol.ActionWriteValue) {
		return protocol.PayloadBounds{}
	}
	return protocol.PayloadBounds{Minimum: 1, Maximum: protocol.MaximumPayloadBytes}
}

// ParseParent returns the canonical project number and secret name needed by effects.
func ParseParent(parent string) (string, string, error) {
	parts := strings.Split(parent, "/")
	if len(parent) > protocol.MaximumCoordinateBytes || len(parts) != 4 || parts[0] != "projects" ||
		parts[2] != "secrets" || len(parts[1]) == 0 || parts[1][0] == '0' ||
		len(parts[3]) == 0 || len(parts[3]) > 255 {
		return "", "", ErrProfile
	}
	project, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || project <= 0 || strconv.FormatInt(project, 10) != parts[1] {
		return "", "", ErrProfile
	}
	for _, c := range parts[3] {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return "", "", ErrProfile
	}
	return parts[1], parts[3], nil
}
