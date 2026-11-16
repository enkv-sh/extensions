// Package profile owns canonical public settings and target semantics.
package profile

import (
	"bytes"
	"encoding/json"
	protocol "enkv.sh/sdk/protocols/output"
	"errors"
	"io"
	"strings"
)

// ErrProfile identifies refused public settings, targets or action semantics.
// Callers may use errors.Is; this is not a live permission check.
var ErrProfile = errors.New("aws-secrets-manager public request refused")

// Contract identities name this plugin's settings, service and target semantics.
const (
	ConfigContractID  = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1"
	ServiceContractID = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1"
	TargetContractID  = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
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

const awsNameChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_+=.@-"

var commercialRegions = map[string]bool{
	"us-east-1": true, "us-east-2": true, "us-west-1": true, "us-west-2": true,
	"af-south-1": true, "ap-east-1": true, "ap-east-2": true, "ap-south-1": true, "ap-south-2": true,
	"ap-southeast-1": true, "ap-southeast-2": true, "ap-southeast-3": true, "ap-southeast-4": true,
	"ap-southeast-5": true, "ap-southeast-6": true, "ap-southeast-7": true,
	"ap-northeast-1": true, "ap-northeast-2": true, "ap-northeast-3": true,
	"ca-central-1": true, "ca-west-1": true,
	"eu-central-1": true, "eu-central-2": true, "eu-west-1": true, "eu-west-2": true, "eu-west-3": true,
	"eu-south-1": true, "eu-south-2": true, "eu-north-1": true,
	"il-central-1": true, "mx-central-1": true, "me-south-1": true, "me-central-1": true,
	"sa-east-1": true,
}

// Target contains the parsed fields needed by the existing effect implementation.
// ARN is set only by ParseOwnedInstance; Slot is the planned ARN without the
// service suffix. Endpoint comes from the admitted region, not caller input.
type Target struct {
	ARN, Slot, Name, Region, Account, Endpoint string
}

func parsePlannedSlot(slot string) (Target, error) {
	p := strings.SplitN(slot, ":", 7)
	if len(slot) > protocol.MaximumCoordinateBytes || len(p) != 7 || p[0] != "arn" || p[1] != "aws" ||
		p[2] != "secretsmanager" || !commercialRegions[p[3]] || !accountValid(p[4]) || p[5] != "secret" {
		return Target{}, ErrProfile
	}
	name := p[6]
	if len(name) < 1 || len(name) > 512 {
		return Target{}, ErrProfile
	}
	for _, c := range name {
		if !strings.ContainsRune(awsNameChars, c) {
			return Target{}, ErrProfile
		}
	}
	return Target{Slot: slot, Name: name, Region: p[3], Account: p[4],
		Endpoint: "https://secretsmanager." + p[3] + ".amazonaws.com"}, nil
}

// ParseOwnedInstance validates a service-assigned ARN and preserves its planned slot.
func ParseOwnedInstance(arn string) (Target, error) {
	if len(arn) < 8 || len(arn) > protocol.MaximumCoordinateBytes || arn[len(arn)-7] != '-' {
		return Target{}, ErrProfile
	}
	suffix := arn[len(arn)-6:]
	for _, c := range suffix {
		if !strings.ContainsRune(awsNameChars, c) {
			return Target{}, ErrProfile
		}
	}
	slot, err := parsePlannedSlot(arn[:len(arn)-7])
	if err != nil {
		return Target{}, err
	}
	slot.ARN = arn
	return slot, nil
}

func accountValid(account string) bool {
	if len(account) != 12 {
		return false
	}
	for _, c := range account {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
