package github

import (
	"enkv.sh/plugins/outputs/github-actions/profile"
	protocol "enkv.sh/sdk/protocols/output"
)

const (
	MaximumRawValueBytes = 48000 // Conservative local profile; service docs say only "48 KB".
	maximumPutBodyBytes  = 2 << 20
)

func parseCanonicalTarget(scope profile.Scope, coordinate string) (profile.Target, error) {
	parsed, err := profile.ParseTarget(scope, coordinate)
	if err != nil || parsed.SecretPath != "/"+coordinate {
		return profile.Target{}, profile.ErrProfile
	}
	return parsed, nil
}
func validateTarget(scope profile.Scope, action protocol.Action, coordinate, owned string, policy profile.Policy, tokenLength uint16) error {
	if tokenLength != 0 || action != protocol.ActionCreateWithValue && action != protocol.ActionWriteValue && action != protocol.ActionUpdatePolicy && action != protocol.ActionDeleteOwned && action != protocol.ActionDeleteReservedSlot {
		return profile.ErrProfile
	}
	if _, err := parseCanonicalTarget(scope, coordinate); err != nil {
		return err
	}
	if action >= protocol.ActionDeleteOwned {
		wire, err := profile.PublicPolicy(policy)
		if err != nil || wire.Present() {
			return profile.ErrProfile
		}
	} else {
		switch scope {
		case profile.Organization:
			if policy.ClassID != "github-actions/org-visibility" {
				return profile.ErrProfile
			}
		case profile.Repository, profile.Environment:
			if policy.ClassID != "" {
				return profile.ErrProfile
			}
		default:
			return profile.ErrProfile
		}
		if _, err := profile.EncodePolicy(policy); err != nil {
			return err
		}
		if action == protocol.ActionUpdatePolicy && (scope != profile.Organization || policy.Mode != profile.PolicyExplicitSet) {
			return profile.ErrProfile
		}
	}
	if action != protocol.ActionCreateWithValue && action != protocol.ActionDeleteReservedSlot && owned != coordinate {
		return profile.ErrProfile
	}
	return nil
}
