// Package profile interprets public GitHub Actions output fields without provider access.
package profile

import (
	"errors"
	"strings"

	protocol "enkv.sh/sdk/protocols/output"
)

// ErrProfile identifies refused GitHub settings, targets or policies and supports
// errors.Is. It does not identify an HTTP failure or token permission.
var ErrProfile = errors.New("GitHub output profile refused")

// Scope fixes the GitHub API namespace for one executable. Zero is invalid.
type Scope uint8

// Repository, Organization and Environment select separate command contracts.
const (
	Repository     Scope = 1
	Organization   Scope = 2
	Environment    Scope = 3
	orgPolicyClass       = "github-actions/org-visibility"
)

// ServiceContractID identifies the shared GitHub Actions service semantics.
const ServiceContractID = "github-actions/service/v1"

// TargetContractID identifies the canonical scoped path and retained target data.
const TargetContractID = "github-actions/target/v1"

// PolicyContractID identifies the organization visibility encoding.
const PolicyContractID = "github-actions/org-visibility/v1"

// ConfigContractID returns the settings identity for scope, or an empty string
// for an unsupported scope.
func ConfigContractID(scope Scope) string {
	switch scope {
	case Repository:
		return "github-actions/repository-config/v1"
	case Organization:
		return "github-actions/organization-config/v1"
	case Environment:
		return "github-actions/environment-config/v1"
	}
	return ""
}

func asciiName(s string, maximum int, initial, rest string) bool {
	if len(s) == 0 || len(s) > maximum || !strings.ContainsRune(initial, rune(s[0])) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !strings.ContainsRune(rest, rune(s[i])) {
			return false
		}
	}
	return true
}

func account(s string) bool {
	const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789"
	return asciiName(s, 39, alphaNum, alphaNum+"-") && s[len(s)-1] != '-'
}

func repository(s string) bool {
	const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789"
	return asciiName(s, 100, alphaNum, alphaNum+"._-") && strings.ContainsRune(alphaNum, rune(s[len(s)-1])) && !strings.HasSuffix(s, ".git")
}

func environment(s string) bool {
	const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789"
	return asciiName(s, 255, alphaNum, alphaNum+"._-") && strings.ContainsRune(alphaNum, rune(s[len(s)-1]))
}

func secret(s string) bool {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	return asciiName(s, 100, alpha, alpha+"0123456789") && !strings.HasPrefix(s, "GITHUB_")
}

// Target contains exact service paths: KeyPath for public-key discovery,
// SecretPath for value and deletion, and PolicyPath for organization repository
// selection. PolicyPath is empty for other scopes.
type Target struct {
	KeyPath, SecretPath, PolicyPath string
}

// The operator reserves this exact path for enkv-created output. GitHub does
// not prove the reservation. This parser refuses local spelling aliases.
func parseTarget(scope Scope, coordinate string) (Target, error) {
	if len(coordinate) > protocol.MaximumCoordinateBytes {
		return Target{}, ErrProfile
	}
	p := strings.Split(coordinate, "/")
	switch scope {
	case Repository:
		if len(p) != 6 || p[0] != "repos" || !account(p[1]) || !repository(p[2]) || p[3] != "actions" || p[4] != "secrets" || !secret(p[5]) {
			return Target{}, ErrProfile
		}
		return Target{KeyPath: "/repos/" + p[1] + "/" + p[2] + "/actions/secrets/public-key", SecretPath: "/" + coordinate}, nil
	case Organization:
		if len(p) != 5 || p[0] != "orgs" || !account(p[1]) || p[2] != "actions" || p[3] != "secrets" || !secret(p[4]) {
			return Target{}, ErrProfile
		}
		return Target{KeyPath: "/orgs/" + p[1] + "/actions/secrets/public-key", SecretPath: "/" + coordinate,
			PolicyPath: "/" + coordinate + "/repositories"}, nil
	case Environment:
		if len(p) != 7 || p[0] != "repos" || !account(p[1]) || !repository(p[2]) || p[3] != "environments" || !environment(p[4]) || p[5] != "secrets" || !secret(p[6]) {
			return Target{}, ErrProfile
		}
		return Target{KeyPath: "/repos/" + p[1] + "/" + p[2] + "/environments/" + p[4] + "/secrets/public-key", SecretPath: "/" + coordinate}, nil
	default:
		return Target{}, ErrProfile
	}
}

func policyValid(scope Scope, policy Policy) bool {
	if scope == Organization {
		if policy.ClassID != orgPolicyClass || len(policy.TextSubjects) != 0 {
			return false
		}
		switch policy.Mode {
		case PolicyWholeScope, PolicyRestrictedScope:
			return policy.SubjectKind == SubjectNone && len(policy.NumberSubjects) == 0
		case PolicyExplicitSet:
			return policy.SubjectKind == SubjectNumber && len(policy.NumberSubjects) > 0
		default:
			return false
		}
	}
	return (scope == Repository || scope == Environment) &&
		policy.ClassID == "" && policy.Mode == 0 &&
		policy.SubjectKind == 0 && len(policy.NumberSubjects) == 0 && len(policy.TextSubjects) == 0
}

// ParseTarget accepts the plugin's scope grammar and canonicalizes only the secret name.
func ParseTarget(scope Scope, coordinate string) (Target, error) {
	canonical, err := CanonicalTarget(scope, coordinate)
	if err != nil {
		return Target{}, err
	}
	return parseTarget(scope, canonical)
}

// CanonicalTarget uppercases only an ASCII secret-name suffix. Address fields
// must already meet this plugin's lowercase grammar. Invalid input returns
// ErrProfile; it performs no discovery or service identity check.
func CanonicalTarget(scope Scope, coordinate string) (string, error) {
	index := strings.LastIndexByte(coordinate, '/')
	if index < 0 {
		return "", ErrProfile
	}
	// GitHub accepts only ASCII secret names. Unicode case conversion can
	// turn a refused source spelling into an accepted ASCII coordinate.
	for i := index + 1; i < len(coordinate); i++ {
		if coordinate[i] >= 0x80 {
			return "", ErrProfile
		}
	}
	canonical := coordinate[:index+1] + strings.ToUpper(coordinate[index+1:])
	if _, err := parseTarget(scope, canonical); err != nil {
		return "", err
	}
	return canonical, nil
}
