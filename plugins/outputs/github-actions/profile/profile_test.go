package profile

import (
	"strings"
	"testing"
)

// full_only: false
func TestInterpretScopeCanonicalMeaningAndPolicy(t *testing.T) {
	for _, row := range []struct {
		scope          Scope
		slot, contract string
	}{
		{Repository, "repos/owner/repo/actions/secrets/TOKEN", "github-actions/repository-config/v1"},
		{Organization, "orgs/owner/actions/secrets/TOKEN", "github-actions/organization-config/v1"},
		{Environment, "repos/owner/repo/environments/prod/secrets/TOKEN", "github-actions/environment-config/v1"},
	} {
		if ConfigContractID(row.scope) != row.contract {
			t.Fatal("config identity")
		}
		for _, input := range []string{row.slot, strings.TrimSuffix(row.slot, "TOKEN") + "token"} {
			canonical, err := CanonicalTarget(row.scope, input)
			if err != nil || canonical != row.slot {
				t.Fatal("canonical target", err)
			}
			target, err := ParseTarget(row.scope, input)
			if err != nil || target.SecretPath != "/"+row.slot || target.KeyPath == "" {
				t.Fatal("exact transport target", err)
			}
		}
	}
	for _, row := range []struct {
		scope   Scope
		prefix  string
		maximum int
	}{
		{Repository, "repos/owner/repo/actions/secrets/", 100},
		{Environment, "repos/owner/repo/environments/" + strings.Repeat("p", 255) + "/secrets/", 100},
	} {
		for _, n := range []int{row.maximum, row.maximum + 1} {
			_, err := ParseTarget(row.scope, row.prefix+strings.Repeat("T", n))
			if (err == nil) != (n == row.maximum) {
				t.Fatal("secret-name boundary")
			}
		}
	}
	if ConfigContractID(0) != "" {
		t.Fatal("unknown scope has config contract")
	}
	for _, mode := range []uint8{PolicyWholeScope, PolicyRestrictedScope, PolicyExplicitSet} {
		p := Policy{ClassID: orgPolicyClass, Mode: mode}
		if mode == PolicyExplicitSet {
			p.SubjectKind = SubjectNumber
			p.NumberSubjects = []uint64{7, 11}
		}
		if !policyValid(Organization, p) {
			t.Fatal("organization policy refused")
		}
		if _, err := EncodePolicy(p); err != nil {
			t.Fatal("policy grammar", err)
		}
	}
}

// full_only: false
func TestInterpretRefusesAliasesAndInvalidPolicy(t *testing.T) {
	for _, row := range []struct {
		scope Scope
		path  string
	}{
		{Repository, "repos/Owner/repo/actions/secrets/TOKEN"}, {Repository, "repos/owner/Repo/actions/secrets/TOKEN"},
		{Repository, "repos/owner/repo.git/actions/secrets/TOKEN"}, {Repository, "repos/owner/repo./actions/secrets/TOKEN"},
		{Repository, "repos/owner/repo-/actions/secrets/TOKEN"}, {Repository, "repos/owner/repo/actions/secrets/GITHUB_TOKEN"},
		{Repository, "repos/owner/repo/actions/secrets/1TOKEN"}, {Repository, "repos/owner/repo/actions/secrets/TOKEN%2FOTHER"},
		{Repository, "users/owner/actions/secrets/TOKEN"}, {Organization, "repos/owner/repo/actions/secrets/TOKEN"},
		{Environment, "repos/owner/repo/environments/Prod/secrets/TOKEN"}, {Scope(0), "orgs/owner/actions/secrets/TOKEN"},
	} {
		if _, err := ParseTarget(row.scope, row.path); err != ErrProfile {
			t.Fatal("alias or wrong scope accepted", row.path, err)
		}
	}
	base := Policy{ClassID: orgPolicyClass, Mode: PolicyExplicitSet, SubjectKind: SubjectNumber, NumberSubjects: []uint64{7, 11}}
	for _, change := range []func(*Policy){
		func(p *Policy) { p.ClassID = "other" }, func(p *Policy) { p.Mode = PolicyNone }, func(p *Policy) { p.SubjectKind = SubjectText },
		func(p *Policy) { p.NumberSubjects = []uint64{0} }, func(p *Policy) { p.NumberSubjects = []uint64{7, 7} },
		func(p *Policy) { p.NumberSubjects = []uint64{11, 7} }, func(p *Policy) { p.NumberSubjects = nil }, func(p *Policy) { p.TextSubjects = []string{"unexpected"} },
		func(p *Policy) { p.Mode = PolicyWholeScope }, func(p *Policy) { p.Mode = PolicyRestrictedScope },
	} {
		p := base
		change(&p)
		if _, err := EncodePolicy(p); err != ErrProfile {
			t.Fatal("invalid provider policy accepted", err)
		}
	}
	if policyValid(Organization, Policy{}) {
		t.Fatal("missing organization visibility accepted")
	}
	for _, scope := range []Scope{Repository, Environment} {
		if policyValid(scope, base) {
			t.Fatal("organization policy accepted for another scope")
		}
	}
}
