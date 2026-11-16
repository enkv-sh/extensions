package profile

import "testing"

// full_only: false
func TestDeriveAndResolveAllScopesAndOrganizationVisibility(t *testing.T) {
	for _, row := range []struct {
		scope    Scope
		settings Destination
		prefix   string
	}{
		{Repository, Destination{Owner: "owner", Repository: "repo"}, "repos/owner/repo/actions/secrets/"},
		{Organization, Destination{Owner: "owner"}, "orgs/owner/actions/secrets/"},
		{Environment, Destination{Owner: "owner", Repository: "repo", Environment: "prod"}, "repos/owner/repo/environments/prod/secrets/"},
	} {
		policies := []Policy{{}}
		if row.scope == Organization {
			policies = []Policy{{ClassID: orgPolicyClass, Mode: PolicyWholeScope}, {ClassID: orgPolicyClass, Mode: PolicyRestrictedScope}, {ClassID: orgPolicyClass, Mode: PolicyExplicitSet, SubjectKind: SubjectNumber, NumberSubjects: []uint64{7, 11}}}
		}
		for _, p := range policies {
			if err := ValidateDestination(row.scope, row.settings, p); err != nil {
				t.Fatal("unused destination", err)
			}
			for _, name := range []string{"token", "OTHER_TOKEN"} {
				want := "TOKEN"
				if name == "OTHER_TOKEN" {
					want = name
				}
				coordinate, err := Derive(row.scope, row.settings, name, p)
				if err != nil || coordinate != row.prefix+want {
					t.Fatal("complete scoped derivation", err)
				}
				target, err := ParseTarget(row.scope, coordinate)
				if err != nil || target.SecretPath != "/"+row.prefix+want {
					t.Fatal("static consumer target", err)
				}
			}
			for _, name := range []string{"", "GITHUB_TOKEN", "1TOKEN", "bad/name"} {
				if _, err := Derive(row.scope, row.settings, name, p); err != ErrProfile {
					t.Fatal("invalid name accepted", name)
				}
			}
		}
		invalid := row.settings
		invalid.Owner = "Owner"
		if ValidateDestination(row.scope, invalid, policies[0]) != ErrProfile {
			t.Fatal("unused owner alias admitted")
		}
		if _, err := Derive(row.scope, Destination{}, "TOKEN", policies[0]); err != ErrProfile {
			t.Fatal("missing address admitted")
		}
	}
	for _, scope := range []Scope{Repository, Environment} {
		if policyValid(scope, Policy{ClassID: "github-actions/inherited-scope"}) {
			t.Fatal("obsolete policy grammar accepted")
		}
	}
}

// full_only: false
func TestSecretNamesRequireASCIIBeforeCanonicalization(t *testing.T) {
	for _, row := range []struct {
		scope    Scope
		settings Destination
		prefix   string
	}{
		{Repository, Destination{Owner: "owner", Repository: "repo"}, "repos/owner/repo/actions/secrets/"},
		{Organization, Destination{Owner: "owner"}, "orgs/owner/actions/secrets/"},
		{Environment, Destination{Owner: "owner", Repository: "repo", Environment: "prod"}, "repos/owner/repo/environments/prod/secrets/"},
	} {
		policy := Policy{}
		if row.scope == Organization {
			policy = Policy{ClassID: orgPolicyClass, Mode: PolicyWholeScope}
		}
		for _, name := range []string{"ı_TOKEN", "ſ_TOKEN", "ascii_1", "ASCII_1"} {
			want := name == "ascii_1" || name == "ASCII_1"
			coordinate, err := Derive(row.scope, row.settings, name, policy)
			if (err == nil) != want || want && coordinate != row.prefix+"ASCII_1" {
				t.Fatal("ASCII-only derivation", name, err)
			}
			target, err := ParseTarget(row.scope, row.prefix+name)
			if (err == nil) != want || want && target.SecretPath != "/"+row.prefix+"ASCII_1" {
				t.Fatal("ASCII-only target parser", name, err)
			}
		}
	}
}
