package profile

// Destination holds public address fields. Organization uses only Owner;
// Repository also requires Repository; Environment requires all three fields.
// Names must already use the plugin's canonical lowercase spelling.
type Destination struct{ Owner, Repository, Environment string }

// ValidateDestination checks address fields and the scope-specific policy with
// no service access. Invalid scopes, extra fields or policies return ErrProfile.
func ValidateDestination(scope Scope, v Destination, policy Policy) error {
	if !account(v.Owner) || scope != Organization && !repository(v.Repository) || scope == Environment && !environment(v.Environment) || scope == Organization && (v.Repository != "" || v.Environment != "") || scope == Repository && v.Environment != "" || !policyValid(scope, policy) {
		return ErrProfile
	}
	_, err := EncodePolicy(policy)
	return err
}

// Derive validates the destination and returns its canonical scoped path,
// uppercasing only the entry's ASCII secret name. It does not reserve that path
// at GitHub; the operator must reserve it for ENKV use.
func Derive(scope Scope, v Destination, name string, policy Policy) (string, error) {
	if err := ValidateDestination(scope, v, policy); err != nil {
		return "", err
	}
	coordinate := "orgs/" + v.Owner + "/actions/secrets/" + name
	if scope == Repository {
		coordinate = "repos/" + v.Owner + "/" + v.Repository + "/actions/secrets/" + name
	}
	if scope == Environment {
		coordinate = "repos/" + v.Owner + "/" + v.Repository + "/environments/" + v.Environment + "/secrets/" + name
	}
	return CanonicalTarget(scope, coordinate)
}
