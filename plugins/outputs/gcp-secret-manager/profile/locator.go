package profile

import (
	"bytes"
	"encoding/json"
	protocol "enkv.sh/sdk/protocols/output"
)

// Settings contains the required public destination fields; there are no defaults.
// ProjectNumber is a positive canonical decimal project number, not a project ID.
type Settings struct {
	ProjectNumber string `json:"project_number"`
}
type targetData struct {
	ProjectNumber string `json:"project_number"`
	Name          string `json:"name"`
}

func canonicalSettings(raw []byte) (Settings, []byte, error) {
	var s Settings
	if decodeObject(raw, map[string]*string{"project_number": &s.ProjectNumber}) != nil {
		return Settings{}, nil, ErrProfile
	}
	if _, _, err := ParseParent("projects/" + s.ProjectNumber + "/secrets/check"); err != nil {
		return Settings{}, nil, err
	}
	b, err := json.Marshal(s)
	return s, b, err
}

// Derive validates a canonical destination and entry name, then returns owned
// target data for raw or padded-Base64 application encoding. It uses no
// credentials and retains no input aliases. Invalid input returns ErrProfile.
func Derive(d protocol.Destination, name string, encoding uint8) (protocol.Target, error) {
	if ValidateDestination(d) != nil {
		return protocol.Target{}, ErrProfile
	}
	s, _, err := canonicalSettings(d.CanonicalSettings)
	if err != nil {
		return protocol.Target{}, err
	}
	parent := "projects/" + s.ProjectNumber + "/secrets/" + name
	if _, _, err := ParseParent(parent); err != nil {
		return protocol.Target{}, err
	}
	data, err := json.Marshal(targetData{s.ProjectNumber, name})
	if err != nil {
		return protocol.Target{}, err
	}
	t := protocol.Target{ServiceContractID: ServiceContractID, TargetContractID: TargetContractID, CanonicalTarget: parent, ConsumerLocator: parent + "/versions/latest", TargetData: data, PayloadEncoding: encoding, Capabilities: actions, WriteValueBounds: writeBounds(actions)}
	if !t.Valid() {
		return protocol.Target{}, ErrProfile
	}
	return t, nil
}

// ParseTarget checks the complete canonical target and retained deletion data.
// It does not contact the service; malformed or zero targets return ErrProfile.
func ParseTarget(t protocol.Target) (string, string, error) {
	if !t.Valid() || t.ServiceContractID != ServiceContractID || t.TargetContractID != TargetContractID || t.LocatorRequiresCreation || t.Capabilities & ^actions != 0 || t.CreateValueBounds != (protocol.PayloadBounds{}) || t.WriteValueBounds != writeBounds(t.Capabilities) {
		return "", "", ErrProfile
	}
	var data targetData
	if decodeObject(t.TargetData, map[string]*string{"project_number": &data.ProjectNumber, "name": &data.Name}) != nil {
		return "", "", ErrProfile
	}
	canonical, err := json.Marshal(data)
	if err != nil || !bytes.Equal(canonical, t.TargetData) {
		return "", "", ErrProfile
	}
	parent := "projects/" + data.ProjectNumber + "/secrets/" + data.Name
	if t.CanonicalTarget != parent || t.ConsumerLocator != parent+"/versions/latest" {
		return "", "", ErrProfile
	}
	return ParseParent(parent)
}

// ResolveConsumerLocator returns the static latest-version locator after
// validating the target. The resource argument is unused; this does not prove
// that a secret or version exists. Invalid targets return ErrProfile.
func ResolveConsumerLocator(t protocol.Target, _ string) (string, error) {
	if _, _, err := ParseTarget(t); err != nil {
		return "", err
	}
	return t.ConsumerLocator, nil
}

// Normalize accepts the required settings with no defaults and returns new
// canonical settings and fixed capabilities. It performs no service or
// credential lookup; unknown, duplicate or missing fields return ErrProfile.
func Normalize(raw []byte) (protocol.Destination, error) {
	_, canonical, err := canonicalSettings(raw)
	if err != nil {
		return protocol.Destination{}, err
	}
	return protocol.Destination{ConfigContractID: ConfigContractID, ServiceContractID: ServiceContractID, CanonicalSettings: canonical, Capabilities: actions}, nil
}

// ValidateDestination checks exact canonical bytes, contract identities and
// capabilities. External IAM policy is not a destination setting. It borrows d
// only for this call; invalid or zero destinations return ErrProfile.
func ValidateDestination(d protocol.Destination) error {
	if !d.Valid() || d.ConfigContractID != ConfigContractID || d.ServiceContractID != ServiceContractID || d.Capabilities != actions || d.Policy.Present() || len(d.Policy.Data) != 0 {
		return ErrProfile
	}
	_, canonical, err := canonicalSettings(d.CanonicalSettings)
	if err != nil || !bytes.Equal(canonical, d.CanonicalSettings) {
		return ErrProfile
	}
	return nil
}
