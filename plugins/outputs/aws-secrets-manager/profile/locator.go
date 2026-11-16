package profile

import (
	"bytes"
	"encoding/json"
	protocol "enkv.sh/sdk/protocols/output"
)

// Settings contains the required public destination fields; there are no defaults.
// Account is twelve decimal digits and Region is in the local commercial-region list.
type Settings struct {
	Account string `json:"account"`
	Region  string `json:"region"`
}
type targetData struct {
	Account string `json:"account"`
	Region  string `json:"region"`
	Name    string `json:"name"`
}

func canonicalSettings(raw []byte) (Settings, []byte, error) {
	var s Settings
	if decodeObject(raw, map[string]*string{"account": &s.Account, "region": &s.Region}) != nil || !accountValid(s.Account) || !commercialRegions[s.Region] {
		return Settings{}, nil, ErrProfile
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
	slot := "arn:aws:secretsmanager:" + s.Region + ":" + s.Account + ":secret:" + name
	if _, err := parsePlannedSlot(slot); err != nil {
		return protocol.Target{}, err
	}
	data, err := json.Marshal(targetData{s.Account, s.Region, name})
	if err != nil {
		return protocol.Target{}, err
	}
	t := protocol.Target{ServiceContractID: ServiceContractID, TargetContractID: TargetContractID, CanonicalTarget: slot, TargetData: data, PayloadEncoding: encoding, LocatorRequiresCreation: true, Capabilities: actions, WriteValueBounds: writeBounds(actions)}
	if !t.Valid() {
		return protocol.Target{}, ErrProfile
	}
	return t, nil
}

// ParseTarget checks the complete canonical target and retained deletion data.
// It does not contact the service; malformed or zero targets return ErrProfile.
func ParseTarget(t protocol.Target) (Target, error) {
	if !t.Valid() || t.ServiceContractID != ServiceContractID || t.TargetContractID != TargetContractID || !t.LocatorRequiresCreation || t.ConsumerLocator != "" || t.Capabilities & ^actions != 0 || t.CreateValueBounds != (protocol.PayloadBounds{}) || t.WriteValueBounds != writeBounds(t.Capabilities) {
		return Target{}, ErrProfile
	}
	var data targetData
	if decodeObject(t.TargetData, map[string]*string{"account": &data.Account, "region": &data.Region, "name": &data.Name}) != nil {
		return Target{}, ErrProfile
	}
	canonical, err := json.Marshal(data)
	if err != nil || !bytes.Equal(canonical, t.TargetData) {
		return Target{}, ErrProfile
	}
	slot := "arn:aws:secretsmanager:" + data.Region + ":" + data.Account + ":secret:" + data.Name
	parsed, err := parsePlannedSlot(slot)
	if err != nil || t.CanonicalTarget != slot {
		return Target{}, ErrProfile
	}
	return parsed, nil
}

// ResolveConsumerLocator checks that resource is the service-assigned ARN
// for this exact planned slot and returns its AWSCURRENT reference. A planned
// ARN alone is insufficient; relation failures return ErrProfile.
func ResolveConsumerLocator(t protocol.Target, resource string) (string, error) {
	parsed, err := ParseTarget(t)
	if err != nil {
		return "", err
	}
	owned, err := ParseOwnedInstance(resource)
	if err != nil || owned.Slot != parsed.Slot {
		return "", ErrProfile
	}
	return owned.ARN + "?stage=AWSCURRENT", nil
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
