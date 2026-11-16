package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/netip"
	"slices"
	"time"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	protocol "enkv.sh/sdk/protocols/generator"
)

type settings struct {
	Account   string           `json:"account"`
	Name      string           `json:"name"`
	Policies  []settingsPolicy `json:"policies"`
	RequestIP *settingsIP      `json:"request_ip,omitempty"`
	NotBefore string           `json:"not_before,omitempty"`
	ExpiresOn string           `json:"expires_on,omitempty"`
}
type settingsPolicy struct {
	Effect           string             `json:"effect"`
	PermissionGroups []string           `json:"permission_groups"`
	Resources        []settingsResource `json:"resources"`
}
type settingsResource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type settingsIP struct {
	In    []string `json:"in,omitempty"`
	NotIn []string `json:"not_in,omitempty"`
}

// Normalize owns the ordinary Cloudflare settings grammar and canonical order.
func Normalize(input []byte, origin string) (protocol.Intent, error) {
	if len(input) == 0 || len(input) > protocol.MaximumSettingsInputLength {
		return protocol.Intent{}, ErrProfile
	}
	var value settings
	if json.Unmarshal(input, &value, json.RejectUnknownMembers(true)) != nil {
		return protocol.Intent{}, ErrProfile
	}
	var fields map[string]jsontext.Value
	if json.Unmarshal(input, &fields) != nil {
		return protocol.Intent{}, ErrProfile
	}
	for _, name := range []string{"not_before", "expires_on"} {
		if raw, ok := fields[name]; ok && (raw.Kind() != '"' || bytes.Equal(raw, []byte(`""`))) {
			return protocol.Intent{}, ErrProfile
		}
	}
	if raw, ok := fields["request_ip"]; ok {
		if raw.Kind() != '{' {
			return protocol.Intent{}, ErrProfile
		}
		var lists map[string]jsontext.Value
		if json.Unmarshal(raw, &lists) != nil {
			return protocol.Intent{}, ErrProfile
		}
		for _, list := range lists {
			if list.Kind() != '[' {
				return protocol.Intent{}, ErrProfile
			}
		}
	}
	parsed, err := settingsIntent(value)
	if err != nil {
		return protocol.Intent{}, err
	}
	canonical, err := json.Marshal(canonicalSettings(parsed))
	if err != nil || len(canonical) > protocol.MaximumSettingsLength {
		return protocol.Intent{}, ErrProfile
	}
	return protocol.Intent{Schema: protocol.Schema, ConfigContractID: ConfigContractID(origin), LifecycleMode: protocol.LifecycleManaged, ResourceContractID: ResourceContractID(origin), Settings: canonical}, nil
}

// ParseCanonical checks exact canonical bytes and returns the provider controls.
func ParseCanonical(intent protocol.Intent, origin string) (Intent, error) {
	if intent.Schema != protocol.Schema || intent.ConfigContractID != ConfigContractID(origin) || intent.ResourceContractID != ResourceContractID(origin) || intent.LifecycleMode != protocol.LifecycleManaged {
		return Intent{}, ErrProfile
	}
	normalized, err := Normalize(intent.Settings, origin)
	if err != nil || !bytes.Equal(normalized.Settings, intent.Settings) {
		return Intent{}, ErrProfile
	}
	var value settings
	if json.Unmarshal(intent.Settings, &value, json.RejectUnknownMembers(true)) != nil {
		return Intent{}, ErrProfile
	}
	return settingsIntent(value)
}

func settingsIntent(value settings) (Intent, error) {
	var account [32]byte
	if len(value.Account) != 32 {
		return Intent{}, ErrProfile
	}
	copy(account[:], value.Account)
	if !ValidTag(account) || len(value.Name) == 0 || len(value.Name) > provider.CloudflareMaxNameLength || !validName([]byte(value.Name)) || len(value.Policies) == 0 || len(value.Policies) > provider.CloudflareMaxPolicies {
		return Intent{}, ErrProfile
	}
	rows := make([][]byte, len(value.Policies))
	for i, p := range value.Policies {
		effect := uint8(0)
		if p.Effect == "allow" {
			effect = EffectAllow
		}
		if p.Effect == "deny" {
			effect = EffectDeny
		}
		if effect == 0 || len(p.PermissionGroups) == 0 || len(p.PermissionGroups) > provider.CloudflareMaxPermissionGroups || len(p.Resources) == 0 || len(p.Resources) > provider.CloudflareMaxResources {
			return Intent{}, ErrProfile
		}
		permissions := make([][32]byte, len(p.PermissionGroups))
		for j, text := range p.PermissionGroups {
			if len(text) != 32 {
				return Intent{}, ErrProfile
			}
			copy(permissions[j][:], text)
			if !ValidTag(permissions[j]) {
				return Intent{}, ErrProfile
			}
		}
		slices.SortFunc(permissions, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
		for j := 1; j < len(permissions); j++ {
			if permissions[j] == permissions[j-1] {
				return Intent{}, ErrProfile
			}
		}
		resources := make([][33]byte, len(p.Resources))
		for j, r := range p.Resources {
			switch r.Kind {
			case "account":
				resources[j][0] = ResourceAccount
			case "zone":
				resources[j][0] = ResourceZone
			case "account_zones":
				resources[j][0] = ResourceAccountZones
			default:
				return Intent{}, ErrProfile
			}
			if len(r.ID) != 32 {
				return Intent{}, ErrProfile
			}
			var tag [32]byte
			copy(tag[:], r.ID)
			if !ValidTag(tag) {
				return Intent{}, ErrProfile
			}
			copy(resources[j][1:], tag[:])
		}
		slices.SortFunc(resources, func(a, b [33]byte) int { return bytes.Compare(a[:], b[:]) })
		for j := 1; j < len(resources); j++ {
			if resources[j] == resources[j-1] {
				return Intent{}, ErrProfile
			}
		}
		row := []byte{effect}
		row = binary.BigEndian.AppendUint16(row, uint16(len(permissions)))
		for _, p := range permissions {
			row = append(row, p[:]...)
		}
		row = binary.BigEndian.AppendUint16(row, uint16(len(resources)))
		for _, r := range resources {
			row = append(row, r[:]...)
		}
		rows[i] = row
	}
	slices.SortFunc(rows, bytes.Compare)
	for i := 1; i < len(rows); i++ {
		if bytes.Equal(rows[i-1], rows[i]) {
			return Intent{}, ErrProfile
		}
	}
	var lists [2][][18]byte
	if value.RequestIP != nil {
		for i, texts := range [][]string{value.RequestIP.In, value.RequestIP.NotIn} {
			if len(texts) > provider.CloudflareMaxPrefixesPerList {
				return Intent{}, ErrProfile
			}
			for _, text := range texts {
				p, err := netip.ParsePrefix(text)
				if err != nil || p.String() != text || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
					return Intent{}, ErrProfile
				}
				var row [18]byte
				row[0] = 6
				row[17] = byte(p.Bits())
				if p.Addr().Is4() {
					row[0] = 4
					a := p.Addr().As4()
					copy(row[13:17], a[:])
				} else {
					a := p.Addr().As16()
					copy(row[1:17], a[:])
				}
				lists[i] = append(lists[i], row)
			}
			slices.SortFunc(lists[i], func(a, b [18]byte) int { return bytes.Compare(a[:], b[:]) })
			for j := 1; j < len(lists[i]); j++ {
				if lists[i][j] == lists[i][j-1] {
					return Intent{}, ErrProfile
				}
			}
		}
	}
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, account[:]...)
	body = appendBlob(body, []byte(value.Name))
	body = binary.BigEndian.AppendUint16(body, uint16(len(rows)))
	for _, r := range rows {
		body = append(body, r...)
	}
	for _, list := range lists {
		body = binary.BigEndian.AppendUint16(body, uint16(len(list)))
		for _, p := range list {
			body = append(body, p[:]...)
		}
	}
	for _, text := range []string{value.NotBefore, value.ExpiresOn} {
		if text == "" {
			body = append(body, 0)
			continue
		}
		v, err := time.Parse("2006-01-02T15:04:05Z", text)
		if err != nil || v.Year() < 1970 || v.Format("2006-01-02T15:04:05Z") != text {
			return Intent{}, ErrProfile
		}
		body = append(body, 1)
		body = binary.BigEndian.AppendUint64(body, uint64(v.Unix()))
	}
	return ParseIntent(body, account)
}

func canonicalSettings(v Intent) settings {
	out := settings{Account: string(v.Account[:]), Name: string(v.Name), Policies: make([]settingsPolicy, v.PolicyCount()), NotBefore: v.NotBefore, ExpiresOn: v.ExpiresOn}
	for i := range out.Policies {
		p, _ := v.CopyPolicy(i)
		row := settingsPolicy{Effect: "allow", PermissionGroups: make([]string, len(p.PermissionGroups)), Resources: make([]settingsResource, len(p.Resources))}
		if p.Effect == EffectDeny {
			row.Effect = "deny"
		}
		for j, id := range p.PermissionGroups {
			row.PermissionGroups[j] = string(id[:])
		}
		for j, r := range p.Resources {
			kind := "account"
			if r.Kind == ResourceZone {
				kind = "zone"
			}
			if r.Kind == ResourceAccountZones {
				kind = "account_zones"
			}
			row.Resources[j] = settingsResource{Kind: kind, ID: string(r.ID[:])}
		}
		out.Policies[i] = row
	}
	in, notIn := v.IPConditions()
	if len(in) > 0 || len(notIn) > 0 {
		out.RequestIP = &settingsIP{In: in, NotIn: notIn}
	}
	return out
}
