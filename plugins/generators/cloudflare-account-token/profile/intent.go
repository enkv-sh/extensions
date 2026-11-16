// Package profile owns the pure Cloudflare account-token interpretation.
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"net/netip"
	"sort"
	"time"
	"unicode/utf8"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
)

// Policy effects and resource kinds use these closed binary encodings.
// Account and account-zones resources must name the intent account.
const (
	EffectAllow uint8 = 1
	EffectDeny  uint8 = 2

	ResourceAccount      uint8 = 1
	ResourceZone         uint8 = 2
	ResourceAccountZones uint8 = 3

	familyIPv4 uint8 = 4
	familyIPv6 uint8 = 6
)

// ErrProfile reports refused settings, controls or request semantics. Callers may
// use errors.Is; it carries no provider response or credential bytes.
var ErrProfile = errors.New("cloudflare profile refused")

type resource struct {
	kind uint8
	tag  [32]byte
}

type policy struct {
	effect      uint8
	permissions [][32]byte
	resources   []resource
	encoded     []byte
}

type prefix struct {
	encoded [18]byte
	text    string
}

// Intent contains the validated canonical intent and its public fields.
// Policies and IP prefixes remain private and do not borrow input bytes. Name
// is owned by the returned Intent; copies of Intent share that slice. Treat all
// fields as immutable after parsing so Digest continues to describe them. The
// zero value is not a valid intent. Account and resource IDs are ASCII hex tags;
// optional times are empty when absent.
type Intent struct {
	Account              [32]byte
	Name                 []byte
	policies             []policy
	in, notIn            []prefix
	NotBefore, ExpiresOn string
	Digest               [32]byte
}

// ParseIntent validates the closed binary intent and preserves its canonical
// ordering. It copies all retained input and requires commandAccount to match.
// It does not normalize a noncanonical input into an accepted one. Refusals
// return ErrProfile; a successful result can outlive body.
func ParseIntent(body []byte, commandAccount [32]byte) (Intent, error) {
	var out Intent
	if len(body) == 0 || len(body) > provider.MaximumIntentLength || !ValidTag(commandAccount) {
		return out, ErrProfile
	}
	r := intentReader{body: body}
	if r.u16() != 1 {
		return Intent{}, ErrProfile
	}
	out.Account = r.tag()
	if out.Account != commandAccount || !ValidTag(out.Account) {
		return Intent{}, ErrProfile
	}
	name := r.blob(provider.CloudflareMaxNameLength)
	if len(name) == 0 || !validName(name) {
		return Intent{}, ErrProfile
	}
	out.Name = bytes.Clone(name)
	policyCount := int(r.u16())
	if policyCount < 1 || policyCount > provider.CloudflareMaxPolicies {
		return Intent{}, ErrProfile
	}
	out.policies = make([]policy, policyCount)
	var previous []byte
	for i := range out.policies {
		start := r.offset
		p := &out.policies[i]
		p.effect = r.u8()
		if p.effect != EffectAllow && p.effect != EffectDeny {
			return Intent{}, ErrProfile
		}
		permissionCount := int(r.u16())
		if permissionCount < 1 || permissionCount > provider.CloudflareMaxPermissionGroups {
			return Intent{}, ErrProfile
		}
		p.permissions = make([][32]byte, permissionCount)
		for j := range p.permissions {
			p.permissions[j] = r.tag()
			if !ValidTag(p.permissions[j]) || j > 0 && bytes.Compare(p.permissions[j-1][:], p.permissions[j][:]) >= 0 {
				return Intent{}, ErrProfile
			}
		}
		resourceCount := int(r.u16())
		if resourceCount < 1 || resourceCount > provider.CloudflareMaxResources {
			return Intent{}, ErrProfile
		}
		p.resources = make([]resource, resourceCount)
		hasAccount, hasAccountZones := false, false
		for j := range p.resources {
			p.resources[j] = resource{kind: r.u8(), tag: r.tag()}
			v := p.resources[j]
			if !ValidTag(v.tag) || v.kind < ResourceAccount || v.kind > ResourceAccountZones ||
				(v.kind == ResourceAccount || v.kind == ResourceAccountZones) && v.tag != out.Account {
				return Intent{}, ErrProfile
			}
			hasAccount = hasAccount || v.kind == ResourceAccount
			hasAccountZones = hasAccountZones || v.kind == ResourceAccountZones
			if j > 0 && compareResource(p.resources[j-1], v) >= 0 {
				return Intent{}, ErrProfile
			}
		}
		if hasAccount && hasAccountZones {
			return Intent{}, ErrProfile
		}
		if r.err != nil {
			return Intent{}, ErrProfile
		}
		p.encoded = bytes.Clone(body[start:r.offset])
		if i > 0 && bytes.Compare(previous, p.encoded) >= 0 {
			return Intent{}, ErrProfile
		}
		previous = p.encoded
	}
	var err error
	if out.in, err = r.prefixes(); err != nil {
		return Intent{}, err
	}
	if out.notIn, err = r.prefixes(); err != nil {
		return Intent{}, err
	}
	var notBefore, expires *time.Time
	if notBefore, err = r.optionalTime(); err != nil {
		return Intent{}, err
	}
	if expires, err = r.optionalTime(); err != nil {
		return Intent{}, err
	}
	if r.err != nil || r.offset != len(body) || notBefore != nil && expires != nil && !notBefore.Before(*expires) {
		return Intent{}, ErrProfile
	}
	if notBefore != nil {
		out.NotBefore = notBefore.Format("2006-01-02T15:04:05Z")
	}
	if expires != nil {
		out.ExpiresOn = expires.Format("2006-01-02T15:04:05Z")
	}
	out.Digest = digest("intent", body)
	return out, nil
}

// PolicyCount returns the number of complete canonical policies.
func (v Intent) PolicyCount() int {
	return len(v.policies)
}

// MatchesPolicies compares complete canonical policy rows in their intent order.
func (v Intent) MatchesPolicies(encoded [][]byte) bool {
	if len(encoded) != len(v.policies) {
		return false
	}
	for i := range encoded {
		if !bytes.Equal(encoded[i], v.policies[i].encoded) {
			return false
		}
	}
	return true
}

// IPConditions returns independently owned lists of the canonical IP prefixes.
func (v Intent) IPConditions() (in, notIn []string) {
	return prefixStrings(v.in), prefixStrings(v.notIn)
}

func prefixStrings(values []prefix) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = values[i].text
	}
	return result
}

// ValidTag reports whether a provider tag has the canonical lowercase hex form.
func ValidTag(tag [32]byte) bool {
	for _, value := range tag {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return tag != [32]byte{}
}

func validName(name []byte) bool {
	if !utf8.Valid(name) {
		return false
	}
	for _, value := range name {
		if value < 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func compareResource(a, b resource) int {
	if a.kind < b.kind {
		return -1
	}
	if a.kind > b.kind {
		return 1
	}
	return bytes.Compare(a.tag[:], b.tag[:])
}

func (r *intentReader) prefixes() ([]prefix, error) {
	count := int(r.u16())
	if count > provider.CloudflareMaxPrefixesPerList {
		return nil, ErrProfile
	}
	result := make([]prefix, count)
	for i := range result {
		result[i].encoded[0] = r.u8()
		copy(result[i].encoded[1:17], r.take(16))
		result[i].encoded[17] = r.u8()
		var address netip.Addr
		bits := int(result[i].encoded[17])
		switch result[i].encoded[0] {
		case familyIPv4:
			if !bytes.Equal(result[i].encoded[1:13], make([]byte, 12)) || bits > 32 {
				return nil, ErrProfile
			}
			var raw [4]byte
			copy(raw[:], result[i].encoded[13:17])
			address = netip.AddrFrom4(raw)
		case familyIPv6:
			if bits > 128 {
				return nil, ErrProfile
			}
			var raw [16]byte
			copy(raw[:], result[i].encoded[1:17])
			address = netip.AddrFrom16(raw)
			if address.Is4In6() {
				return nil, ErrProfile
			}
		default:
			return nil, ErrProfile
		}
		block := netip.PrefixFrom(address, bits)
		if !block.IsValid() || block.Masked().Addr() != address {
			return nil, ErrProfile
		}
		result[i].text = block.String()
		if i > 0 && bytes.Compare(result[i-1].encoded[:], result[i].encoded[:]) >= 0 {
			return nil, ErrProfile
		}
	}
	if r.err != nil {
		return nil, ErrProfile
	}
	return result, nil
}

func (r *intentReader) optionalTime() (*time.Time, error) {
	present := r.u8()
	if present == 0 {
		return nil, nil
	}
	if present != 1 {
		return nil, ErrProfile
	}
	seconds := r.u64()
	if seconds > uint64(^uint64(0)>>1) {
		return nil, ErrProfile
	}
	value := time.Unix(int64(seconds), 0).UTC()
	if value.Year() < 1970 || value.Year() > 9999 || uint64(value.Unix()) != seconds {
		return nil, ErrProfile
	}
	return &value, nil
}

// RequestJSON returns a new compact provider request body from a parsed,
// unmodified Intent. The caller owns and clears the bytes. Refusals return
// ErrProfile; this method does not send the request.
func (v Intent) RequestJSON() ([]byte, error) {
	if !ValidTag(v.Account) || len(v.Name) == 0 || len(v.policies) == 0 {
		return nil, ErrProfile
	}
	body := make([]byte, 0, 4096)
	body = append(body, `{"name":`...)
	body = appendQuoted(body, v.Name)
	body = append(body, `,"policies":[`...)
	for i, p := range v.policies {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, `{"effect":"`...)
		if p.effect == EffectAllow {
			body = append(body, "allow"...)
		} else {
			body = append(body, "deny"...)
		}
		body = append(body, `","permission_groups":[`...)
		for j, permission := range p.permissions {
			if j > 0 {
				body = append(body, ',')
			}
			body = append(body, `{"id":"`...)
			body = append(body, permission[:]...)
			body = append(body, `"}`...)
		}
		body = append(body, `],"resources":{`...)
		resources := append([]resource(nil), p.resources...)
		sort.Slice(resources, func(i, j int) bool { return resourceKey(resources[i]) < resourceKey(resources[j]) })
		for j, resource := range resources {
			if j > 0 {
				body = append(body, ',')
			}
			body = appendQuoted(body, []byte(resourceKey(resource)))
			body = append(body, ':')
			if resource.kind != ResourceAccountZones {
				body = append(body, `"*"`...)
			} else {
				body = append(body, `{"com.cloudflare.api.account.zone.*":"*"}`...)
			}
		}
		body = append(body, "}}"...)
	}
	body = append(body, ']')
	if len(v.in) > 0 || len(v.notIn) > 0 {
		body = append(body, `,"condition":{"request.ip":{`...)
		if len(v.in) > 0 {
			body = append(body, `"in":[`...)
			body = appendPrefixes(body, v.in)
			body = append(body, ']')
		}
		if len(v.notIn) > 0 {
			if len(v.in) > 0 {
				body = append(body, ',')
			}
			body = append(body, `"not_in":[`...)
			body = appendPrefixes(body, v.notIn)
			body = append(body, ']')
		}
		body = append(body, "}}"...)
	}
	if v.NotBefore != "" {
		body = append(body, `,"not_before":"`...)
		body = append(body, v.NotBefore...)
		body = append(body, '"')
	}
	if v.ExpiresOn != "" {
		body = append(body, `,"expires_on":"`...)
		body = append(body, v.ExpiresOn...)
		body = append(body, '"')
	}
	body = append(body, '}')
	if len(body) > provider.CloudflareMaxRequestBytes {
		clear(body)
		return nil, ErrProfile
	}
	return body, nil
}

func appendQuoted(dst, value []byte) []byte {
	result, err := jsontext.AppendQuote(dst, value)
	if err != nil {
		panic("validated UTF-8 refused by jsontext")
	}
	return result
}

func appendPrefixes(dst []byte, values []prefix) []byte {
	for i, value := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendQuoted(dst, []byte(value.text))
	}
	return dst
}

func resourceKey(v resource) string {
	switch v.kind {
	case ResourceAccount, ResourceAccountZones:
		return "com.cloudflare.api.account." + string(v.tag[:])
	case ResourceZone:
		return "com.cloudflare.api.account.zone." + string(v.tag[:])
	default:
		panic("invalid validated resource")
	}
}

func digest(label string, body []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("ENKV/GENERATOR/v1/" + label + "\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(body)
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

type intentReader struct {
	body   []byte
	offset int
	err    error
}

func (r *intentReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.body)-r.offset {
		r.err = ErrProfile
		return nil
	}
	value := r.body[r.offset : r.offset+n]
	r.offset += n
	return value
}

func (r *intentReader) u8() uint8 {
	v := r.take(1)
	if len(v) != 1 {
		return 0
	}
	return v[0]
}

func (r *intentReader) u16() uint16 {
	v := r.take(2)
	if len(v) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

func (r *intentReader) u32() uint32 {
	v := r.take(4)
	if len(v) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *intentReader) u64() uint64 {
	v := r.take(8)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (r *intentReader) tag() [32]byte {
	var out [32]byte
	copy(out[:], r.take(32))
	return out
}

func (r *intentReader) blob(max int) []byte {
	n := r.u32()
	if n > uint32(max) {
		r.err = ErrProfile
		return nil
	}
	return r.take(int(n))
}

// EncodeControls returns an owned binary control record and checks it with
// ParseIntent. Supply an unmodified parsed Intent; the check validates encoded
// structure but does not compare v.Digest. The caller clears the returned bytes
// after use. Invalid controls return ErrProfile.
func EncodeControls(v Intent) ([]byte, error) {
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, v.Account[:]...)
	body = appendBlob(body, v.Name)
	body = binary.BigEndian.AppendUint16(body, uint16(len(v.policies)))
	for _, p := range v.policies {
		body = append(body, p.encoded...)
	}
	for _, list := range [][]prefix{v.in, v.notIn} {
		body = binary.BigEndian.AppendUint16(body, uint16(len(list)))
		for _, p := range list {
			body = append(body, p.encoded[:]...)
		}
	}
	for _, text := range []string{v.NotBefore, v.ExpiresOn} {
		if text == "" {
			body = append(body, 0)
			continue
		}
		value, err := time.Parse("2006-01-02T15:04:05Z", text)
		if err != nil {
			return nil, ErrProfile
		}
		body = append(body, 1)
		body = binary.BigEndian.AppendUint64(body, uint64(value.Unix()))
	}
	if _, err := ParseIntent(body, v.Account); err != nil {
		return nil, err
	}
	return body, nil
}
