package cloudflare

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

const (
	maximumCreateAnnotationLength        = 256
	maximumMessageLength                 = 1024
	maximumDocumentationURLLength        = 2048
	maximumSourcePointerLength           = 256
	maximumPolicyIDLength                = 256
	maximumPermissionNameLength          = 256
	maximumPermissionMetadataRows        = 256
	maximumPermissionMetadataKeyLength   = 256
	maximumPermissionMetadataValueLength = 256
)

type apiEnvelope struct {
	Success  *bool          `json:"success"`
	Errors   *[]apiMessage  `json:"errors"`
	Messages *[]apiMessage  `json:"messages"`
	Result   jsontext.Value `json:"result"`
}

type apiMessage struct {
	Code             *uint32        `json:"code"`
	Message          *string        `json:"message"`
	DocumentationURL *string        `json:"documentation_url"`
	Source           *messageSource `json:"source"`
}

type messageSource struct {
	Pointer *string `json:"pointer"`
}

type createResult struct {
	ID                     *string           `json:"id"`
	Value                  jsontext.Value    `json:"value"`
	Status                 *string           `json:"status"`
	Name                   *string           `json:"name"`
	Policies               *[]responsePolicy `json:"policies"`
	Condition              jsontext.Value    `json:"condition"`
	NotBefore              jsontext.Value    `json:"not_before"`
	ExpiresOn              jsontext.Value    `json:"expires_on"`
	IssuedOn               jsontext.Value    `json:"issued_on"`
	ModifiedOn             jsontext.Value    `json:"modified_on"`
	LastUsedOn             jsontext.Value    `json:"last_used_on"`
	CreatorEmailAtCreation *string           `json:"creator_email_at_creation"`
	ProvisionerID          *string           `json:"provisioner_id"`
	ProvisionerType        *string           `json:"provisioner_type"`
	TokenPrefix            *string           `json:"token_prefix"`
	TokenSuffix            *string           `json:"token_suffix"`
}

func (result *createResult) clearJSON() {
	for _, raw := range []jsontext.Value{result.Value, result.Condition, result.NotBefore, result.ExpiresOn, result.IssuedOn, result.ModifiedOn, result.LastUsedOn} {
		clear(raw[:cap(raw)])
	}
	if result.Policies != nil {
		for _, policy := range *result.Policies {
			for _, raw := range policy.Resources {
				clear(raw[:cap(raw)])
			}
		}
	}
}

type deleteResult struct {
	ID *string `json:"id"`
}

type responsePolicy struct {
	ID               *string                   `json:"id"`
	Effect           *string                   `json:"effect"`
	PermissionGroups *[]responsePermission     `json:"permission_groups"`
	Resources        map[string]jsontext.Value `json:"resources"`
}

type responsePermission struct {
	ID   *string           `json:"id"`
	Name *string           `json:"name"`
	Meta map[string]string `json:"meta"`
}

type responseCondition struct {
	RequestIP *responseIP `json:"request.ip"`
}

type responseIP struct {
	In    *[]string `json:"in"`
	NotIn *[]string `json:"not_in"`
}

// NormalizeCreate maps a bounded provider response to the closed wire facts.
// Partial or invalid bearer bytes are never returned. body is borrowed only for
// this call; returned value bytes are owned by the caller and must be cleared.
// A known token can be retained as owned-unusable without claiming usability.
func NormalizeCreate(status int, body []byte, intent profile.Intent, requestDigest [32]byte) (provider.SafeFacts, []byte) {
	return normalizeCreate(status, body, intent, requestDigest, json.Unmarshal)
}

func normalizeCreate(status int, body []byte, intent profile.Intent, requestDigest [32]byte, decode func([]byte, any, ...json.Options) error) (provider.SafeFacts, []byte) {
	facts := baseFacts(status, intent.Account, intent.Digest, requestDigest)
	envelope, ok := parseEnvelope(body, decode)
	if !ok {
		if status != http.StatusOK {
			facts.Reason = provider.ReasonRejected
		} else {
			facts.Reason = provider.ReasonMalformed
		}
		return facts, nil
	}
	defer clear(envelope.Result[:cap(envelope.Result)])
	facts.ErrorCodes = messageCodes(*envelope.Errors)
	if status != http.StatusOK || envelope.Success == nil || !*envelope.Success || len(*envelope.Errors) != 0 {
		facts.Reason = provider.ReasonRejected
		return facts, nil
	}
	var result createResult
	defer result.clearJSON()
	if isAbsent(envelope.Result) || decode(envelope.Result, &result, json.RejectUnknownMembers(true)) != nil {
		facts.Reason = provider.ReasonMalformed
		return facts, nil
	}
	for _, annotation := range []*string{result.CreatorEmailAtCreation, result.ProvisionerID, result.ProvisionerType, result.TokenPrefix, result.TokenSuffix} {
		if annotation != nil && (len(*annotation) > maximumCreateAnnotationLength || !utf8.ValidString(*annotation)) {
			facts.Reason = provider.ReasonMalformed
			return facts, nil
		}
	}
	if result.TokenSuffix != nil && (len(*result.TokenSuffix) != 4 || utf8.RuneCountInString(*result.TokenSuffix) != 4) {
		facts.Reason = provider.ReasonMalformed
		return facts, nil
	}
	token, ok := parseTag(result.ID)
	if !ok {
		facts.Reason = provider.ReasonMalformed
		return facts, nil
	}
	facts.TokenPresent, facts.TokenID = 1, provider.ID(token)

	secret, valueReason := parseSecret(result.Value)
	controls, echo, issued, modified, lastUsed := matchCreateResult(result, intent)
	facts.EchoPresence = echo
	facts.IssuedUTC, facts.ModifiedUTC, facts.LastUsedUTC = issued, modified, lastUsed
	statusValue, statusOK := parseTokenStatus(result.Status)
	facts.TokenStatus = statusValue
	reason := valueReason
	if reason == provider.ReasonNone && !controls {
		reason = provider.ReasonControls
	}
	if reason == provider.ReasonNone && (!statusOK || statusValue != provider.TokenStatusActive) {
		reason = provider.ReasonInactive
	}
	if reason != provider.ReasonNone {
		clear(secret[:cap(secret)])
		facts.Disposition, facts.Reason = provider.DispositionOwnedUnusableCreate, reason
		return facts, nil
	}
	facts.Disposition = provider.DispositionCompleteCreate
	facts.Reason = provider.ReasonNone
	facts.MatchedControlsDigest = provider.ID(intent.Digest)
	return facts, secret
}

// NormalizeDelete accepts only the exact retained token acknowledgement. It
// borrows body for the call and returns no aliases. Success does not prove that
// prior bearer values can no longer be used.
func NormalizeDelete(status int, body []byte, account, target, intentDigest, requestDigest [32]byte) provider.SafeFacts {
	return normalizeDelete(status, body, account, target, intentDigest, requestDigest, json.Unmarshal)
}

func normalizeDelete(status int, body []byte, account, target, intentDigest, requestDigest [32]byte, decode func([]byte, any, ...json.Options) error) provider.SafeFacts {
	facts := baseFacts(status, account, intentDigest, requestDigest)
	envelope, ok := parseEnvelope(body, decode)
	if !ok {
		if status != http.StatusOK {
			facts.Reason = provider.ReasonRejected
		} else {
			facts.Reason = provider.ReasonMalformed
		}
		return facts
	}
	defer clear(envelope.Result[:cap(envelope.Result)])
	facts.ErrorCodes = messageCodes(*envelope.Errors)
	if status != http.StatusOK || envelope.Success == nil || !*envelope.Success || len(*envelope.Errors) != 0 {
		facts.Reason = provider.ReasonRejected
		return facts
	}
	var result deleteResult
	if isAbsent(envelope.Result) || decode(envelope.Result, &result, json.RejectUnknownMembers(true)) != nil {
		facts.Reason = provider.ReasonMalformed
		return facts
	}
	token, ok := parseTag(result.ID)
	if !ok {
		facts.Reason = provider.ReasonMalformed
		return facts
	}
	if token != target {
		// A well-formed different identity is a binding contradiction, not
		// generic missing evidence. Retain the reported ID so Core cannot
		// turn this observation into eligible residue or retarget cleanup.
		facts.Reason = provider.ReasonIdentityConflict
		facts.TokenPresent, facts.TokenID = 1, provider.ID(token)
		return facts
	}
	facts.Disposition, facts.Reason = provider.DispositionDeleteAcknowledged, provider.ReasonNone
	facts.TokenPresent, facts.TokenID = 1, provider.ID(token)
	return facts
}

func baseFacts(status int, account, intentDigest, requestDigest [32]byte) provider.SafeFacts {
	httpStatus := uint16(provider.HTTPStatusAbsent)
	if status >= http.StatusContinue && status <= provider.HTTPStatusMaximum {
		httpStatus = uint16(status)
	}
	return provider.SafeFacts{
		Schema: 1, Disposition: provider.DispositionUnknown, Reason: provider.ReasonMalformed, HTTPStatus: httpStatus,
		Account: provider.ID(account), RequestDigest: provider.ID(requestDigest), IntentDigest: provider.ID(intentDigest),
	}
}

func parseEnvelope(body []byte, decode func([]byte, any, ...json.Options) error) (apiEnvelope, bool) {
	var envelope apiEnvelope
	if len(body) == 0 || len(body) > provider.CloudflareMaxResponseBytes || validateJSON(body, provider.CloudflareMaxResponseDepth, provider.CloudflareMaxResponseNodes) != nil ||
		decode(body, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.Success == nil ||
		envelope.Errors == nil || envelope.Messages == nil || len(bytes.TrimSpace(envelope.Result)) == 0 ||
		len(*envelope.Errors) > provider.CloudflareMaxDiagnosticRows || len(*envelope.Messages) > provider.CloudflareMaxDiagnosticRows || !validMessages(*envelope.Errors) || !validMessages(*envelope.Messages) {
		clear(envelope.Result[:cap(envelope.Result)])
		return apiEnvelope{}, false
	}
	return envelope, true
}

func validMessages(rows []apiMessage) bool {
	for _, row := range rows {
		if row.Code == nil || row.Message == nil || len(*row.Message) > maximumMessageLength || !utf8.ValidString(*row.Message) {
			return false
		}
		if row.DocumentationURL != nil && (len(*row.DocumentationURL) > maximumDocumentationURLLength || !utf8.ValidString(*row.DocumentationURL)) {
			return false
		}
		if row.Source != nil && (row.Source.Pointer == nil || len(*row.Source.Pointer) > maximumSourcePointerLength || !utf8.ValidString(*row.Source.Pointer)) {
			return false
		}
	}
	return true
}

func messageCodes(rows []apiMessage) []uint32 {
	result := make([]uint32, len(rows))
	for i := range rows {
		result[i] = *rows[i].Code
	}
	return result
}

func parseTag(value *string) ([32]byte, bool) {
	var tag [32]byte
	if value == nil || len(*value) != len(tag) {
		return tag, false
	}
	copy(tag[:], *value)
	return tag, profile.ValidTag(tag)
}

func parseSecret(raw jsontext.Value) ([]byte, uint8) {
	if isAbsent(raw) {
		return nil, provider.ReasonMissingValue
	}
	if raw.Kind() != '"' {
		return nil, provider.ReasonInvalidValue
	}
	secret, err := jsontext.AppendUnquote(nil, raw)
	if err != nil || !provider.ValidBearer(secret) {
		clear(secret[:cap(secret)])
		return nil, provider.ReasonInvalidValue
	}
	return secret, provider.ReasonNone
}

func parseTokenStatus(value *string) (uint8, bool) {
	if value == nil {
		return provider.TokenStatusAbsent, false
	}
	switch *value {
	case "active":
		return provider.TokenStatusActive, true
	case "disabled":
		return provider.TokenStatusDisabled, true
	case "expired":
		return provider.TokenStatusExpired, true
	default:
		return provider.TokenStatusAbsent, false
	}
}

func matchCreateResult(result createResult, intent profile.Intent) (bool, uint16, []byte, []byte, []byte) {
	echo := uint16(provider.EchoNone)
	nameOK := result.Name != nil && *result.Name == string(intent.Name)
	if result.Name != nil {
		echo |= provider.EchoName
	}
	policiesOK := result.Policies != nil && matchPolicies(*result.Policies, intent)
	if result.Policies != nil {
		echo |= provider.EchoPolicies
	}
	conditionPresent, conditionOK := matchCondition(result.Condition, intent)
	if conditionPresent {
		echo |= provider.EchoCondition
	}
	notBeforePresent, notBeforeOK := matchOptionalString(result.NotBefore, intent.NotBefore)
	if notBeforePresent {
		echo |= provider.EchoNotBefore
	}
	expiresPresent, expiresOK := matchOptionalString(result.ExpiresOn, intent.ExpiresOn)
	if expiresPresent {
		echo |= provider.EchoExpiry
	}
	issued, issuedOK := optionalTimestamp(result.IssuedOn)
	modified, modifiedOK := optionalTimestamp(result.ModifiedOn)
	lastUsed, lastUsedOK := optionalTimestamp(result.LastUsedOn)
	return nameOK && policiesOK && conditionOK && notBeforeOK && expiresOK && issuedOK && modifiedOK && lastUsedOK,
		echo, issued, modified, lastUsed
}

func matchPolicies(values []responsePolicy, intent profile.Intent) bool {
	if len(values) != intent.PolicyCount() {
		return false
	}
	encoded := make([][]byte, len(values))
	for i, value := range values {
		if value.ID != nil && (len(*value.ID) > maximumPolicyIDLength || !utf8.ValidString(*value.ID)) || value.Effect == nil || value.PermissionGroups == nil || value.Resources == nil {
			return false
		}
		var effect uint8
		switch *value.Effect {
		case "allow":
			effect = profile.EffectAllow
		case "deny":
			effect = profile.EffectDeny
		default:
			return false
		}
		permissions := make([][32]byte, len(*value.PermissionGroups))
		if len(permissions) < 1 || len(permissions) > provider.CloudflareMaxPermissionGroups {
			return false
		}
		for j, permission := range *value.PermissionGroups {
			var ok bool
			permissions[j], ok = parseTag(permission.ID)
			if !ok || permission.Name != nil && (len(*permission.Name) > maximumPermissionNameLength || !utf8.ValidString(*permission.Name)) || len(permission.Meta) > maximumPermissionMetadataRows {
				return false
			}
			for key, item := range permission.Meta {
				if len(key) > maximumPermissionMetadataKeyLength || len(item) > maximumPermissionMetadataValueLength || !utf8.ValidString(key) || !utf8.ValidString(item) {
					return false
				}
			}
		}
		sort.Slice(permissions, func(i, j int) bool { return bytes.Compare(permissions[i][:], permissions[j][:]) < 0 })
		for j := 1; j < len(permissions); j++ {
			if permissions[j-1] == permissions[j] {
				return false
			}
		}
		resources, ok := normalizeResources(value.Resources, intent.Account)
		if !ok || len(resources) < 1 || len(resources) > provider.CloudflareMaxResources {
			return false
		}
		row := []byte{effect}
		row = appendU16(row, len(permissions))
		for _, permission := range permissions {
			row = append(row, permission[:]...)
		}
		row = appendU16(row, len(resources))
		for _, resource := range resources {
			row = append(row, resource.kind)
			row = append(row, resource.tag[:]...)
		}
		encoded[i] = row
	}
	sort.Slice(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })
	return intent.MatchesPolicies(encoded)
}

type resource struct {
	kind uint8
	tag  [32]byte
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

func normalizeResources(values map[string]jsontext.Value, account [32]byte) ([]resource, bool) {
	resources := make([]resource, 0, len(values))
	for key, raw := range values {
		const prefix = "com.cloudflare.api.account."
		if !strings.HasPrefix(key, prefix) {
			return nil, false
		}
		remainder := strings.TrimPrefix(key, prefix)
		var item resource
		if remainder == string(account[:]) {
			item.tag = account
			var marker string
			if json.Unmarshal(raw, &marker) == nil && marker == "*" {
				item.kind = profile.ResourceAccount
			} else {
				var nested map[string]string
				if json.Unmarshal(raw, &nested) != nil || len(nested) != 1 || nested["com.cloudflare.api.account.zone.*"] != "*" {
					return nil, false
				}
				item.kind = profile.ResourceAccountZones
			}
		} else if strings.HasPrefix(remainder, "zone.") {
			value := strings.TrimPrefix(remainder, "zone.")
			if len(value) != 32 {
				return nil, false
			}
			copy(item.tag[:], value)
			var marker string
			if !profile.ValidTag(item.tag) || json.Unmarshal(raw, &marker) != nil || marker != "*" {
				return nil, false
			}
			item.kind = profile.ResourceZone
		} else {
			return nil, false
		}
		resources = append(resources, item)
	}
	sort.Slice(resources, func(i, j int) bool { return compareResource(resources[i], resources[j]) < 0 })
	for i := 1; i < len(resources); i++ {
		if compareResource(resources[i-1], resources[i]) == 0 {
			return nil, false
		}
	}
	return resources, true
}

func matchCondition(raw jsontext.Value, intent profile.Intent) (bool, bool) {
	wantIn, wantNotIn := intent.IPConditions()
	wantPresent := len(wantIn) > 0 || len(wantNotIn) > 0
	if isAbsent(raw) {
		return false, !wantPresent
	}
	var condition responseCondition
	if json.Unmarshal(raw, &condition, json.RejectUnknownMembers(true)) != nil {
		return true, false
	}
	if condition.RequestIP == nil {
		return false, !wantPresent
	}
	gotIn, gotNotIn := []string(nil), []string(nil)
	if condition.RequestIP.In != nil {
		gotIn = append(gotIn, (*condition.RequestIP.In)...)
	}
	if condition.RequestIP.NotIn != nil {
		gotNotIn = append(gotNotIn, (*condition.RequestIP.NotIn)...)
	}
	sort.Strings(gotIn)
	sort.Strings(gotNotIn)
	sort.Strings(wantIn)
	sort.Strings(wantNotIn)
	if len(gotIn) == 0 && len(gotNotIn) == 0 {
		return false, !wantPresent
	}
	return true, slicesEqual(gotIn, wantIn) && slicesEqual(gotNotIn, wantNotIn) && wantPresent
}

func matchOptionalString(raw jsontext.Value, want string) (bool, bool) {
	if isAbsent(raw) {
		return false, want == ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return true, false
	}
	if value == "" {
		return false, want == ""
	}
	return true, value == want
}

func optionalTimestamp(raw jsontext.Value) ([]byte, bool) {
	if isAbsent(raw) {
		return nil, true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	if value == "" {
		return nil, true
	}
	if len(value) > provider.ObservationTimeMaxLength || !isASCII(value) {
		return nil, false
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return nil, false
	}
	return []byte(value), true
}

func isAbsent(raw jsontext.Value) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for i := range value {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

func appendU16(dst []byte, value int) []byte {
	return append(dst, byte(value>>8), byte(value))
}

func validateJSON(body []byte, maximumDepth, maximumNodes int) error {
	decoder := jsontext.NewDecoder(bytes.NewReader(body))
	nodes := 0
	if err := readJSONNode(decoder, 1, maximumDepth, maximumNodes, &nodes); err != nil {
		return err
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		if err == nil {
			return profile.ErrProfile
		}
		return err
	}
	return nil
}

func readJSONNode(decoder *jsontext.Decoder, depth, maximumDepth, maximumNodes int, nodes *int) error {
	*nodes++
	kind := decoder.PeekKind()
	if *nodes > maximumNodes || (kind == '{' || kind == '[') && depth > maximumDepth {
		return profile.ErrProfile
	}
	nextDepth := func() int {
		if decoder.PeekKind() == '{' || decoder.PeekKind() == '[' {
			return depth + 1
		}
		return depth
	}
	switch kind {
	case '{':
		if _, err := decoder.ReadToken(); err != nil {
			return err
		}
		for decoder.PeekKind() != '}' {
			name, err := decoder.ReadToken()
			if err != nil || name.Kind() != '"' {
				if err != nil {
					return err
				}
				return profile.ErrProfile
			}
			if err := readJSONNode(decoder, nextDepth(), maximumDepth, maximumNodes, nodes); err != nil {
				return err
			}
		}
		_, err := decoder.ReadToken()
		return err
	case '[':
		if _, err := decoder.ReadToken(); err != nil {
			return err
		}
		for decoder.PeekKind() != ']' {
			if err := readJSONNode(decoder, nextDepth(), maximumDepth, maximumNodes, nodes); err != nil {
				return err
			}
		}
		_, err := decoder.ReadToken()
		return err
	default:
		_, err := decoder.ReadToken()
		return err
	}
}
