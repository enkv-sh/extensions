package cloudflare

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

func createEnvelope(t *testing.T, value string) ([]byte, profile.Intent, [32]byte) {
	t.Helper()
	intentBody, account, _ := testIntent(t)
	intent, err := profile.ParseIntent(intentBody, account)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := testTag(9)
	permission := testTag(1)
	zone := testTag(2)
	token := testTag(3)
	body := fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"edge-\"token\\one","policies":[{"id":"server-policy","effect":"allow","permission_groups":[{"id":"%s","name":"read","meta":{"scope":"account"}}],"resources":{"com.cloudflare.api.account.%s":"*","com.cloudflare.api.account.zone.%s":"*"}}],"condition":{"request.ip":{"in":["192.0.2.0/24"],"not_in":["2001:db8::/32"]}},"not_before":"2024-01-01T00:00:00Z","expires_on":"2025-01-01T00:00:00Z","issued_on":"2025-01-01T00:00:00Z","modified_on":null,"last_used_on":""}}`, token, value, permission, account, zone)
	return []byte(body), intent, requestDigest
}

// full_only: false
func TestNormalizeCompleteCreate(t *testing.T) {
	value := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	body, intent, requestDigest := createEnvelope(t, value)
	annotations := map[string]string{
		"missing":     "",
		"null":        "null",
		"empty":       `""`,
		"text":        `"creator-annotation@example.invalid"`,
		"limit":       `"` + strings.Repeat("x", 256) + `"`,
		"UTF-8 limit": `"` + strings.Repeat("ü", 128) + `"`,
	}
	for name, annotation := range annotations {
		t.Run(name, func(t *testing.T) {
			response := body
			if annotation != "" {
				response = replaceResponse(t, body, `"status":"active"`, `"status":"active","creator_email_at_creation":`+annotation)
			}
			facts, secret := NormalizeCreate(200, response, intent, requestDigest)
			defer clear(secret)
			if facts.Disposition != 1 || facts.Reason != 0 || facts.TokenPresent != 1 || facts.TokenStatus != 1 || facts.EchoPresence != 31 ||
				facts.RequestDigest != provider.ID(requestDigest) || facts.IntentDigest != provider.ID(intent.Digest) || facts.MatchedControlsDigest != provider.ID(intent.Digest) || string(secret) != value {
				t.Fatalf("unexpected complete create: facts=%+v secret=%q", facts, secret)
			}
		})
	}
	metadata := map[string]string{
		"provisioner_id":   `"provisioner-annotation"`,
		"provisioner_type": `"com.cloudflare.api.oauthtoken"`,
		"token_prefix":     `"cfat"`,
		"token_suffix":     `"KLMN"`,
	}
	baseline, baselineSecret := NormalizeCreate(200, body, intent, requestDigest)
	defer clear(baselineSecret)
	allMetadata := `"status":"active"`
	for field, annotation := range metadata {
		allMetadata += `,"` + field + `":` + annotation
		values := map[string]string{"text": annotation, "null": "null"}
		if field != "token_suffix" {
			values["empty"], values["limit"], values["UTF-8 limit"] = `""`, `"`+strings.Repeat("x", 256)+`"`, `"`+strings.Repeat("ü", 128)+`"`
		}
		for name, valueJSON := range values {
			t.Run(field+"/"+name, func(t *testing.T) {
				response := replaceResponse(t, body, `"status":"active"`, `"status":"active","`+field+`":`+valueJSON)
				facts, secret := NormalizeCreate(200, response, intent, requestDigest)
				defer clear(secret)
				if facts.Disposition != 1 || facts.Reason != 0 || facts.TokenPresent != 1 || facts.TokenID != provider.ID(testTag(3)) || facts.TokenStatus != 1 || facts.EchoPresence != 31 ||
					facts.RequestDigest != provider.ID(requestDigest) || facts.IntentDigest != provider.ID(intent.Digest) || facts.MatchedControlsDigest != provider.ID(intent.Digest) || string(secret) != value {
					t.Fatal("documented response metadata changed complete create facts")
				}
				if !reflect.DeepEqual(facts, baseline) {
					t.Fatal("metadata entered normalized facts")
				}
			})
		}
	}
	facts, secret := NormalizeCreate(200, replaceResponse(t, body, `"status":"active"`, allMetadata), intent, requestDigest)
	defer clear(secret)
	if !reflect.DeepEqual(facts, baseline) || !bytes.Equal(secret, baselineSecret) {
		t.Fatal("combined metadata changed normalized facts or value")
	}
}

// full_only: false
func TestNormalizeOwnedUnusableCreateNeverReturnsPartialSecret(t *testing.T) {
	body, intent, requestDigest := createEnvelope(t, "short-secret")
	body = replaceResponse(t, body, `"status":"active"`, `"status":"active","creator_email_at_creation":"creator-annotation@example.invalid","provisioner_id":"annotation","provisioner_type":"annotation","token_prefix":"cfat","token_suffix":"cret"`)
	facts, secret := NormalizeCreate(200, body, intent, requestDigest)
	if facts.Disposition != 2 || facts.Reason != 2 || facts.TokenPresent != 1 || len(secret) != 0 {
		t.Fatalf("unexpected owned create: facts=%+v secret=%q", facts, secret)
	}
}

// full_only: false
func TestNormalizeCreateRejectsMalformedCreatorAnnotationBeforeRetainingID(t *testing.T) {
	body, intent, requestDigest := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	annotations := map[string]string{
		"number":              `"creator_email_at_creation":1`,
		"boolean":             `"creator_email_at_creation":true`,
		"array":               `"creator_email_at_creation":[]`,
		"object":              `"creator_email_at_creation":{}`,
		"excess bytes":        `"creator_email_at_creation":"` + strings.Repeat("x", 257) + `"`,
		"excess UTF-8 bytes":  `"creator_email_at_creation":"` + strings.Repeat("ü", 128) + `x"`,
		"invalid UTF-8":       `"creator_email_at_creation":"` + string([]byte{0xff}) + `"`,
		"invalid surrogate":   `"creator_email_at_creation":"\ud800"`,
		"duplicate":           `"creator_email_at_creation":null,"creator_email_at_creation":null`,
		"escaped duplicate":   `"creator_email_at_creation":null,"creator_email_at_creatio\u006e":null`,
		"other unknown field": `"creator_email_at_creation":null,"another_annotation":"text"`,
		"unknown case":        `"Creator_Email_At_Creation":"text"`,
	}
	for name, annotation := range annotations {
		t.Run(name, func(t *testing.T) {
			response := replaceResponse(t, body, `"status":"active"`, `"status":"active",`+annotation)
			facts, secret := NormalizeCreate(200, response, intent, requestDigest)
			defer clear(secret)
			if facts.Disposition != 4 || facts.Reason != 5 || facts.TokenPresent != 0 || !facts.TokenID.IsZero() || len(secret) != 0 {
				t.Fatal("malformed annotation retained an identity or value", facts)
			}
		})
	}
}

// full_only: false
func TestNormalizeDeleteRequiresExactAcknowledgement(t *testing.T) {
	account, target, intentDigest, requestDigest := testTag(0), testTag(3), testTag(7), testTag(9)
	body := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, target))
	facts := NormalizeDelete(200, body, account, target, intentDigest, requestDigest)
	if facts.Disposition != 3 || facts.Reason != 0 || facts.TokenID != provider.ID(target) || facts.IntentDigest != provider.ID(intentDigest) || !facts.MatchedControlsDigest.IsZero() {
		t.Fatalf("unexpected delete acknowledgement: %+v", facts)
	}
	wrong := bytes.Clone(body)
	wrong[len(wrong)-4] ^= 1
	if facts := NormalizeDelete(200, wrong, account, target, intentDigest, requestDigest); facts.Disposition != 4 || facts.Reason != 10 || facts.TokenPresent != 1 || facts.TokenID == provider.ID(target) {
		t.Fatalf("mismatch was not unknown: %+v", facts)
	}
}

// full_only: false
func TestNormalizeRejectsAmbiguousAndUnboundedJSON(t *testing.T) {
	_, intent, requestDigest := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	tests := map[string][]byte{
		"duplicate":     []byte(`{"success":true,"success":true,"errors":[],"messages":[],"result":null}`),
		"unknown":       []byte(`{"success":false,"errors":[],"messages":[],"result":null,"other":1}`),
		"invalid UTF-8": append([]byte(`{"success":false,"errors":[{"code":1,"message":"`), append([]byte{0xff}, []byte(`"}],"messages":[],"result":null}`)...)...),
		"trailing":      []byte(`{"success":false,"errors":[],"messages":[],"result":null} {}`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			facts, secret := NormalizeCreate(200, body, intent, requestDigest)
			if facts.Disposition != 4 || facts.Reason != 5 || len(secret) != 0 {
				t.Fatalf("ambiguous JSON escaped: facts=%+v secret=%q", facts, secret)
			}
		})
	}
	if validateJSON([]byte(`{"a":{"b":1}}`), 2, 4) != nil {
		t.Fatal("exact JSON depth refused")
	}
	if validateJSON([]byte(`{"a":{"b":{}}}`), 2, 4) == nil {
		t.Fatal("excess JSON depth accepted")
	}
	if validateJSON([]byte(`[1,2,3]`), 4, 3) == nil {
		t.Fatal("excess JSON nodes accepted")
	}
}

// full_only: false
func TestProviderFailureRemainsUnknown(t *testing.T) {
	_, intent, requestDigest := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	body := []byte(`{"success":false,"errors":[{"code":9109,"message":"denied"}],"messages":[],"result":null}`)
	facts, secret := NormalizeCreate(403, body, intent, requestDigest)
	if facts.Disposition != 4 || facts.Reason != 7 || facts.HTTPStatus != 403 || len(facts.ErrorCodes) != 1 || facts.ErrorCodes[0] != 9109 || len(secret) != 0 {
		t.Fatalf("rejection changed meaning: facts=%+v secret=%q", facts, secret)
	}
}

// full_only: false
func TestNormalizeCreateStrictPredicateFailures(t *testing.T) {
	body, intent, requestDigest := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	body = replaceResponse(t, body, `"status":"active"`, `"status":"active","provisioner_id":null,"provisioner_type":"annotation","token_prefix":"cfat","token_suffix":"KLMN"`)
	tokenID := testTag(3)
	token := string(tokenID[:])
	type responseCase struct {
		name         string
		body         []byte
		disposition  uint8
		reason       uint8
		tokenPresent uint8
	}
	tests := []responseCase{
		{name: "missing ID", body: replaceResponse(t, body, `"id":"`+token+`",`, ""), disposition: 4, reason: 5},
		{name: "invalid ID", body: replaceResponse(t, body, token, "g"+token[1:]), disposition: 4, reason: 5},
		{name: "missing value", body: replaceResponse(t, body, `"value":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",`, ""), disposition: 2, reason: 1, tokenPresent: 1},
		{name: "invalid value grammar", body: replaceResponse(t, body, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM!"), disposition: 2, reason: 2, tokenPresent: 1},
		{name: "oversized value", body: replaceResponse(t, body, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", strings.Repeat("a", 81)), disposition: 2, reason: 2, tokenPresent: 1},
		{name: "missing status", body: replaceResponse(t, body, `"status":"active",`, ""), disposition: 2, reason: 4, tokenPresent: 1},
		{name: "inactive status", body: replaceResponse(t, body, `"status":"active"`, `"status":"disabled"`), disposition: 2, reason: 4, tokenPresent: 1},
		{name: "missing name", body: replaceResponse(t, body, `"name":"edge-\"token\\one",`, ""), disposition: 2, reason: 3, tokenPresent: 1},
		{name: "conflicting name", body: replaceResponse(t, body, `"name":"edge-\"token\\one"`, `"name":"different"`), disposition: 2, reason: 3, tokenPresent: 1},
		{name: "missing policies", body: removeResponseSpan(t, body, `"policies":[`, `"condition":`), disposition: 2, reason: 3, tokenPresent: 1},
		{name: "unknown result member", body: replaceResponse(t, body, `"status":"active"`, `"status":"active","unknown":true`), disposition: 4, reason: 5},
		{name: "duplicate nested member", body: replaceResponse(t, body, `"effect":"allow"`, `"effect":"allow","effect":"allow"`), disposition: 4, reason: 5},
		{name: "invalid optional timestamp", body: replaceResponse(t, body, `"issued_on":"2025-01-01T00:00:00Z"`, `"issued_on":"not-a-time"`), disposition: 2, reason: 3, tokenPresent: 1},
		{name: "oversized optional timestamp", body: replaceResponse(t, body, `"issued_on":"2025-01-01T00:00:00Z"`, `"issued_on":"`+strings.Repeat("x", 65)+`"`), disposition: 2, reason: 3, tokenPresent: 1},
	}
	for _, field := range []string{"provisioner_id", "provisioner_type", "token_prefix", "token_suffix"} {
		original, _, _ := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
		for name, value := range map[string]string{
			"wrong type": `[]`, "oversize": `"` + strings.Repeat("x", 257) + `"`,
			"duplicate": `null,"` + field + `":null`, "folded name": `null,"` + strings.ToUpper(field) + `":null`,
			"invalid UTF-8": `"` + string([]byte{0xff}) + `"`, "invalid surrogate": `"\ud800"`,
		} {
			tests = append(tests, responseCase{
				name: field + "/" + name, body: replaceResponse(t, original, `"status":"active"`, `"status":"active","`+field+`":`+value), disposition: 4, reason: 5,
			})
		}
	}
	for _, suffix := range []string{`""`, `"abc"`, `"abcde"`, `"éab"`} {
		tests = append(tests, responseCase{
			name: "invalid suffix/" + suffix, body: replaceResponse(t, body, `"token_suffix":"KLMN"`, `"token_suffix":`+suffix), disposition: 4, reason: 5,
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts, secret := NormalizeCreate(200, test.body, intent, requestDigest)
			defer clear(secret)
			if facts.Disposition != test.disposition || facts.Reason != test.reason || facts.TokenPresent != test.tokenPresent || len(secret) != 0 {
				t.Fatalf("predicate failure escaped: facts=%+v secret=%q", facts, secret)
			}
		})
	}
}

// full_only: false
func TestNormalizeEnvelopeBoundsAndClosedMessages(t *testing.T) {
	_, intent, requestDigest := createEnvelope(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	tests := []struct {
		name string
		body []byte
	}{
		{name: "response bytes", body: append([]byte(`{"success":false,"errors":[],"messages":[],"result":null}`), bytes.Repeat([]byte(" "), provider.CloudflareMaxResponseBytes)...)},
		{name: "error rows", body: []byte(`{"success":false,"errors":[` + strings.Repeat(`{"code":1,"message":"x"},`, 16) + `{"code":1,"message":"x"}],"messages":[],"result":null}`)},
		{name: "message text", body: []byte(`{"success":false,"errors":[{"code":1,"message":"` + strings.Repeat("x", 1025) + `"}],"messages":[],"result":null}`)},
		{name: "message URL", body: []byte(`{"success":false,"errors":[{"code":1,"message":"x","documentation_url":"` + strings.Repeat("x", 2049) + `"}],"messages":[],"result":null}`)},
		{name: "message pointer", body: []byte(`{"success":false,"errors":[{"code":1,"message":"x","source":{"pointer":"` + strings.Repeat("x", 257) + `"}}],"messages":[],"result":null}`)},
		{name: "unknown message member", body: []byte(`{"success":false,"errors":[{"code":1,"message":"x","unknown":true}],"messages":[],"result":null}`)},
		{name: "duplicate message member", body: []byte(`{"success":false,"errors":[{"code":1,"code":2,"message":"x"}],"messages":[],"result":null}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts, secret := NormalizeCreate(200, test.body, intent, requestDigest)
			defer clear(secret)
			if facts.Disposition != 4 || facts.Reason != 5 || len(secret) != 0 {
				t.Fatalf("bounded envelope escaped: facts=%+v secret=%q", facts, secret)
			}
		})
	}
}

// full_only: false
func TestNormalizeDeleteStrictPredicateFailures(t *testing.T) {
	account, target, intentDigest, requestDigest := testTag(0), testTag(3), testTag(7), testTag(9)
	wrongTarget := testTag(4)
	token := string(target[:])
	valid := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, token))
	tests := []struct {
		name         string
		status       int
		body         []byte
		reason       uint8
		tokenPresent uint8
	}{
		{name: "missing ID", status: 200, body: replaceResponse(t, valid, `"id":"`+token+`"`, ""), reason: 5},
		{name: "invalid ID", status: 200, body: replaceResponse(t, valid, token, "g"+token[1:]), reason: 5},
		{name: "wrong ID", status: 200, body: replaceResponse(t, valid, token, string(wrongTarget[:])), reason: 10, tokenPresent: 1},
		{name: "unknown result member", status: 200, body: replaceResponse(t, valid, `"id":"`+token+`"`, `"id":"`+token+`","unknown":true`), reason: 5},
		{name: "create annotation", status: 200, body: replaceResponse(t, valid, `"id":"`+token+`"`, `"id":"`+token+`","creator_email_at_creation":"creator-annotation@example.invalid"`), reason: 5},
		{name: "duplicate ID", status: 200, body: replaceResponse(t, valid, `"id":"`+token+`"`, `"id":"`+token+`","id":"`+token+`"`), reason: 5},
		{name: "false success", status: 200, body: replaceResponse(t, valid, `"success":true`, `"success":false`), reason: 7},
		{name: "wrong status", status: 204, body: valid, reason: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := NormalizeDelete(test.status, test.body, account, target, intentDigest, requestDigest)
			if facts.Disposition != 4 || facts.Reason != test.reason || facts.TokenPresent != test.tokenPresent || test.tokenPresent == 1 && facts.TokenID != provider.ID(wrongTarget) {
				t.Fatalf("delete predicate failure escaped: %+v", facts)
			}
		})
	}
}

// full_only: false
func TestNormalizeResponseClearsOwnedJSONCopies(t *testing.T) {
	const value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	body, intent, requestDigest := createEnvelope(t, value)
	account, target, zone := intent.Account, testTag(3), testTag(2)
	wrongTarget := testTag(4)
	deleteBody := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, target))
	fullCopies := []string{
		"envelope.result", "result.value", "result.condition", "result.not_before", "result.expires_on",
		"result.issued_on", "result.modified_on", "result.last_used_on",
		"result.resources.com.cloudflare.api.account." + string(account[:]),
		"result.resources.com.cloudflare.api.account.zone." + string(zone[:]),
	}
	partialResult := replaceResponse(t, body, `"status":"active"`, `"status":[]`)
	partialEnvelope := append(bytes.Clone(body[:len(body)-1]), []byte(`,"unknown":true}`)...)
	resultStart := bytes.Index(body, []byte(`"result":`)) + len(`"result":`)
	resultJSON := body[resultStart : len(body)-1]
	invalidMessages := append([]byte(`{"result":`), resultJSON...)
	invalidMessages = append(invalidMessages, []byte(`,"success":true,"errors":[],"messages":[{"code":1}]}`)...)
	tests := []struct {
		name        string
		delete      bool
		status      int
		body        []byte
		copies      []string
		disposition uint8
		reason      uint8
		secret      string
	}{
		{name: "complete create transfers exact secret", status: 200, body: body, copies: fullCopies, disposition: 1, secret: value},
		{name: "unusable controls after secret extraction", status: 200, body: replaceResponse(t, body, `"name":"edge-\"token\\one"`, `"name":"different"`), copies: fullCopies, disposition: 2, reason: 3},
		{name: "inactive after secret extraction", status: 200, body: replaceResponse(t, body, `"status":"active"`, `"status":"disabled"`), copies: fullCopies, disposition: 2, reason: 4},
		{name: "invalid value", status: 200, body: replaceResponse(t, body, value, "short-secret"), copies: fullCopies, disposition: 2, reason: 2},
		{name: "invalid identity", status: 200, body: replaceResponse(t, body, string(target[:]), "g"+string(target[1:])), copies: fullCopies, disposition: 4, reason: 5},
		{name: "invalid annotation", status: 200, body: replaceResponse(t, body, `"status":"active"`, `"status":"active","provisioner_id":"`+strings.Repeat("x", 257)+`"`), copies: fullCopies, disposition: 4, reason: 5},
		{name: "partial result decode", status: 200, body: partialResult, copies: []string{"envelope.result", "result.value"}, disposition: 4, reason: 5},
		{name: "late result decode failure", status: 200, body: replaceResponse(t, body, `"last_used_on":""`, `"last_used_on":"","unknown":true`), copies: fullCopies, disposition: 4, reason: 5},
		{name: "partial envelope decode", status: 200, body: partialEnvelope, copies: []string{"envelope.result"}, disposition: 4, reason: 5},
		{name: "invalid envelope messages", status: 200, body: invalidMessages, copies: []string{"envelope.result"}, disposition: 4, reason: 5},
		{name: "missing envelope member", status: 200, body: replaceResponse(t, body, `"messages":[],`, ""), copies: []string{"envelope.result"}, disposition: 4, reason: 5},
		{name: "rejected create HTTP status", status: 503, body: body, copies: []string{"envelope.result"}, disposition: 4, reason: 7},
		{name: "rejected create service status", status: 200, body: replaceResponse(t, body, `"success":true`, `"success":false`), copies: []string{"envelope.result"}, disposition: 4, reason: 7},
		{name: "complete delete", delete: true, status: 200, body: deleteBody, copies: []string{"envelope.result"}, disposition: 3},
		{name: "delete conflicting identity", delete: true, status: 200, body: replaceResponse(t, deleteBody, string(target[:]), string(wrongTarget[:])), copies: []string{"envelope.result"}, disposition: 4, reason: 10},
		{name: "rejected delete HTTP status", delete: true, status: 503, body: deleteBody, copies: []string{"envelope.result"}, disposition: 4, reason: 7},
		{name: "delete result decode failure", delete: true, status: 200, body: replaceResponse(t, deleteBody, `"id":`, `"unknown":true,"id":`), copies: []string{"envelope.result"}, disposition: 4, reason: 5},
		{name: "delete unexpected secret-bearing result", delete: true, status: 200, body: body, copies: []string{"envelope.result"}, disposition: 4, reason: 5},
		{name: "delete partial envelope decode", delete: true, status: 200, body: append(bytes.Clone(deleteBody[:len(deleteBody)-1]), []byte(`,"unknown":true}`)...), copies: []string{"envelope.result"}, disposition: 4, reason: 5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := bytes.Clone(test.body)
			copies := make(map[string][]byte)
			decode := observeResponseJSONCopies(copies)
			var facts provider.SafeFacts
			var secret []byte
			if test.delete {
				facts = normalizeDelete(test.status, test.body, account, target, intent.Digest, requestDigest, decode)
			} else {
				facts, secret = normalizeCreate(test.status, test.body, intent, requestDigest, decode)
			}
			defer clear(secret[:cap(secret)])
			if facts.Disposition != test.disposition || facts.Reason != test.reason || string(secret) != test.secret {
				t.Fatalf("classification or transferred secret differs: disposition=%d reason=%d secret_length=%d", facts.Disposition, facts.Reason, len(secret))
			}
			if !bytes.Equal(test.body, before) {
				t.Error("normalization changed borrowed response bytes")
			}
			names := make([]string, 0, len(copies))
			for name, allocation := range copies {
				names = append(names, name)
				for _, b := range allocation {
					if b != 0 {
						t.Errorf("owned JSON allocation %s retains bytes", name)
						break
					}
				}
			}
			slices.Sort(names)
			wantNames := slices.Clone(test.copies)
			slices.Sort(wantNames)
			if !slices.Equal(names, wantNames) {
				t.Errorf("observed JSON allocations = %v, want %v", names, wantNames)
			}
		})
	}
}

func observeResponseJSONCopies(copies map[string][]byte) func([]byte, any, ...json.Options) error {
	retain := func(name string, raw jsontext.Value) {
		if raw == nil {
			return
		}
		allocation := raw[:cap(raw)]
		// A nonzero unused tail distinguishes full-allocation disposal from
		// clearing only the JSON length. Decoded bytes remain unchanged.
		for i := len(raw); i < len(allocation); i++ {
			allocation[i] = 0xa5
		}
		copies[name] = allocation
	}
	return func(body []byte, out any, options ...json.Options) error {
		err := json.Unmarshal(body, out, options...)
		switch result := out.(type) {
		case *apiEnvelope:
			retain("envelope.result", result.Result)
		case *createResult:
			retain("result.value", result.Value)
			retain("result.condition", result.Condition)
			retain("result.not_before", result.NotBefore)
			retain("result.expires_on", result.ExpiresOn)
			retain("result.issued_on", result.IssuedOn)
			retain("result.modified_on", result.ModifiedOn)
			retain("result.last_used_on", result.LastUsedOn)
			if result.Policies != nil {
				for _, policy := range *result.Policies {
					for key, raw := range policy.Resources {
						retain("result.resources."+key, raw)
					}
				}
			}
		}
		return err
	}
}

func replaceResponse(t *testing.T, body []byte, old, replacement string) []byte {
	t.Helper()
	if bytes.Count(body, []byte(old)) != 1 {
		t.Fatalf("response fixture replacement is ambiguous: %q", old)
	}
	return bytes.Replace(body, []byte(old), []byte(replacement), 1)
}

func removeResponseSpan(t *testing.T, body []byte, start, end string) []byte {
	t.Helper()
	startIndex := bytes.Index(body, []byte(start))
	endIndex := bytes.Index(body, []byte(end))
	if startIndex < 0 || endIndex <= startIndex || bytes.Count(body, []byte(start)) != 1 || bytes.Count(body, []byte(end)) != 1 {
		t.Fatalf("response fixture span is ambiguous: %q..%q", start, end)
	}
	result := make([]byte, 0, len(body)-(endIndex-startIndex))
	result = append(result, body[:startIndex]...)
	return append(result, body[endIndex:]...)
}
