package opentofutfvars

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/conformance"
	"enkv.sh/sdk/manifest-generator/native"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Independent Python compact JSON/Base64/SHA-256; no production renderer.
const mixedLiteral = `{"enkv":{"schema":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","config_contract_id":"ENKV/OPENTOFU-TFVARS-CONFIG/v1","observation":{"domain_id":"0101010101010101010101010101010101010101010101010101010101010101","head_revision_id":"0202020202020202020202020202020202020202020202020202020202020202","snapshot_id":"0303030303030303030303030303030303030303030303030303030303030303"},"target_recipient_id":"0404040404040404040404040404040404040404040404040404040404040404","selection":{"target_mode":"exact-recipient","entry_mode":"exact-names"},"service_filter":null,"plain":{"binary":{"entry_incarnation_id":"0505050505050505050505050505050505050505050505050505050505050505","encoding":"base64","value":"AP8="}},"secrets":{"token":{"entry_incarnation_id":"0606060606060606060606060606060606060606060606060606060606060606","destinations":[{"destination_id":"primary","binding_incarnation_id":"0707070707070707070707070707070707070707070707070707070707070707","entry_incarnation_id":"0606060606060606060606060606060606060606060606060606060606060606","service_contract_id":"aws-secrets-manager/service/v1","consumer_locator":"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-AbCdEf?stage=AWSCURRENT","target_contract_id":"target/v1","canonical_target":"account/key","target_data_base64":"AP8=","payload_encoding":"raw","consumer_policy":null}]}},"excluded_entries":[],"evidence_limit":"authorized-input-and-exact-bytes"}}`
const excludedLiteral = `{"enkv":{"schema":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","config_contract_id":"ENKV/OPENTOFU-TFVARS-CONFIG/v1","observation":{"domain_id":"0101010101010101010101010101010101010101010101010101010101010101","head_revision_id":"0202020202020202020202020202020202020202020202020202020202020202","snapshot_id":"0303030303030303030303030303030303030303030303030303030303030303"},"target_recipient_id":"0404040404040404040404040404040404040404040404040404040404040404","selection":{"target_mode":"current-authority","entry_mode":"all-authorized"},"service_filter":null,"plain":{},"secrets":{},"excluded_entries":[{"name":"","entry_incarnation_id":"0505050505050505050505050505050505050505050505050505050505050505","reason":"no-output"}],"evidence_limit":"authorized-input-and-exact-bytes"}}`
const organizationLiteral = `{"enkv":{"schema":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","config_contract_id":"ENKV/OPENTOFU-TFVARS-CONFIG/v1","observation":{"domain_id":"0101010101010101010101010101010101010101010101010101010101010101","head_revision_id":"0202020202020202020202020202020202020202020202020202020202020202","snapshot_id":"0303030303030303030303030303030303030303030303030303030303030303"},"target_recipient_id":"0404040404040404040404040404040404040404040404040404040404040404","selection":{"target_mode":"exact-recipient","entry_mode":"exact-names"},"service_filter":"github-actions/service/v1","plain":{},"secrets":{"token":{"entry_incarnation_id":"0606060606060606060606060606060606060606060606060606060606060606","destinations":[{"destination_id":"primary","binding_incarnation_id":"0707070707070707070707070707070707070707070707070707070707070707","entry_incarnation_id":"0606060606060606060606060606060606060606060606060606060606060606","service_contract_id":"github-actions/service/v1","consumer_locator":"orgs/o/actions/secrets/TOKEN","target_contract_id":"target/v1","canonical_target":"account/key","target_data_base64":"AP8=","payload_encoding":"raw","consumer_policy":{"contract_id":"github-actions/organization-policy/v1","data_base64":"AQf/","digest":"0909090909090909090909090909090909090909090909090909090909090909"}}]}},"excluded_entries":[],"evidence_limit":"authorized-input-and-exact-bytes"}}`

func openTofuFixtureID(n byte) (id manifest.ID) {
	for i := range id {
		id[i] = n
	}
	return
}
func openTofuFixture() *manifest.Projection { return openTofuNamedFixture("mixed") }
func openTofuNamedFixture(kind string) *manifest.Projection {
	id := openTofuFixtureID
	p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: []byte(`{}`), Observation: manifest.Observation{DomainID: id(1), HEADRevisionID: id(2), SnapshotID: id(3)}, TargetRecipientID: id(4), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, Entries: []manifest.Entry{}, ExcludedEntries: []manifest.ExcludedEntry{}, ResolvedEntries: []manifest.EntryIdentity{}}
	if kind == "excluded" {
		p.Selection = manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
		p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "", EntryIncarnationID: id(5), Reason: manifest.NoOutput}}
		p.ResolvedEntries = []manifest.EntryIdentity{{Name: "", EntryIncarnationID: id(5)}}
		return p
	}
	d := manifest.Destination{DestinationID: "primary", BindingIncarnationID: id(7), EntryIncarnationID: id(6), ServiceContractID: "aws-secrets-manager/service/v1", ConsumerLocator: "arn:aws:secretsmanager:us-east-1:123456789012:secret:example-AbCdEf?stage=AWSCURRENT", TargetContractID: "target/v1", CanonicalTarget: "account/key", TargetData: []byte{0, 255}, PayloadEncoding: manifest.EncodingRaw}
	if kind == "organization" {
		service := "github-actions/service/v1"
		p.ServiceFilter = &service
		d.ServiceContractID = service
		d.ConsumerLocator = "orgs/o/actions/secrets/TOKEN"
		d.PolicyPresent = true
		d.PolicyContractID = "github-actions/organization-policy/v1"
		d.PolicyData = []byte{1, 7, 255}
		d.PolicyDigest = id(9)
	} else {
		p.Entries = append(p.Entries, manifest.Entry{Name: "binary", EntryIncarnationID: id(5), Kind: manifest.Plain, PlainValue: []byte{0, 255}})
		p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: "binary", EntryIncarnationID: id(5)})
	}
	p.Entries = append(p.Entries, manifest.Entry{Name: "token", EntryIncarnationID: id(6), Kind: manifest.Secret, Destinations: []manifest.Destination{d}})
	p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: "token", EntryIncarnationID: id(6)})
	return p
}
func exactArtifactForTest(body []byte) []byte {
	owned := make([]byte, len(body))
	copy(owned, body)
	return owned
}
func authorCheck(t *testing.T, p *manifest.Projection, want string, render manifest.Renderer) error {
	t.Helper()
	implementation := implementationForTest(t)
	implementation.Render = render
	return conformance.CheckImplementation(t.Context(), native.Serve, implementation, conformance.Fixture{Projection: p, ExpectedArtifact: []byte(want)})
}

// full_only: false
func TestOpenTofuPublicRendererExactMixedVector(t *testing.T) {
	p := openTofuFixture()
	r := Render(t.Context(), manifest.Borrow(p))
	defer clear(r.Artifact[:cap(r.Artifact)])
	if manifest.ValidateResult(r) != "" || r.Failure != "" || string(r.Artifact) != mixedLiteral {
		t.Fatal("independent mixed vector", r.Failure)
	}
	digest := sha256.Sum256(r.Artifact)
	if len(r.Artifact) != 1473 || hex.EncodeToString(digest[:]) != "ffdf7985fb1eade1070348968437edc0b04e420716544da75d12d7123b4cf6f2" {
		t.Fatal("mixed length/digest")
	}
	var doc struct {
		Enkv struct {
			Plain map[string]struct {
				Encoding string `json:"encoding"`
				Value    string `json:"value"`
			} `json:"plain"`
			Secrets map[string]struct {
				Destinations []struct {
					Locator string `json:"consumer_locator"`
					Data    string `json:"target_data_base64"`
				} `json:"destinations"`
			} `json:"secrets"`
		} `json:"enkv"`
	}
	if err := json.Unmarshal(r.Artifact, &doc); err != nil {
		t.Fatal(err)
	}
	binary, err := base64.StdEncoding.Strict().DecodeString(doc.Enkv.Plain["binary"].Value)
	if err != nil || !bytes.Equal(binary, []byte{0, 255}) || doc.Enkv.Plain["binary"].Encoding != "base64" || len(doc.Enkv.Secrets["token"].Destinations) != 1 || doc.Enkv.Secrets["token"].Destinations[0].Locator != p.Entries[1].Destinations[0].ConsumerLocator {
		t.Fatal("independent reference consumer", err)
	}
	if err := authorCheck(t, p, mixedLiteral, Render); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOpenTofuOriginalProjectionAndCanonicalMaps(t *testing.T) {
	for _, test := range []struct {
		name, literal, digest string
		length                int
	}{
		{"mixed", mixedLiteral, "ffdf7985fb1eade1070348968437edc0b04e420716544da75d12d7123b4cf6f2", 1473},
		{"excluded", excludedLiteral, "140ce735f6e16995931ad43f223add32ef3036e320254c58c676529735df91a3", 835},
		{"organization", organizationLiteral, "6ec0f91a85f4e4921fa2f44df7b6b45f7146631be8d2822e92828029b0692c38", 1448},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := openTofuNamedFixture(test.name)
			r := Render(t.Context(), manifest.Borrow(p))
			defer clear(r.Artifact[:cap(r.Artifact)])
			digest := sha256.Sum256(r.Artifact)
			if r.Failure != "" || string(r.Artifact) != test.literal || len(r.Artifact) != test.length || hex.EncodeToString(digest[:]) != test.digest {
				t.Fatal("independent complete map", r.Failure)
			}
			if err := authorCheck(t, p, test.literal, Render); err != nil {
				t.Fatal(err)
			}
		})
	}
	changes := []struct{ name, old, new string }{
		{"schema", `"schema":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2"`, `"schema":"other"`}, {"format", `"format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2"`, `"format_contract_id":"other"`}, {"config", `ENKV/OPENTOFU-TFVARS-CONFIG/v1`, `other/config`},
		{"domain", strings.Repeat("01", 32), strings.Repeat("09", 32)}, {"head", strings.Repeat("02", 32), strings.Repeat("09", 32)}, {"snapshot", strings.Repeat("03", 32), strings.Repeat("09", 32)}, {"recipient", strings.Repeat("04", 32), strings.Repeat("09", 32)},
		{"target-mode", `exact-recipient`, `current-authority`}, {"entry-mode", `exact-names`, `all-authorized`}, {"service-filter", `"service_filter":null`, `"service_filter":"private/service"`}, {"plain-name", `"binary":{`, `"other":{`}, {"plain-incarnation", strings.Repeat("05", 32), strings.Repeat("09", 32)}, {"plain-encoding", `"encoding":"base64"`, `"encoding":"raw"`}, {"plain-pad-bits", `AP8=`, `AP9=`},
		{"secret-name", `"token":{`, `"other":{`}, {"secret-incarnation", `"entry_incarnation_id":"` + strings.Repeat("06", 32) + `","destinations"`, `"entry_incarnation_id":"` + strings.Repeat("09", 32) + `","destinations"`}, {"destination", `"destination_id":"primary"`, `"destination_id":"other"`}, {"binding", strings.Repeat("07", 32), strings.Repeat("09", 32)},
		{"destination-incarnation", `"entry_incarnation_id":"` + strings.Repeat("06", 32) + `","service_contract_id"`, `"entry_incarnation_id":"` + strings.Repeat("09", 32) + `","service_contract_id"`}, {"service", `aws-secrets-manager/service/v1`, `private/service/v1`}, {"locator", `example-AbCdEf?stage=AWSCURRENT`, `other-AbCdEf?stage=AWSCURRENT`}, {"target-contract", `target/v1`, `target/v2`}, {"canonical-target", `account/key`, `account/other`}, {"target-data", `"target_data_base64":"AP8="`, `"target_data_base64":"Af8="`}, {"encoding", `"payload_encoding":"raw"`, `"payload_encoding":"base64"`}, {"policy", `"consumer_policy":null`, `"consumer_policy":{}`}, {"evidence", `authorized-input-and-exact-bytes`, `other-evidence`}, {"extra", `"evidence_limit":`, `"extra":null,"evidence_limit":`}, {"duplicate-format", `"format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2"`, `"format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2","format_contract_id":"ENKV/OPENTOFU-TFVARS-MANIFEST/v2"`},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(mixedLiteral, test.old) {
				t.Fatal("mutation missed independent field")
			}
			damaged := strings.Replace(mixedLiteral, test.old, test.new, 1)
			if !json.Valid([]byte(damaged)) {
				t.Fatal("well-formed mutation required")
			}
			if err := authorCheck(t, openTofuFixture(), mixedLiteral, func(context.Context, manifest.View) manifest.Result {
				return manifest.Result{Artifact: exactArtifactForTest([]byte(damaged))}
			}); err == nil {
				t.Fatal("changed original fact escaped author check")
			}
		})
	}
	for _, test := range []struct{ name, kind, old, new string }{{"trailing", "mixed", "", " "}, {"excluded-reason", "excluded", `"reason":"no-output"`, `"reason":"no-matching-service"`}, {"policy-bytes", "organization", `"data_base64":"AQf/"`, `"data_base64":"AQj/"`}} {
		t.Run(test.name, func(t *testing.T) {
			want := mixedLiteral
			if test.kind == "excluded" {
				want = excludedLiteral
			}
			if test.kind == "organization" {
				want = organizationLiteral
			}
			damaged := strings.Replace(want, test.old, test.new, 1)
			if test.name == "trailing" {
				damaged = want + " "
			}
			if err := authorCheck(t, openTofuNamedFixture(test.kind), want, func(context.Context, manifest.View) manifest.Result {
				return manifest.Result{Artifact: exactArtifactForTest([]byte(damaged))}
			}); err == nil {
				t.Fatal("changed complete artifact escaped author check")
			}
		})
	}
}

// full_only: false
func TestOpenTofuConsumerFixtureKeepsReferencesAndBinary(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("consumer", "example.tfvars.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Enkv struct {
			Schema string `json:"schema"`
			Format string `json:"format_contract_id"`
			Plain  map[string]struct {
				Value string `json:"value"`
			} `json:"plain"`
			Secrets map[string]struct {
				Destinations []struct {
					ID      string `json:"destination_id"`
					Locator string `json:"consumer_locator"`
				} `json:"destinations"`
			} `json:"secrets"`
		} `json:"enkv"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	binary, err := base64.StdEncoding.Strict().DecodeString(doc.Enkv.Plain["binary"].Value)
	if err != nil || !bytes.Equal(binary, []byte{0, 255}) || doc.Enkv.Schema != Schema || doc.Enkv.Format != FormatContractID {
		t.Fatal("consumer format and binary", err)
	}
	url, err := base64.StdEncoding.Strict().DecodeString(doc.Enkv.Plain["service_url"].Value)
	if err != nil || string(url) != "https://example.invalid" || len(doc.Enkv.Secrets["api_token"].Destinations) != 1 || doc.Enkv.Secrets["api_token"].Destinations[0].ID != "primary" || doc.Enkv.Secrets["api_token"].Destinations[0].Locator != "arn:aws:secretsmanager:us-east-1:123456789012:secret:example-AbCdEf?stage=AWSCURRENT" {
		t.Fatal("consumer keeps inert complete reference", err)
	}
}

func implementationForTest(t *testing.T) native.Implementation {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("cmd", "enkv-manifest-opentofu-tfvars-json", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := native.Bind(body, ConfigContractID, FormatContractID, manifest.Implementation{ValidateFormatSettings: ValidateFormatSettings, Render: Render})
	if err != nil {
		t.Fatal(err)
	}
	return implementation
}
