package genericjson

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Independent Python JSON/Base64 literals use indent=2, UTF-8 and a final LF.
// Their SHA-256 values do not call the production codec.
const mixedLiteral = `{
  "schema": "ENKV/CONSUMPTION-MANIFEST/v3",
  "format_contract_id": "ENKV/CONSUMPTION-MANIFEST/v3",
  "config_contract_id": "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1",
  "observation": {
    "domain_id": "0101010101010101010101010101010101010101010101010101010101010101",
    "head_revision_id": "0202020202020202020202020202020202020202020202020202020202020202",
    "snapshot_id": "0303030303030303030303030303030303030303030303030303030303030303"
  },
  "target_recipient_id": "2222222222222222222222222222222222222222222222222222222222222222",
  "selection": {
    "target_mode": "exact-recipient",
    "entry_mode": "exact-names"
  },
  "service_filter": null,
  "entries": [
    {
      "name": "",
      "entry_incarnation_id": "0404040404040404040404040404040404040404040404040404040404040404",
      "content": {
        "kind": "plain",
        "value_base64": ""
      }
    },
    {
      "name": "a/\n雪",
      "entry_incarnation_id": "0505050505050505050505050505050505050505050505050505050505050505",
      "content": {
        "kind": "plain",
        "value_base64": "AApB/w=="
      }
    },
    {
      "name": "secret",
      "entry_incarnation_id": "0606060606060606060606060606060606060606060606060606060606060606",
      "content": {
        "kind": "secret",
        "destinations": [
          {
            "destination_id": "primary",
            "binding_incarnation_id": "0707070707070707070707070707070707070707070707070707070707070707",
            "entry_incarnation_id": "0606060606060606060606060606060606060606060606060606060606060606",
            "service_contract_id": "gcp-secret-manager/service/v1",
            "consumer_locator": "projects/123456789012/secrets/app-primary/versions/latest",
            "target_contract_id": "target/v1",
            "canonical_target": "account/key",
            "target_data_base64": "AP8=",
            "payload_encoding": "raw",
            "consumer_policy": null
          },
          {
            "destination_id": "secondary",
            "binding_incarnation_id": "0808080808080808080808080808080808080808080808080808080808080808",
            "entry_incarnation_id": "0606060606060606060606060606060606060606060606060606060606060606",
            "service_contract_id": "github-actions/service/v1",
            "consumer_locator": "orgs/owner/actions/secrets/TOKEN",
            "target_contract_id": "target/v1",
            "canonical_target": "account/key",
            "target_data_base64": "AP8=",
            "payload_encoding": "raw",
            "consumer_policy": {
              "contract_id": "github-actions/organization-policy/v1",
              "data_base64": "AQf/",
              "digest": "0909090909090909090909090909090909090909090909090909090909090909"
            }
          }
        ]
      }
    }
  ],
  "excluded_entries": [],
  "evidence_limit": "authorized-input-and-exact-bytes"
}
`
const excludedLiteral = `{
  "schema": "ENKV/CONSUMPTION-MANIFEST/v3",
  "format_contract_id": "ENKV/CONSUMPTION-MANIFEST/v3",
  "config_contract_id": "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1",
  "observation": {
    "domain_id": "0101010101010101010101010101010101010101010101010101010101010101",
    "head_revision_id": "0202020202020202020202020202020202020202020202020202020202020202",
    "snapshot_id": "0303030303030303030303030303030303030303030303030303030303030303"
  },
  "target_recipient_id": "0404040404040404040404040404040404040404040404040404040404040404",
  "selection": {
    "target_mode": "current-authority",
    "entry_mode": "all-authorized"
  },
  "service_filter": null,
  "entries": [],
  "excluded_entries": [
    {
      "name": "",
      "entry_incarnation_id": "0505050505050505050505050505050505050505050505050505050505050505",
      "reason": "no-output"
    }
  ],
  "evidence_limit": "authorized-input-and-exact-bytes"
}
`

func fixtureID(b byte) (id manifest.ID) {
	for i := range id {
		id[i] = b
	}
	return
}
func manifestJSONLiteralFixture() (*manifest.Projection, string) {
	id := fixtureID
	p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: []byte(`{}`), Observation: manifest.Observation{DomainID: id(1), HEADRevisionID: id(2), SnapshotID: id(3)}, TargetRecipientID: id(0x22), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, ExcludedEntries: []manifest.ExcludedEntry{}, Entries: []manifest.Entry{
		{Name: "", EntryIncarnationID: id(4), Kind: manifest.Plain, PlainValue: []byte{}},
		{Name: "a/\n雪", EntryIncarnationID: id(5), Kind: manifest.Plain, PlainValue: []byte{0, 10, 65, 255}},
		{Name: "secret", EntryIncarnationID: id(6), Kind: manifest.Secret, Destinations: []manifest.Destination{
			{DestinationID: "primary", BindingIncarnationID: id(7), EntryIncarnationID: id(6), ServiceContractID: "gcp-secret-manager/service/v1", ConsumerLocator: "projects/123456789012/secrets/app-primary/versions/latest", TargetContractID: "target/v1", CanonicalTarget: "account/key", TargetData: []byte{0, 255}, PayloadEncoding: manifest.EncodingRaw},
			{DestinationID: "secondary", BindingIncarnationID: id(8), EntryIncarnationID: id(6), ServiceContractID: "github-actions/service/v1", ConsumerLocator: "orgs/owner/actions/secrets/TOKEN", TargetContractID: "target/v1", CanonicalTarget: "account/key", TargetData: []byte{0, 255}, PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true, PolicyContractID: "github-actions/organization-policy/v1", PolicyData: []byte{1, 7, 255}, PolicyDigest: id(9)},
		}}}}
	manifestResolvedProjectionForTest(p)
	return p, mixedLiteral
}
func manifestResolvedProjectionForTest(p *manifest.Projection) {
	p.ResolvedEntries = make([]manifest.EntryIdentity, len(p.Entries))
	for i, e := range p.Entries {
		p.ResolvedEntries[i] = manifest.EntryIdentity{Name: e.Name, EntryIncarnationID: e.EntryIncarnationID}
	}
}
func encodeForTest(ctx context.Context, p *manifest.Projection) ([]byte, manifest.Failure) {
	r := Render(ctx, manifest.Borrow(p))
	return r.Artifact, r.Failure
}

// full_only: false
func TestConsumptionManifestJSONExactMixedLiteral(t *testing.T) {
	p, want := manifestJSONLiteralFixture()
	body, f := encodeForTest(t.Context(), p)
	digest := sha256.Sum256(body)
	if f != "" || string(body) != want || len(body) != 2897 || len(body) != cap(body) || hex.EncodeToString(digest[:]) != "71d887369a867d58968f639f173334bd335690c881526e7d825d2639b01886a9" {
		t.Fatal("complete exact JSON", f, len(body))
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || len(doc) != 10 {
		t.Fatal("closed envelope", err)
	}
	var entries []struct {
		Name    string `json:"name"`
		Content struct {
			Plain        string                       `json:"value_base64"`
			Destinations []map[string]json.RawMessage `json:"destinations"`
		} `json:"content"`
	}
	if err := json.Unmarshal(doc["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	for i, want := range [][]byte{{}, {0, 10, 65, 255}} {
		got, err := base64.StdEncoding.Strict().DecodeString(entries[i].Content.Plain)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("plain consumer", err)
		}
	}
	if entries[1].Name != "a/\n雪" || len(entries[2].Content.Destinations) != 2 {
		t.Fatal("complete selection")
	}
	for i, d := range entries[2].Content.Destinations {
		if len(d) != 10 {
			t.Fatal("destination grammar")
		}
		var locator string
		if err := json.Unmarshal(d["consumer_locator"], &locator); err != nil {
			t.Fatal(err)
		}
		if locator != p.Entries[2].Destinations[i].ConsumerLocator {
			t.Fatal("consumer locator")
		}
	}
	p.Entries[1].PlainValue[0] = 99
	p.Entries[2].Destinations[1].PolicyData[0] = 99
	if string(body) != want {
		t.Fatal("artifact aliases public input")
	}
	body[0] = '!'
	if p.Schema != manifest.Schema {
		t.Fatal("public input aliases returned body")
	}
}

// full_only: false
func TestConsumptionManifestJSONClosedProjectionGrammar(t *testing.T) {
	for _, name := range []string{"schema", "format", "config", "settings", "observation-id", "target-id", "nil-entries", "entry-id", "invalid-name", "name-limit", "unordered-names", "unknown-kind", "plain-overlap", "secret-overlap", "missing-destination", "destination-id", "destination-incarnation", "unordered-destinations", "locator-limit", "target-data-limit", "policy-absence", "policy-id", "policy-digest", "policy-limit", "encoding", "missing-selection-mode", "invalid-service-filter", "nil-exclusions", "nil-resolved", "missing-union-row", "wrong-union-incarnation", "overlapping-exclusion", "exclusion-filter-without-filter", "destination-filter-mismatch"} {
		t.Run(name, func(t *testing.T) {
			p, _ := manifestJSONLiteralFixture()
			d := &p.Entries[2].Destinations[1]
			switch name {
			case "schema":
				p.Schema = "other"
			case "format":
				p.FormatContractID = "other"
			case "config":
				p.ConfigContractID = "other"
			case "settings":
				p.Settings = []byte(`{ }`)
			case "observation-id":
				p.Observation.SnapshotID = manifest.ID{}
			case "target-id":
				p.TargetRecipientID = manifest.ID{}
			case "nil-entries":
				p.Entries = nil
			case "entry-id":
				p.Entries[0].EntryIncarnationID = manifest.ID{}
			case "invalid-name":
				p.Entries[1].Name = string([]byte{255})
			case "name-limit":
				p.Entries[1].Name = strings.Repeat("a", 257)
			case "unordered-names":
				p.Entries[1].Name = ""
			case "unknown-kind":
				p.Entries[0].Kind = 99
			case "plain-overlap":
				p.Entries[0].Destinations = []manifest.Destination{}
			case "secret-overlap":
				p.Entries[2].PlainValue = []byte{}
			case "missing-destination":
				p.Entries[2].Destinations = nil
			case "destination-id":
				d.BindingIncarnationID = manifest.ID{}
			case "destination-incarnation":
				d.EntryIncarnationID = manifest.ID{99}
			case "unordered-destinations":
				d.DestinationID = "primary"
			case "locator-limit":
				d.ConsumerLocator = strings.Repeat("a", 1025)
			case "target-data-limit":
				d.TargetData = make([]byte, 4097)
			case "policy-absence":
				d.PolicyPresent = false
			case "policy-id":
				d.PolicyContractID = ""
			case "policy-digest":
				d.PolicyDigest = manifest.ID{}
			case "policy-limit":
				d.PolicyData = make([]byte, 524547)
			case "encoding":
				d.PayloadEncoding = 3
			case "missing-selection-mode":
				p.Selection.TargetMode = ""
			case "invalid-service-filter":
				filter := ""
				p.ServiceFilter = &filter
			case "nil-exclusions":
				p.ExcludedEntries = nil
			case "nil-resolved":
				p.ResolvedEntries = nil
			case "missing-union-row":
				p.ResolvedEntries = p.ResolvedEntries[:2]
			case "wrong-union-incarnation":
				p.ResolvedEntries[2].EntryIncarnationID = manifest.ID{99}
			case "overlapping-exclusion":
				p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "secret", EntryIncarnationID: d.EntryIncarnationID, Reason: manifest.NoOutput}}
			case "exclusion-filter-without-filter":
				p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "z", EntryIncarnationID: manifest.ID{99}, Reason: manifest.NoMatchingService}}
				p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: "z", EntryIncarnationID: manifest.ID{99}})
			case "destination-filter-mismatch":
				filter := "unrelated/service"
				p.ServiceFilter = &filter
			}
			body, f := encodeForTest(t.Context(), p)
			want := manifest.InvalidInput
			if name == "name-limit" || name == "locator-limit" || name == "target-data-limit" || name == "policy-limit" {
				want = manifest.LimitExceeded
			}
			if name == "invalid-name" {
				want = manifest.InvalidUTF8
			}
			if body != nil || f != want {
				t.Fatal("invalid projection exposed body or wrong reason", f, want)
			}
		})
	}
}

// full_only: false
func TestConsumptionManifestJSONEscapesAndPerEntryBase64(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 49151, 49152, 49153} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p, _ := manifestJSONLiteralFixture()
			p.Entries = p.Entries[:1]
			p.Entries[0].PlainValue = make([]byte, n)
			manifestResolvedProjectionForTest(p)
			body, f := encodeForTest(t.Context(), p)
			tail := []string{"", "AA==", "AAA="}[n%3]
			want := strings.Repeat("AAAA", n/3) + tail
			if f != "" || !bytes.Contains(body, []byte(`"value_base64": "`+want+`"`)) {
				t.Fatal("independent padding", f)
			}
		})
	}
	p, _ := manifestJSONLiteralFixture()
	p.Entries = p.Entries[:1]
	p.Entries[0].Name = "\x00\b\t\n\f\r\"\\<>&\u2028\u2029"
	manifestResolvedProjectionForTest(p)
	body, f := encodeForTest(t.Context(), p)
	if f != "" || !bytes.Contains(body, []byte(`"name": "\u0000\b\t\n\f\r\"\\\u003c\u003e\u0026\u2028\u2029"`)) {
		t.Fatal("JSON escapes", f)
	}
}

// full_only: false
func TestConsumptionManifestJSONOpaquePolicyBytes(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0, 255, 7}, bytes.Repeat([]byte{255}, 49153)} {
		p, _ := manifestJSONLiteralFixture()
		p.Entries = p.Entries[2:]
		p.Entries[0].Destinations = p.Entries[0].Destinations[1:]
		d := &p.Entries[0].Destinations[0]
		d.PolicyData = data
		manifestResolvedProjectionForTest(p)
		body, f := encodeForTest(t.Context(), p)
		want := "\"consumer_policy\": {\n              \"contract_id\": \"github-actions/organization-policy/v1\",\n              \"data_base64\": \"" + base64.StdEncoding.EncodeToString(data) + "\",\n              \"digest\": \"" + strings.Repeat("09", 32) + "\"\n            }"
		if f != "" || !bytes.Contains(body, []byte(want)) {
			t.Fatal("opaque policy is not exact", f)
		}
	}
}

// full_only: false
func TestConsumptionManifestJSONExactExcludedPartition(t *testing.T) {
	p, _ := manifestJSONLiteralFixture()
	p.TargetRecipientID = fixtureID(4)
	p.Selection = manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	p.Entries = []manifest.Entry{}
	p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "", EntryIncarnationID: fixtureID(5), Reason: manifest.NoOutput}}
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "", EntryIncarnationID: fixtureID(5)}}
	body, f := encodeForTest(t.Context(), p)
	digest := sha256.Sum256(body)
	if f != "" || string(body) != excludedLiteral || len(body) != 927 || hex.EncodeToString(digest[:]) != "7c8d5dbf8a8fff54fd777024f2862d76907136a186f38428fe4d618f891d7a73" {
		t.Fatal("independent excluded literal", f, len(body))
	}
}

type manifestCancelContext struct {
	context.Context
	calls, failAt int
}

func (c *manifestCancelContext) Err() error {
	c.calls++
	if c.failAt != 0 && c.calls >= c.failAt {
		return context.Canceled
	}
	return c.Context.Err()
}

// manifestCountingCalls calibrates the actual layout's count pass without
// allocating an artifact. The declared refusal ends that calibration only.
func manifestCountingCalls(t *testing.T, m *manifest.Projection) int {
	t.Helper()
	tracker := &manifestCancelContext{Context: t.Context()}
	calls := 0
	r := jsonwriter.Encode(tracker, manifest.Borrow(m), func(w *jsonwriter.Writer, v manifest.View) {
		writeManifest(w, v)
		if w.Failure() == "" {
			calls = tracker.calls
			w.Refuse(manifest.Cancelled)
		}
	})
	if calls == 0 || r.Failure != manifest.Cancelled || r.Artifact != nil {
		t.Fatal("layout count calibration failed", r.Failure)
	}
	return calls
}

// full_only: false
func TestConsumptionManifestJSONBoundedCompletion(t *testing.T) {
	m, want := manifestJSONLiteralFixture()
	got, f := encodeForTest(t.Context(), m)
	if f != "" || string(got) != want || cap(got) != len(got) {
		t.Fatal("one exact output backing", f)
	}
	clear(got[:cap(got)])
	calls := manifestCountingCalls(t, m)
	for _, cut := range []struct {
		name string
		at   int
	}{
		{"counting", 1}, {"encoding-start", calls + 1}, {"encoding-last-row", 2 * calls}, {"after-encoding", 2*calls + 1},
	} {
		t.Run(cut.name, func(t *testing.T) {
			ctx := &manifestCancelContext{Context: t.Context(), failAt: cut.at}
			got, f := encodeForTest(ctx, m)
			if got != nil || f != manifest.Cancelled {
				t.Fatal("partial artifact escaped", f)
			}
		})
	}
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	got, f = encodeForTest(expired, m)
	if got != nil || f != manifest.Expired {
		t.Fatal("expired encoding", f)
	}
}
