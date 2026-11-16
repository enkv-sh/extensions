package manifest

import (
	"context"
	"strings"
	"testing"
)

func fixtureProjection() *Projection {
	return &Projection{Schema: Schema, FormatContractID: "private/ini/v1", ConfigContractID: "private/ini-settings/v1", Settings: []byte("{}"), Selection: Selection{TargetMode: ExactRecipient, EntryMode: ExactNames}, Observation: Observation{ID{1}, ID{2}, ID{3}}, TargetRecipientID: ID{4}, ResolvedEntries: []EntryIdentity{}, Entries: []Entry{}, ExcludedEntries: []ExcludedEntry{}}
}
func fixtureDestination() Destination {
	return Destination{DestinationID: "slot", ServiceContractID: "unlisted/service/v1", TargetContractID: "unlisted/target/v1", CanonicalTarget: "account/key", ConsumerLocator: "local://key", TargetData: []byte{0, 1, 255}, BindingIncarnationID: ID{6}, EntryIncarnationID: ID{5}, PayloadEncoding: EncodingRaw}
}
func fixtureSecret(p *Projection) {
	p.Entries = []Entry{{Name: "secret", EntryIncarnationID: ID{5}, Kind: Secret, Destinations: []Destination{fixtureDestination()}}}
	p.ResolvedEntries = []EntryIdentity{{"secret", ID{5}}}
}

// full_only: false
func TestProjectionValidation(t *testing.T) {
	for _, condition := range []string{"empty", "unknown-semantics", "invalid-schema", "invalid-json", "missing-settings", "empty-format", "overlong-contract", "bad-filter", "wrong-filter", "bad-partition", "duplicate-identity", "plain-destinations", "secret-plain", "no-destinations", "target-data-limit", "locator-limit", "encoding", "policy-absent-data", "policy-present-missing-contract", "policy-present-missing-digest", "excluded-no-filter", "unsorted"} {
		t.Run(condition, func(t *testing.T) {
			p := fixtureProjection()
			fixtureSecret(p)
			want := InvalidInput
			switch condition {
			case "empty":
				p = fixtureProjection()
				want = ""
			case "unknown-semantics":
				p.Entries[0].Destinations[0].PolicyPresent = true
				p.Entries[0].Destinations[0].PolicyContractID = "private/opaque-policy/v42"
				p.Entries[0].Destinations[0].PolicyData = []byte{255, 0, 9}
				p.Entries[0].Destinations[0].PolicyDigest = ID{7}
				want = ""
			case "invalid-schema":
				p.Schema = "ENKV/CONSUMPTION-MANIFEST/v2"
			case "invalid-json":
				p.Settings = []byte("{")
			case "missing-settings":
				p.Settings = nil
			case "empty-format":
				p.FormatContractID = ""
			case "overlong-contract":
				p.ConfigContractID = strings.Repeat("x", 257)
				want = LimitExceeded
			case "bad-filter":
				s := ""
				p.ServiceFilter = &s
			case "wrong-filter":
				s := "other/service"
				p.ServiceFilter = &s
			case "bad-partition":
				p.ResolvedEntries = nil
			case "duplicate-identity":
				p.Entries = append(p.Entries, Entry{Name: "z", EntryIncarnationID: ID{5}, Kind: Plain, PlainValue: []byte{}})
				p.ResolvedEntries = append(p.ResolvedEntries, EntryIdentity{"z", ID{5}})
			case "plain-destinations":
				p.Entries[0].Kind = Plain
			case "secret-plain":
				p.Entries[0].PlainValue = []byte{}
			case "no-destinations":
				p.Entries[0].Destinations = nil
			case "target-data-limit":
				p.Entries[0].Destinations[0].TargetData = make([]byte, 4097)
				want = LimitExceeded
			case "locator-limit":
				p.Entries[0].Destinations[0].ConsumerLocator = strings.Repeat("x", 1025)
				want = LimitExceeded
			case "encoding":
				p.Entries[0].Destinations[0].PayloadEncoding = 3
			case "policy-absent-data":
				p.Entries[0].Destinations[0].PolicyData = []byte{1}
			case "policy-present-missing-contract":
				p.Entries[0].Destinations[0].PolicyPresent = true
				p.Entries[0].Destinations[0].PolicyDigest = ID{7}
			case "policy-present-missing-digest":
				p.Entries[0].Destinations[0].PolicyPresent = true
				p.Entries[0].Destinations[0].PolicyContractID = "private/policy"
			case "excluded-no-filter":
				p = fixtureProjection()
				p.ExcludedEntries = []ExcludedEntry{{"x", ID{5}, NoMatchingService}}
				p.ResolvedEntries = []EntryIdentity{{"x", ID{5}}}
			case "unsorted":
				p.Entries = append(p.Entries, Entry{Name: "a", EntryIncarnationID: ID{8}, Kind: Plain, PlainValue: []byte{}})
				p.ResolvedEntries = append(p.ResolvedEntries, EntryIdentity{"a", ID{8}})
			}
			if got := Validate(t.Context(), p); got != want {
				t.Fatalf("failure=%s want=%s", got, want)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want Failure
	}{
		{"nil", nil, InvalidInput},
		{"cancelled", ctx, Cancelled},
	} {
		if got := Validate(test.ctx, fixtureProjection()); got != test.want {
			t.Fatalf("%s context: failure=%s want=%s", test.name, got, test.want)
		}
	}
}

// full_only: false
func TestOpaquePolicyAndSettingsLimits(t *testing.T) {
	p := fixtureProjection()
	fixtureSecret(p)
	p.Settings = []byte(`"` + strings.Repeat("x", 16382) + `"`)
	d := &p.Entries[0].Destinations[0]
	d.PolicyPresent = true
	d.PolicyContractID = strings.Repeat("x", 256)
	d.PolicyDigest = ID{7}
	d.PolicyData = make([]byte, 524546)
	d.TargetData = make([]byte, 4096)
	if f := Validate(t.Context(), p); f != "" {
		t.Fatal(f)
	}
	d.PolicyData = append(d.PolicyData, 0)
	if f := Validate(t.Context(), p); f != LimitExceeded {
		t.Fatal("first excess policy", f)
	}
	d.PolicyData = nil
	p.Settings = append(p.Settings, ' ')
	if f := Validate(t.Context(), p); f != LimitExceeded {
		t.Fatal("first excess settings", f)
	}
	p = fixtureProjection()
	p.Entries = []Entry{{Name: "", EntryIncarnationID: ID{5}, Kind: Plain, PlainValue: make([]byte, 65536)}}
	p.ResolvedEntries = []EntryIdentity{{"", ID{5}}}
	if f := Validate(t.Context(), p); f != "" {
		t.Fatal(f)
	}
	p.Entries[0].PlainValue = append(p.Entries[0].PlainValue, 0)
	if f := Validate(t.Context(), p); f != LimitExceeded {
		t.Fatal("first excess plain", f)
	}
}
