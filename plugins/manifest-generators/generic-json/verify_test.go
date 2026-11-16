package genericjson

import (
	"bytes"
	"context"
	"encoding/json"
	manifest "enkv.sh/sdk/manifest-generator"
	"strings"
	"testing"
)

func requireCorrespondenceFixture(t *testing.T, body []byte) {
	t.Helper()
	if manifest.ValidateResult(manifest.Result{Artifact: body}) != "" || !json.Valid(body) {
		t.Fatal("damaged bytes must reach author correspondence check")
	}
}
func rejectsArtifact(t *testing.T, p *manifest.Projection, want string, damaged []byte) {
	t.Helper()
	requireCorrespondenceFixture(t, damaged)
	if err := authorArtifactCheck(t, p, want, func(context.Context, manifest.View) manifest.Result {
		return manifest.Result{Artifact: exactArtifactForTest(damaged)}
	}); err == nil {
		t.Fatal("changed well-framed body escaped author check")
	}
}

// full_only: false
func TestCanonicalOutputScopes(t *testing.T) {
	for _, service := range []string{"aws-secrets-manager/service/v1", "gcp-secret-manager/service/v1", "github-repository/service/v1", "github-organization/service/v1", "github-environment/service/v1", "private-workshop/service/v7"} {
		t.Run(service, func(t *testing.T) {
			p, _ := manifestJSONLiteralFixture()
			p.Entries = p.Entries[2:]
			p.Entries[0].Destinations = p.Entries[0].Destinations[:1]
			d := &p.Entries[0].Destinations[0]
			d.ServiceContractID = service
			p.ServiceFilter = &service
			manifestResolvedProjectionForTest(p)
			r := Render(t.Context(), manifest.Borrow(p))
			if r.Failure != "" {
				t.Fatal(r.Failure)
			}
			var doc struct {
				Service string `json:"service_filter"`
				Entries []struct {
					Content struct {
						Destinations []struct {
							Service string `json:"service_contract_id"`
						} `json:"destinations"`
					} `json:"content"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(r.Artifact, &doc); err != nil || doc.Service != service || len(doc.Entries) != 1 || len(doc.Entries[0].Content.Destinations) != 1 || doc.Entries[0].Content.Destinations[0].Service != service {
				t.Fatal("semantic service consumer", err)
			}
		})
	}
}

// full_only: false
func TestAuthorChecksRejectWrongWellFormedReturns(t *testing.T) {
	p, want := manifestJSONLiteralFixture()
	for name, pair := range map[string][2]string{
		"target": {`"target_recipient_id": "22`, `"target_recipient_id": "23`}, "selector": {`"entry_mode": "exact-names"`, `"entry_mode": "all-authorized"`}, "filter": {`"service_filter": null`, `"service_filter": "private/service"`}, "destination": {`"destination_id": "primary"`, `"destination_id": "changed"`}, "binding": {`"binding_incarnation_id": "07`, `"binding_incarnation_id": "09`}, "locator": {`projects/123456789012/secrets/app-primary/versions/latest`, `projects/123456789012/secrets/other/versions/latest`}, "policy": {`"data_base64": "AQf/"`, `"data_base64": "AQj/"`}, "target-data": {`"target_data_base64": "AP8="`, `"target_data_base64": "Af8="`}, "evidence": {`authorized-input-and-exact-bytes`, `independent-proof`}} {
		t.Run(name, func(t *testing.T) {
			damaged := exactArtifactForTest(bytes.Replace([]byte(want), []byte(pair[0]), []byte(pair[1]), 1))
			if string(damaged) == want {
				t.Fatal("damage missed independent literal")
			}
			rejectsArtifact(t, p, want, damaged)
		})
	}
	start := strings.Index(want, "          {\n")
	middle := strings.Index(want, ",\n          {\n")
	end := strings.Index(want[middle:], "\n        ]") + middle
	changed := want[:start] + want[middle+2:end] + ",\n" + want[start:middle] + want[end:]
	rejectsArtifact(t, p, want, exactArtifactForTest([]byte(changed)))
	p.TargetRecipientID = fixtureID(4)
	p.Selection = manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	p.Entries = []manifest.Entry{}
	p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "", EntryIncarnationID: fixtureID(5), Reason: manifest.NoOutput}}
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "", EntryIncarnationID: fixtureID(5)}}
	start = strings.Index(excludedLiteral, `"excluded_entries": [`) + len(`"excluded_entries": [`)
	end = strings.Index(excludedLiteral[start:], "\n  ],\n  \"evidence_limit\"") + start
	omitted := excludedLiteral[:start] + excludedLiteral[end:]
	rejectsArtifact(t, p, excludedLiteral, exactArtifactForTest([]byte(omitted)))
}

// full_only: false
func TestViewMutationCannotChangeAuthorExpectation(t *testing.T) {
	p, want := manifestJSONLiteralFixture()
	v := manifest.Borrow(p)
	h := v.Header()
	h.TargetRecipientID[0] ^= 255
	h.Observation.DomainID[0] ^= 255
	changed := &manifest.Projection{Schema: h.Schema, FormatContractID: h.FormatContractID, ConfigContractID: h.ConfigContractID, Settings: []byte(`{}`), Observation: h.Observation, TargetRecipientID: h.TargetRecipientID, Selection: h.Selection, Entries: []manifest.Entry{}, ExcludedEntries: []manifest.ExcludedEntry{}}
	for i := 0; i < v.EntryCount(); i++ {
		e, _ := v.Entry(i)
		m := e.Metadata()
		m.EntryIncarnationID[0] ^= 255
		m.Name += "!"
		row := manifest.Entry{Name: m.Name, EntryIncarnationID: m.EntryIncarnationID, Kind: m.Kind}
		if m.Kind == manifest.Plain {
			row.PlainValue = make([]byte, e.PlainLength())
			if n, f := e.CopyPlain(0, row.PlainValue); f != "" || n != len(row.PlainValue) {
				t.Fatal(f)
			}
			for j := range row.PlainValue {
				row.PlainValue[j] ^= 255
			}
		} else {
			row.Destinations = []manifest.Destination{}
			for j := 0; j < e.DestinationCount(); j++ {
				d, _ := e.Destination(j)
				dm := d.Metadata()
				data := make([]byte, d.TargetDataLength())
				policy := make([]byte, d.PolicyLength())
				if n, f := d.CopyTargetData(0, data); f != "" || n != len(data) {
					t.Fatal(f)
				}
				if n, f := d.CopyPolicy(0, policy); f != "" || n != len(policy) {
					t.Fatal(f)
				}
				dm.BindingIncarnationID[0] ^= 255
				row.Destinations = append(row.Destinations, manifest.Destination{DestinationID: dm.DestinationID + "!", BindingIncarnationID: dm.BindingIncarnationID, EntryIncarnationID: row.EntryIncarnationID, ServiceContractID: dm.ServiceContractID, ConsumerLocator: dm.ConsumerLocator + "!", TargetContractID: dm.TargetContractID, CanonicalTarget: dm.CanonicalTarget, TargetData: data, PayloadEncoding: dm.PayloadEncoding, PolicyPresent: dm.PolicyPresent, PolicyContractID: dm.PolicyContractID, PolicyData: policy, PolicyDigest: dm.PolicyDigest})
			}
		}
		changed.Entries = append(changed.Entries, row)
	}
	manifestResolvedProjectionForTest(changed)
	r := Render(t.Context(), manifest.Borrow(changed))
	if r.Failure != "" {
		t.Fatal("changed copied facts must remain common-valid", r.Failure)
	}
	rejectsArtifact(t, p, want, r.Artifact)
	original := Render(t.Context(), v)
	if original.Failure != "" || string(original.Artifact) != want {
		t.Fatal("view copies changed original", original.Failure)
	}
}
