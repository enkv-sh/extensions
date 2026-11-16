package main

import (
	"context"
	"encoding/base64"
	"strconv"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
)

func field(w *jsonwriter.Writer, name, value string) {
	w.Literal(name + "=")
	w.Text(value, manifest.MaxQuotedTextBytes, true)
	w.Literal("\n")
}
func idField(w *jsonwriter.Writer, name string, id manifest.ID) {
	w.Literal(name + "=")
	w.ID(id)
	w.Literal("\n")
}
func encodedField(w *jsonwriter.Writer, name, value string) {
	field(w, name, base64.StdEncoding.EncodeToString([]byte(value)))
}
func section(w *jsonwriter.Writer, prefix, name string) { w.Literal("[" + prefix + "." + name + "]\n") }
func blobField(w *jsonwriter.Writer, name string, length, maximum int, copyAt func(int, []byte) (int, manifest.Failure)) {
	w.Literal(name + "=")
	w.Base64(length, maximum, copyAt)
	w.Literal("\n")
}

func plainField(w *jsonwriter.Writer, entry manifest.EntryView) {
	// The complete-value helper copies raw bytes only. This format still owns
	// Base64 encoding and the scratch lifetime in both count and write passes.
	var plain [manifest.MaxRawValue]byte
	defer clear(plain[:])
	length, failure := entry.CopyPlainValue(plain[:])
	if failure != "" {
		w.Refuse(failure)
		return
	}
	w.Base64(length, manifest.MaxRawValue, func(offset int, dst []byte) (int, manifest.Failure) {
		return copy(dst, plain[offset:length]), ""
	})
}

func render(ctx context.Context, view manifest.View) manifest.Result {
	if failure := view.Validate(ctx); failure != "" {
		return manifest.Result{Failure: failure}
	}
	header := view.Header()
	var backing [manifest.MaxSettingsBytes]byte
	length := view.SettingsLength()
	if length > len(backing) {
		return manifest.Result{Failure: manifest.LimitExceeded}
	}
	if n, f := view.CopySettings(0, backing[:length]); f != "" || n != length {
		return manifest.Result{Failure: manifest.InvalidInput}
	}
	defer clear(backing[:])
	canonical := validateSettings(ctx, manifest.SettingsRequest{FormatContractID: header.FormatContractID, ConfigContractID: header.ConfigContractID, Canonical: true, Settings: backing[:length]})
	defer clear(canonical.Settings[:cap(canonical.Settings)])
	if canonical.Failure != "" {
		return manifest.Result{Failure: canonical.Failure}
	}
	configuration, ok := parseSettings(canonical.Settings)
	if !ok {
		return manifest.Result{Failure: manifest.InvalidInput}
	}
	return jsonwriter.Encode(ctx, view, func(w *jsonwriter.Writer, view manifest.View) {
		w.Validate(view)
		header := view.Header()
		prefix := configuration.SectionPrefix
		section(w, prefix, "manifest")
		field(w, "format", formatContract)
		field(w, "projection_schema", header.Schema)
		field(w, "config_contract", header.ConfigContractID)
		blobField(w, "settings_base64", view.SettingsLength(), manifest.MaxSettingsBytes, view.CopySettings)
		idField(w, "domain_id", header.Observation.DomainID)
		idField(w, "head_revision_id", header.Observation.HEADRevisionID)
		idField(w, "snapshot_id", header.Observation.SnapshotID)
		idField(w, "target_recipient_id", header.TargetRecipientID)
		field(w, "target_mode", string(header.Selection.TargetMode))
		field(w, "entry_mode", string(header.Selection.EntryMode))
		field(w, "has_service_filter", strconv.FormatBool(header.HasServiceFilter))
		encodedField(w, "service_filter_base64", header.ServiceFilter)
		field(w, "evidence_limit", header.EvidenceLimit)
		field(w, "included_count", strconv.Itoa(view.EntryCount()))
		field(w, "excluded_count", strconv.Itoa(view.ExcludedCount()))
		w.Literal("\n")
		for i := 0; i < view.EntryCount(); i++ {
			e, _ := view.Entry(i)
			metadata := e.Metadata()
			entrySection := "entry." + strconv.Itoa(i)
			section(w, prefix, entrySection)
			encodedField(w, "name_base64", metadata.Name)
			idField(w, "incarnation_id", metadata.EntryIncarnationID)
			if metadata.Kind == manifest.Plain {
				field(w, "kind", "plain")
				w.Literal("value_base64=")
				plainField(w, e)
				w.Literal("\n\n")
				continue
			}
			field(w, "kind", "secret")
			field(w, "destination_count", strconv.Itoa(e.DestinationCount()))
			w.Literal("\n")
			for j := 0; j < e.DestinationCount(); j++ {
				d, _ := e.Destination(j)
				m := d.Metadata()
				section(w, prefix, entrySection+".destination."+strconv.Itoa(j))
				encodedField(w, "destination_id_base64", m.DestinationID)
				idField(w, "binding_incarnation_id", m.BindingIncarnationID)
				idField(w, "entry_incarnation_id", m.EntryIncarnationID)
				encodedField(w, "service_contract_base64", m.ServiceContractID)
				encodedField(w, "target_contract_base64", m.TargetContractID)
				encodedField(w, "canonical_target_base64", m.CanonicalTarget)
				encodedField(w, "consumer_locator_base64", m.ConsumerLocator)
				blobField(w, "target_data_base64", d.TargetDataLength(), manifest.MaxTargetDataBytes, d.CopyTargetData)
				encoding := "raw"
				if m.PayloadEncoding == manifest.EncodingBase64 {
					encoding = "base64"
				}
				field(w, "payload_encoding", encoding)
				field(w, "policy_present", strconv.FormatBool(m.PolicyPresent))
				encodedField(w, "policy_contract_base64", m.PolicyContractID)
				if m.PolicyPresent {
					idField(w, "policy_digest", m.PolicyDigest)
				} else {
					field(w, "policy_digest", "")
				}
				blobField(w, "policy_data_base64", d.PolicyLength(), manifest.MaxPolicyBytes, d.CopyPolicy)
				w.Literal("\n")
			}
		}
		for i := 0; i < view.ExcludedCount(); i++ {
			e, _ := view.Excluded(i)
			section(w, prefix, "excluded."+strconv.Itoa(i))
			encodedField(w, "name_base64", e.Name)
			idField(w, "incarnation_id", e.EntryIncarnationID)
			field(w, "reason", string(e.Reason))
			w.Literal("\n")
		}
	})
}
