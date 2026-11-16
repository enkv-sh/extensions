package genericjson

import (
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
)

func writeDestination(w *jsonwriter.Writer, d manifest.DestinationView) {
	m := d.Metadata()
	w.Literal("          {\n            \"destination_id\": ")
	w.Text(m.DestinationID, 256, false)
	w.Literal(",\n            \"binding_incarnation_id\": ")
	w.ID(m.BindingIncarnationID)
	w.Literal(",\n            \"entry_incarnation_id\": ")
	w.ID(m.EntryIncarnationID)
	w.Literal(",\n            \"service_contract_id\": ")
	w.Text(m.ServiceContractID, 256, false)
	w.Literal(",\n            \"consumer_locator\": ")
	w.Text(m.ConsumerLocator, 1024, false)
	w.Literal(",\n            \"target_contract_id\": ")
	w.Text(m.TargetContractID, 256, false)
	w.Literal(",\n            \"canonical_target\": ")
	w.Text(m.CanonicalTarget, 1024, false)
	w.Literal(",\n            \"target_data_base64\": ")
	w.Base64(d.TargetDataLength(), manifest.MaxTargetDataBytes, d.CopyTargetData)
	w.Literal(",\n            \"payload_encoding\": ")
	switch m.PayloadEncoding {
	case manifest.EncodingRaw:
		w.Literal(`"raw"`)
	case manifest.EncodingBase64:
		w.Literal(`"base64"`)
	default:
		w.Refuse(manifest.InvalidInput)
	}
	w.Literal(",\n            \"consumer_policy\": ")
	if !m.PolicyPresent {
		w.Literal(`null`)
	} else {
		w.Literal("{\n              \"contract_id\": ")
		w.Text(m.PolicyContractID, 256, false)
		w.Literal(",\n              \"data_base64\": ")
		w.Base64(d.PolicyLength(), manifest.MaxPolicyBytes, d.CopyPolicy)
		w.Literal(",\n              \"digest\": ")
		w.ID(m.PolicyDigest)
		w.Literal("\n            }")
	}
	w.Literal("\n          }")
}

func headerValid(v manifest.View) bool {
	h := v.Header()
	if h.Schema != manifest.Schema || h.FormatContractID != FormatContractID || h.ConfigContractID != ConfigContractID || v.SettingsLength() != 2 {
		return false
	}
	var settings [2]byte
	n, f := v.CopySettings(0, settings[:])
	return f == "" && n == 2 && settings == [2]byte{'{', '}'}
}

func writeHeader(w *jsonwriter.Writer, v manifest.View) {
	h := v.Header()
	w.Literal(`  "schema": `)
	w.Text(Schema, 256, false)
	w.Literal(",\n  \"format_contract_id\": ")
	w.Text(h.FormatContractID, 256, false)
	w.Literal(",\n  \"config_contract_id\": ")
	w.Text(h.ConfigContractID, 256, false)
	w.Literal(",\n  \"observation\": {\n    \"domain_id\": ")
	w.ID(h.Observation.DomainID)
	w.Literal(",\n    \"head_revision_id\": ")
	w.ID(h.Observation.HEADRevisionID)
	w.Literal(",\n    \"snapshot_id\": ")
	w.ID(h.Observation.SnapshotID)
	w.Literal("\n  },\n  \"target_recipient_id\": ")
	w.ID(h.TargetRecipientID)
	w.Literal(",\n  \"selection\": {\n    \"target_mode\": ")
	w.Text(string(h.Selection.TargetMode), 64, false)
	w.Literal(",\n    \"entry_mode\": ")
	w.Text(string(h.Selection.EntryMode), 64, false)
	w.Literal("\n  },\n  \"service_filter\": ")
	if h.HasServiceFilter {
		w.Text(h.ServiceFilter, 256, false)
	} else {
		w.Literal(`null`)
	}
}
