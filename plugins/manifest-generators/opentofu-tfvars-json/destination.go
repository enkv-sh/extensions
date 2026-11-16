package opentofutfvars

import (
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
)

func writeDestination(w *jsonwriter.Writer, d manifest.DestinationView) {
	m := d.Metadata()
	w.Literal(`{"destination_id":`)
	w.Text(m.DestinationID, 256, false)
	w.Literal(`,"binding_incarnation_id":`)
	w.ID(m.BindingIncarnationID)
	w.Literal(`,"entry_incarnation_id":`)
	w.ID(m.EntryIncarnationID)
	w.Literal(`,"service_contract_id":`)
	w.Text(m.ServiceContractID, 256, false)
	w.Literal(`,"consumer_locator":`)
	w.Text(m.ConsumerLocator, 1024, false)
	w.Literal(`,"target_contract_id":`)
	w.Text(m.TargetContractID, 256, false)
	w.Literal(`,"canonical_target":`)
	w.Text(m.CanonicalTarget, 1024, false)
	w.Literal(`,"target_data_base64":`)
	w.Base64(d.TargetDataLength(), manifest.MaxTargetDataBytes, d.CopyTargetData)
	w.Literal(`,"payload_encoding":`)
	switch m.PayloadEncoding {
	case manifest.EncodingRaw:
		w.Literal(`"raw"`)
	case manifest.EncodingBase64:
		w.Literal(`"base64"`)
	default:
		w.Refuse(manifest.InvalidInput)
	}
	w.Literal(`,"consumer_policy":`)
	if !m.PolicyPresent {
		w.Literal(`null`)
	} else {
		w.Literal(`{"contract_id":`)
		w.Text(m.PolicyContractID, 256, false)
		w.Literal(`,"data_base64":`)
		w.Base64(d.PolicyLength(), manifest.MaxPolicyBytes, d.CopyPolicy)
		w.Literal(`,"digest":`)
		w.ID(m.PolicyDigest)
		w.Literal(`}`)
	}
	w.Literal(`}`)
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
	w.Literal(`"schema":`)
	w.Text(Schema, 256, false)
	w.Literal(`,"format_contract_id":`)
	w.Text(h.FormatContractID, 256, false)
	w.Literal(`,"config_contract_id":`)
	w.Text(h.ConfigContractID, 256, false)
	w.Literal(`,"observation":{"domain_id":`)
	w.ID(h.Observation.DomainID)
	w.Literal(`,"head_revision_id":`)
	w.ID(h.Observation.HEADRevisionID)
	w.Literal(`,"snapshot_id":`)
	w.ID(h.Observation.SnapshotID)
	w.Literal(`},"target_recipient_id":`)
	w.ID(h.TargetRecipientID)
	w.Literal(`,"selection":{"target_mode":`)
	w.Text(string(h.Selection.TargetMode), 64, false)
	w.Literal(`,"entry_mode":`)
	w.Text(string(h.Selection.EntryMode), 64, false)
	w.Literal(`},"service_filter":`)
	if h.HasServiceFilter {
		w.Text(h.ServiceFilter, 256, false)
	} else {
		w.Literal(`null`)
	}
}
