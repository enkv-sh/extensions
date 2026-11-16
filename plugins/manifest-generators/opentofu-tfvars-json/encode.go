// Package opentofutfvars renders the canonical OpenTofu reference map.
package opentofutfvars

import (
	"context"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
)

// Render borrows a frozen authorized view until return and returns an owned,
// exact-capacity artifact. Keep the view alive and unchanged across both encoding
// passes. The caller clears successful bytes; failure clears provisional bytes
// and retains no aliases or workers. A nil context or invalid header/settings is
// refused, and cancellation uses the closed manifest failure result.
func Render(ctx context.Context, v manifest.View) manifest.Result {
	return jsonwriter.Encode(ctx, v, writeManifest)
}

func writeManifest(w *jsonwriter.Writer, v manifest.View) {
	if !headerValid(v) {
		w.Refuse(manifest.InvalidInput)
		return
	}
	w.Validate(v)
	if w.Failure() != "" {
		return
	}
	w.Literal(`{"enkv":{`)
	writeHeader(w, v)
	w.Literal(`,"plain":{`)
	first := true
	for i := 0; i < v.EntryCount(); i++ {
		e, ok := v.Entry(i)
		if !ok {
			w.Refuse(manifest.InvalidInput)
			return
		}
		m := e.Metadata()
		if m.Kind != manifest.Plain {
			continue
		}
		if !first {
			w.Literal(`,`)
		}
		first = false
		w.Text(m.Name, manifest.MaxNameBytes, true)
		w.Literal(`:{"entry_incarnation_id":`)
		w.ID(m.EntryIncarnationID)
		w.Literal(`,"encoding":"base64","value":`)
		w.Plain(e)
		w.Literal(`}`)
		if w.Failure() != "" {
			return
		}
	}
	w.Literal(`},"secrets":{`)
	first = true
	for i := 0; i < v.EntryCount(); i++ {
		e, ok := v.Entry(i)
		if !ok {
			w.Refuse(manifest.InvalidInput)
			return
		}
		m := e.Metadata()
		if m.Kind != manifest.Secret {
			continue
		}
		if !first {
			w.Literal(`,`)
		}
		first = false
		w.Text(m.Name, manifest.MaxNameBytes, true)
		w.Literal(`:{"entry_incarnation_id":`)
		w.ID(m.EntryIncarnationID)
		count := e.DestinationCount()
		if !w.Destinations(count) {
			return
		}
		w.Literal(`,"destinations":[`)
		for j := 0; j < count; j++ {
			d, ok := e.Destination(j)
			if !ok {
				w.Refuse(manifest.InvalidInput)
				return
			}
			if j > 0 {
				w.Literal(`,`)
			}
			writeDestination(w, d)
		}
		w.Literal(`]}`)
		if w.Failure() != "" {
			return
		}
	}
	w.Literal(`},"excluded_entries":[`)
	for i := 0; i < v.ExcludedCount(); i++ {
		e, ok := v.Excluded(i)
		if !ok {
			w.Refuse(manifest.InvalidInput)
			return
		}
		if i > 0 {
			w.Literal(`,`)
		}
		w.Literal(`{"name":`)
		w.Text(e.Name, manifest.MaxNameBytes, true)
		w.Literal(`,"entry_incarnation_id":`)
		w.ID(e.EntryIncarnationID)
		w.Literal(`,"reason":`)
		w.Text(string(e.Reason), 64, false)
		w.Literal(`}`)
	}
	w.Validate(v)
	w.Literal(`],"evidence_limit":`)
	w.Text(manifest.EvidenceLimit, 256, false)
	w.Literal(`}}`)
}
