// Package genericjson renders the canonical v3 consumption manifest grammar.
package genericjson

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
	if v.EntryCount() > manifest.MaxEntries || v.ExcludedCount() > manifest.MaxEntries-v.EntryCount() {
		w.Refuse(manifest.LimitExceeded)
		return
	}
	w.Literal("{\n")
	writeHeader(w, v)
	w.Literal(",\n  \"entries\": [")
	if v.EntryCount() > 0 {
		w.Literal("\n")
	}
	for i := 0; i < v.EntryCount(); i++ {
		e, ok := v.Entry(i)
		if !ok {
			w.Refuse(manifest.InvalidInput)
			return
		}
		r := e.Metadata()
		if i > 0 {
			w.Literal(",\n")
		}
		w.Literal("    {\n      \"name\": ")
		w.Text(r.Name, manifest.MaxNameBytes, true)
		w.Literal(",\n      \"entry_incarnation_id\": ")
		w.ID(r.EntryIncarnationID)
		w.Literal(",\n      \"content\": ")
		switch r.Kind {
		case manifest.Plain:
			w.Literal("{\n        \"kind\": \"plain\",\n        \"value_base64\": ")
			w.Plain(e)
			w.Literal("\n      }")
		case manifest.Secret:
			count := e.DestinationCount()
			if !w.Destinations(count) {
				return
			}
			w.Literal("{\n        \"kind\": \"secret\",\n        \"destinations\": [\n")
			for j := 0; j < count; j++ {
				d, ok := e.Destination(j)
				if !ok {
					w.Refuse(manifest.InvalidInput)
					return
				}
				if j > 0 {
					w.Literal(",\n")
				}
				writeDestination(w, d)
			}
			w.Literal("\n        ]\n      }")
		default:
			w.Refuse(manifest.InvalidInput)
			return
		}
		w.Literal("\n    }")
		if w.Failure() != "" {
			return
		}
	}
	if v.EntryCount() > 0 {
		w.Literal("\n  ")
	}
	w.Literal("],\n  \"excluded_entries\": [")
	if v.ExcludedCount() > 0 {
		w.Literal("\n")
	}
	for i := 0; i < v.ExcludedCount(); i++ {
		r, ok := v.Excluded(i)
		if !ok {
			w.Refuse(manifest.InvalidInput)
			return
		}
		if i > 0 {
			w.Literal(",\n")
		}
		w.Literal("    {\n      \"name\": ")
		w.Text(r.Name, manifest.MaxNameBytes, true)
		w.Literal(",\n      \"entry_incarnation_id\": ")
		w.ID(r.EntryIncarnationID)
		w.Literal(",\n      \"reason\": ")
		w.Text(string(r.Reason), 64, false)
		w.Literal("\n    }")
	}
	if w.Failure() == "" {
		w.Validate(v)
	}
	if v.ExcludedCount() > 0 {
		w.Literal("\n  ")
	}
	w.Literal("],\n  \"evidence_limit\": ")
	w.Text(manifest.EvidenceLimit, 256, false)
	w.Literal("\n}\n")
}
