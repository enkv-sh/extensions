package jsonwriter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"unsafe"

	manifest "enkv.sh/sdk/manifest-generator"
)

type writerCancelContext struct {
	context.Context
	calls, failAt int
}

// full_only: false
func TestWriterPlainChecksKindBeforeState(t *testing.T) {
	projection := &manifest.Projection{Entries: []manifest.Entry{
		{Kind: manifest.Plain, PlainValue: []byte{}},
		{Kind: manifest.Secret},
		{Kind: manifest.Plain, PlainValue: []byte("x")},
	}}
	empty, _ := manifest.Borrow(projection).Entry(0)
	secret, _ := manifest.Borrow(projection).Entry(1)
	plain, _ := manifest.Borrow(projection).Entry(2)
	for _, writing := range []bool{false, true} {
		for _, row := range []struct {
			name  string
			view  manifest.EntryView
			prior manifest.Failure
			want  manifest.Failure
		}{
			{"secret", secret, "", manifest.InvalidInput},
			{"zero", manifest.EntryView{}, "", manifest.InvalidInput},
			{"empty-plain", empty, "", ""},
			{"prior-secret", secret, manifest.Expired, manifest.Expired},
			{"prior-plain", plain, manifest.Expired, manifest.Expired},
		} {
			t.Run(fmt.Sprintf("%s/write=%t", row.name, writing), func(t *testing.T) {
				w := Writer{ctx: t.Context(), at: 3, raw: 5, limit: 8, failed: row.prior}
				if writing {
					w.body = bytes.Repeat([]byte{0xcc}, 8)
				}
				before := bytes.Clone(w.body)
				w.Plain(row.view)
				wantAt := uint64(3)
				if row.want == "" {
					wantAt += 2
					if writing {
						copy(before[3:5], `""`)
					}
				}
				if w.failed != row.want || w.at != wantAt || w.raw != 5 || !bytes.Equal(w.body, before) {
					t.Fatal("plain kind or prior failure changed writer state", w.failed, w.at, w.raw)
				}
			})
		}
	}
}

func (c *writerCancelContext) Err() error {
	c.calls++
	if c.failAt != 0 && c.calls >= c.failAt {
		return context.Canceled
	}
	return c.Context.Err()
}

// full_only: false
func TestWriterBoundedCompletion(t *testing.T) {
	const want = `{"value":"A\u003c\u0026"}`
	emit := func(w *Writer) { w.Literal(`{"value":`); w.Text("A<&", 2048, false); w.Literal(`}`) }
	for _, limit := range []uint64{0, uint64(len(want) - 1), uint64(len(want)), uint64(len(want) + 1)} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			count := Writer{ctx: t.Context(), limit: limit}
			emit(&count)
			if limit < uint64(len(want)) {
				if count.failed != manifest.LimitExceeded {
					t.Fatal("exact output bound", count.failed)
				}
				return
			}
			if count.failed != "" || count.at != uint64(len(want)) || count.body != nil {
				t.Fatal("exact count without artifact", count.failed)
			}
			body := make([]byte, int(count.at))
			w := Writer{ctx: t.Context(), body: body, limit: count.at}
			emit(&w)
			got, f := w.complete(count.at)
			if f != "" || string(got) != want || cap(got) != len(got) {
				t.Fatal("one exact output backing", f)
			}
		})
	}
	tracker := &writerCancelContext{Context: t.Context()}
	count := Writer{ctx: tracker, limit: uint64(len(want))}
	emit(&count)
	body := bytes.Repeat([]byte{0xcc}, len(want))
	late := &writerCancelContext{Context: t.Context(), failAt: tracker.calls + 1}
	w := Writer{ctx: late, body: body, limit: uint64(len(body))}
	emit(&w)
	if w.failed != "" || w.at != uint64(len(want)) {
		t.Fatal("late fixture did not fully encode")
	}
	got, f := w.complete(uint64(len(body)))
	if got != nil || f != manifest.Cancelled || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("late failure did not clear complete provisional backing", f)
	}
}

// full_only: false
func TestEncoderWorkspaceCapacity(t *testing.T) {
	w := Writer{}
	if cap(w.plainWindow[:]) != 49152 || cap(w.quoted[:]) != 12290 || unsafe.Sizeof(w) > 65536 {
		t.Fatal("encoder fixed workspace", unsafe.Sizeof(w))
	}
	w.ctx = t.Context()
	w.limit = 12290
	w.body = make([]byte, 12290)
	w.Text(strings.Repeat("\x00", 2048), 2048, false)
	if w.failed != "" || w.at != 12290 || cap(w.quoted[:]) != 12290 || cap(w.body) != 12290 {
		t.Fatal("quoted token capacity", w.failed, w.at)
	}
}

// full_only: true
// Tests the shared mechanism's known maximum backing. Complete format and
// consumer checks belong to each implementation.
func TestWriterMaximumOwnedBackingAndLateFailure(t *testing.T) {
	id := func(n byte) (id manifest.ID) {
		for i := range id {
			id[i] = n
		}
		return
	}
	destination := manifest.Destination{DestinationID: "primary", BindingIncarnationID: id(7), EntryIncarnationID: id(6), ServiceContractID: "private/service", ConsumerLocator: "reference", TargetContractID: "private/target", CanonicalTarget: "namespace/key", PayloadEncoding: manifest.EncodingRaw}
	p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}"),
		Observation: manifest.Observation{DomainID: id(1), HEADRevisionID: id(2), SnapshotID: id(3)}, TargetRecipientID: id(4), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames},
		Entries: []manifest.Entry{{Name: "secret", EntryIncarnationID: id(6), Kind: manifest.Secret, Destinations: []manifest.Destination{destination}}}, ResolvedEntries: []manifest.EntryIdentity{{Name: "secret", EntryIncarnationID: id(6)}}, ExcludedEntries: []manifest.ExcludedEntry{}}
	// Fixed literal derived directly from the public field values above.
	wantDestination := `{"service":"private/service","locator":"reference"}`
	const prefix = `{"padding":"`
	const middle = `","destination":`
	const suffix = `}`
	const maximum = 246313668
	if uint64(maximum) != manifest.MaxArtifactBytes {
		t.Fatal("generic maximum changed without a derivation")
	}
	padding := maximum - uint64(len(prefix)+len(middle)+len(wantDestination)+len(suffix))
	window := strings.Repeat("a", manifest.PlainWindowBytes)
	emit := func(w *Writer) {
		w.Literal(prefix)
		for remaining := padding; remaining > 0; {
			n := min(remaining, uint64(len(window)))
			w.Literal(window[:int(n)])
			remaining -= n
			if w.failed != "" {
				return
			}
		}
		w.Literal(middle)
		entry, ok := manifest.Borrow(p).Entry(0)
		if !ok {
			t.Fatal("missing owner fixture")
		}
		if !w.Destinations(entry.DestinationCount()) {
			return
		}
		d, ok := entry.Destination(0)
		if !ok {
			t.Fatal("missing destination fixture")
		}
		metadata := d.Metadata()
		w.Literal(`{"service":`)
		w.Text(metadata.ServiceContractID, 256, false)
		w.Literal(`,"locator":`)
		w.Text(metadata.ConsumerLocator, 1024, false)
		w.Literal(`}`)
		w.Literal(suffix)
	}
	// Hash the independent fixed stream without retaining a second artifact.
	wantHash := sha256.New()
	_, _ = io.WriteString(wantHash, prefix)
	for remaining := padding; remaining > 0; {
		n := min(remaining, uint64(len(window)))
		_, _ = io.WriteString(wantHash, window[:int(n)])
		remaining -= n
	}
	_, _ = io.WriteString(wantHash, middle+wantDestination+suffix)
	tracker := &writerCancelContext{Context: t.Context()}
	count := Writer{ctx: tracker, limit: maximum}
	emit(&count)
	if count.body != nil || count.failed != "" || count.at != maximum {
		t.Fatal("maximum count acquired output or changed independent length", count.failed, count.at)
	}
	body := make([]byte, int(maximum))
	for _, name := range []string{"exact-owned-handoff", "cancel-after-last-row", "malformed-last-destination", "limit-last-byte", "one-over-destination-vector"} {
		t.Run(name, func(t *testing.T) {
			for i := range body {
				body[i] = 0xcc
			}
			w := Writer{ctx: t.Context(), body: body, limit: maximum}
			wantReason := manifest.Cancelled
			last := &p.Entries[0].Destinations[0]
			old := last.ConsumerLocator
			oldDestinations := p.Entries[0].Destinations
			defer func() { p.Entries[0].Destinations = oldDestinations; last.ConsumerLocator = old }()
			switch name {
			case "cancel-after-last-row":
				w.ctx = &writerCancelContext{Context: t.Context(), failAt: tracker.calls + 1}
			case "malformed-last-destination":
				last.ConsumerLocator = string([]byte{0xff})
				wantReason = manifest.InvalidUTF8
			case "limit-last-byte":
				w.limit--
				wantReason = manifest.LimitExceeded
			case "one-over-destination-vector":
				p.Entries[0].Destinations = make([]manifest.Destination, 9)
				copy(p.Entries[0].Destinations, oldDestinations)
				wantReason = manifest.LimitExceeded
			}
			emit(&w)
			if w.at < maximum*99/100 {
				t.Fatal("failure was not late in maximum encoding", w.at, maximum)
			}
			got, f := w.complete(maximum)
			if name == "exact-owned-handoff" {
				digest := sha256.Sum256(got)
				if f != "" || uint64(len(got)) != maximum || uint64(cap(got)) != maximum || unsafe.SliceData(got) != unsafe.SliceData(body) || !bytes.Equal(digest[:], wantHash.Sum(nil)) {
					t.Fatal("maximum writer did not transfer its one exact owner", f)
				}
				return
			}
			if got != nil || f != wantReason {
				t.Fatal("maximum partial artifact escaped", f)
			}
			for _, b := range body {
				if b != 0 {
					t.Fatal("maximum provisional capacity was not cleared")
				}
			}
		})
	}
}

// full_only: false
func TestWriterFamilyCountBounds(t *testing.T) {
	const maximum uint64 = 246313668
	w := Writer{ctx: t.Context(), limit: manifest.MaxArtifactBytes}
	w.reserve(maximum)
	if w.at != maximum || w.failed != "" || w.body != nil {
		t.Fatal("exact family count refused or allocated")
	}
	w.reserve(1)
	if w.failed != manifest.LimitExceeded || w.at != maximum || w.body != nil {
		t.Fatal("first excess accepted")
	}
}

type endedContext struct {
	context.Context
	cause error
}

func (c *endedContext) Err() error { return c.cause }

// full_only: false
func TestWriterContextMappingPreservesOriginalPolicy(t *testing.T) {
	for _, row := range []struct {
		name string
		ctx  context.Context
		want manifest.Failure
	}{
		{"nil", nil, manifest.InvalidInput}, {"valid", t.Context(), ""},
		{"cancelled", &endedContext{Context: t.Context(), cause: context.Canceled}, manifest.Cancelled},
		{"expired", &endedContext{Context: t.Context(), cause: context.DeadlineExceeded}, manifest.Expired},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := Encode(row.ctx, manifest.View{}, func(w *Writer, _ manifest.View) { w.Literal(`{}`) })
			if r.Failure != row.want || r.Failure != "" && r.Artifact != nil {
				t.Fatal("context changed encoding", r.Failure)
			}
		})
	}
	var typedNil *endedContext
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_ = Encode(typedNil, manifest.View{}, func(w *Writer, _ manifest.View) { w.Literal(`{}`) })
	}()
	if !panicked {
		t.Fatal("typed-nil caller policy changed")
	}
}

// full_only: false
func TestWriterValidateChecksWholeViewDestinationCounts(t *testing.T) {
	for _, row := range []struct {
		name                  string
		entries, destinations int
		want                  manifest.Failure
	}{
		{"entry-bound", 1, 8, ""}, {"entry-over", 1, 9, manifest.LimitExceeded},
		{"aggregate-bound", 128, 8, ""}, {"aggregate-over", 129, 8, manifest.LimitExceeded},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: "format", ConfigContractID: "config", Settings: []byte(`{}`), Selection: manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}, Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4}, ExcludedEntries: []manifest.ExcludedEntry{}}
			for i := range row.entries {
				name, incarnation := fmt.Sprintf("entry%03d", i), manifest.ID{byte(i + 1), 1}
				e := manifest.Entry{Name: name, EntryIncarnationID: incarnation, Kind: manifest.Secret}
				for j := range row.destinations {
					e.Destinations = append(e.Destinations, manifest.Destination{DestinationID: fmt.Sprintf("slot%02d", j), ServiceContractID: "service", ConsumerLocator: "locator", TargetContractID: "target", CanonicalTarget: "target", BindingIncarnationID: manifest.ID{1}, EntryIncarnationID: incarnation, PayloadEncoding: manifest.EncodingRaw})
				}
				p.Entries = append(p.Entries, e)
				p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: name, EntryIncarnationID: incarnation})
			}
			result := Encode(t.Context(), manifest.Borrow(p), func(w *Writer, v manifest.View) { w.Validate(v); w.Literal(`{}`) })
			if result.Failure != row.want || row.want != "" && result.Artifact != nil {
				t.Fatal("whole-view destination limits changed", result.Failure)
			}
		})
	}
}
