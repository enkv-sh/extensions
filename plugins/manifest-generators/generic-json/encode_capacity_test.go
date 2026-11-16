package genericjson

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	manifest "enkv.sh/sdk/manifest-generator"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func maximumProjection(t *testing.T) *manifest.Projection {
	t.Helper()
	id := func(n byte) (id manifest.ID) {
		for i := range id {
			id[i] = n
		}
		return
	}
	p := &manifest.Projection{Schema: manifest.Schema, FormatContractID: FormatContractID, ConfigContractID: ConfigContractID, Settings: []byte(`{}`), Observation: manifest.Observation{DomainID: id(1), HEADRevisionID: id(2), SnapshotID: id(3)}, TargetRecipientID: id(0x22), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, ExcludedEntries: []manifest.ExcludedEntry{}, Entries: make([]manifest.Entry, 512), ResolvedEntries: make([]manifest.EntryIdentity, 512)}
	var raw, output int
	for i := range p.Entries {
		e := &p.Entries[i]
		e.Name = fmt.Sprintf("%03d", i) + strings.Repeat("\x00", 253)
		binary.BigEndian.PutUint32(e.EntryIncarnationID[:4], uint32(i+1))
		p.ResolvedEntries[i] = manifest.EntryIdentity{Name: e.Name, EntryIncarnationID: e.EntryIncarnationID}
		if i < 384 {
			e.Kind = manifest.Plain
			n := (8 << 20) / 384
			if i < (8<<20)%384 {
				n++
			}
			e.PlainValue = bytes.Repeat([]byte{byte(i)}, n)
			raw += n
			continue
		}
		e.Kind = manifest.Secret
		e.Destinations = make([]manifest.Destination, 8)
		for j := range e.Destinations {
			k := (i-384)*8 + j
			length := 28728
			if k < 2 {
				length = 524546
			} else if k < 406 {
				length = 28727
			}
			e.Destinations[j] = manifest.Destination{DestinationID: fmt.Sprintf("%04d", k) + strings.Repeat("\x00", 252), BindingIncarnationID: manifest.ID{7}, EntryIncarnationID: e.EntryIncarnationID, ServiceContractID: strings.Repeat("\x00", 256), ConsumerLocator: strings.Repeat("\x00", 1024), TargetContractID: strings.Repeat("\x00", 256), CanonicalTarget: strings.Repeat("\x00", 1024), TargetData: bytes.Repeat([]byte{255}, 4096), PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true, PolicyContractID: strings.Repeat("\x00", 256), PolicyData: bytes.Repeat([]byte{255}, length), PolicyDigest: id(9)}
			output += 4*256 + 2*1024 + 4096 + length
		}
	}
	if raw != 8<<20 || output != 36<<20 || len(p.Entries) != cap(p.Entries) {
		t.Fatal("independent joint maximum", raw, output)
	}
	return p
}

// full_only: false
func TestConsumptionManifestJSONExpansionAccount(t *testing.T) {
	// Every public scalar byte is charged to36MiB; six output bytes cover either
	// worst JSON quoting or Base64. Entry names have a separate quoted allowance.
	// Each destination's fixed syntax and three hexadecimal IDs fit1024 bytes,
	// each included/excluded row's remaining syntax fits1024, and headers fit64KiB.
	const raw = 8 << 20
	const entries = 512
	const destinations = 1024
	const compact = 4*((raw+2)/3) + 4*entries + 6*(36<<20) + 6*entries*256 + destinations*1024 + entries*1024 + 65536
	// The deepest member uses fourteen indentation spaces. LF and colon space
	// add two more. Ten destination fields, three policy fields and their
	// delimiters fit 512 extra bytes per destination; entry/content/array
	// lines fit 256 per entry, and the complete header and final LF fit 4096.
	const formatting = destinations*512 + entries*256 + 4096
	const account = compact + formatting
	if compact != 240104108 || formatting != 659456 || account != 240763564 || account > manifest.MaxArtifactBytes || manifest.MaxArtifactBytes != 246313668 {
		t.Fatal("independent expansion account")
	}
	const separate = entries * 4
	const aggregate = 4 * ((entries + 2) / 3)
	if separate != 2048 || aggregate != 684 || separate-aggregate > 4*entries {
		t.Fatal("per-entry Base64 padding")
	}
}

// full_only: true
// Joint maximum:8MiB raw,512 unique entries,1024 destinations,36MiB public
// destination bytes, including two maximum524546-byte policies.
// Expected bytes are independently derived by Python JSON/Base64/SHA-256.
func TestConsumptionManifestJSONMaximumProjectionExpansion(t *testing.T) {
	p := maximumProjection(t)
	const wantLength = 77782597
	const wantDigest = "a16c2da6556a966df48acc0f726492f2cddb625a62153b7023cc13c8bf7d1822"
	t.Run("complete", func(t *testing.T) {
		r := Render(t.Context(), manifest.Borrow(p))
		defer clear(r.Artifact[:cap(r.Artifact)])
		if r.Failure != "" || len(r.Artifact) != wantLength || cap(r.Artifact) != wantLength {
			t.Fatal("complete maximum artifact", r.Failure, len(r.Artifact), cap(r.Artifact))
		}
		digest := sha256.Sum256(r.Artifact)
		if hex.EncodeToString(digest[:]) != wantDigest {
			t.Fatal("independent maximum digest")
		}
		metadata, f := manifest.MeasureArtifact(t.Context(), r.Artifact)
		if f != "" || metadata.Length != wantLength || metadata.Digest != digest {
			t.Fatal("exact-byte measurement", f)
		}
		p.Entries[0].PlainValue[0] ^= 255
		p.Entries[511].Destinations[7].PolicyData[0] ^= 255
		changed := sha256.Sum256(r.Artifact)
		p.Entries[0].PlainValue[0] ^= 255
		p.Entries[511].Destinations[7].PolicyData[0] ^= 255
		if changed != digest {
			t.Fatal("artifact aliases public owners")
		}
		t.Logf("artifact_bytes=%d raw_bytes=8388608 entries=512 destinations=1024 output_bytes=37748736", len(r.Artifact))
	})
	runtime.GC()
	calls := manifestCountingCalls(t, p)
	for _, name := range []string{"cancel-after-last-row", "malformed-last-destination", "one-over-destination-vector"} {
		t.Run(name, func(t *testing.T) {
			last := &p.Entries[511].Destinations[7]
			oldLocator := last.ConsumerLocator
			oldDestinations := p.Entries[511].Destinations
			defer func() { p.Entries[511].Destinations = oldDestinations; last.ConsumerLocator = oldLocator }()
			ctx := t.Context()
			want := manifest.Cancelled
			var changed *manifestMutationContext
			switch name {
			case "cancel-after-last-row":
				ctx = &manifestCancelContext{Context: t.Context(), failAt: 2*calls + 1}
			case "malformed-last-destination":
				want = manifest.InvalidUTF8
				changed = &manifestMutationContext{Context: t.Context(), at: calls + 1, mutate: func() { last.ConsumerLocator = string([]byte{255}) }}
				ctx = changed
			case "one-over-destination-vector":
				want = manifest.LimitExceeded
				changed = &manifestMutationContext{Context: t.Context(), at: calls + 1, mutate: func() {
					p.Entries[511].Destinations = make([]manifest.Destination, 9)
					copy(p.Entries[511].Destinations, oldDestinations)
					p.Entries[511].Destinations[8] = *last
				}}
				ctx = changed
			}
			r := Render(ctx, manifest.Borrow(p))
			if r.Artifact != nil || r.Failure != want {
				t.Fatal("partial maximum escaped", r.Failure, want)
			}
			if changed != nil && !changed.changed {
				t.Fatal("late mutation missed second pass")
			}
		})
		runtime.GC()
	}
}

// full_only: false
func TestConsumptionManifestJSONPartitionJointRowLimit(t *testing.T) {
	m, _ := manifestJSONLiteralFixture()
	m.Entries = []manifest.Entry{}
	m.ExcludedEntries = make([]manifest.ExcludedEntry, 512)
	m.ResolvedEntries = make([]manifest.EntryIdentity, 512)
	m.Selection = manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	for i := range m.ExcludedEntries {
		name := fmt.Sprintf("%03d", i) + strings.Repeat("\x00", 253)
		id := manifest.ID{byte(i), byte(i >> 8), 1}
		m.ExcludedEntries[i] = manifest.ExcludedEntry{Name: name, EntryIncarnationID: id, Reason: manifest.NoOutput}
		m.ResolvedEntries[i] = manifest.EntryIdentity{Name: name, EntryIncarnationID: id}
	}
	got, f := encodeForTest(t.Context(), m)
	if f != "" || len(got) != cap(got) || len(got) == 0 {
		t.Fatal("512 excluded rows", f)
	}
	m.Entries = []manifest.Entry{{Name: "z", EntryIncarnationID: manifest.ID{9}, Kind: manifest.Plain, PlainValue: []byte{}}}
	got, f = encodeForTest(t.Context(), m)
	if got != nil || f != manifest.LimitExceeded {
		t.Fatal("included and excluded must share one 512-row limit", f)
	}
	m.ExcludedEntries = m.ExcludedEntries[:511]
	m.ResolvedEntries[511] = manifest.EntryIdentity{Name: "z", EntryIncarnationID: manifest.ID{9}}
	got, f = encodeForTest(t.Context(), m)
	if f != "" || len(got) == 0 {
		t.Fatal("511 excluded plus one included", f)
	}
	m.ResolvedEntries[511].EntryIncarnationID = manifest.ID{10}
	got, f = encodeForTest(t.Context(), m)
	if got != nil || f != manifest.InvalidInput {
		t.Fatal("exact resolved union identity", f)
	}
}

type manifestMutationContext struct {
	context.Context
	calls, at int
	mutate    func()
	changed   bool
}

func (c *manifestMutationContext) Err() error {
	c.calls++
	if !c.changed && c.calls >= c.at {
		c.mutate()
		c.changed = true
	}
	return c.Context.Err()
}
