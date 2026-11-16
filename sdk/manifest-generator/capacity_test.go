package manifest_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

// full_only: false
func TestManifestCopyAllocationBounds(t *testing.T) {
	plain := bytes.Repeat([]byte{0xa5}, 65536)
	p := &manifest.Projection{Entries: []manifest.Entry{{Kind: manifest.Plain, PlainValue: plain}}}
	e, _ := manifest.Borrow(p).Entry(0)
	dst := make([]byte, 65536)
	if allocations := testing.AllocsPerRun(100, func() {
		if n, f := e.CopyPlainValue(dst); n != 65536 || f != "" {
			panic("plain copy refused")
		}
	}); allocations != 0 {
		t.Fatal("plain copy allocations", allocations)
	}
	// Source capacity is author-owned and is not limited by the logical JSON size.
	source := make([]byte, 16384, 20000)
	copy(source, `"`+strings.Repeat("s", 16382)+`"`)
	if allocations := testing.AllocsPerRun(100, func() {
		r := manifest.CopySettingsResult(context.Background(), source)
		if r.Failure != "" || len(r.Settings) != 16384 || cap(r.Settings) != 16384 {
			panic("settings copy capacity")
		}
		clear(r.Settings[:cap(r.Settings)])
	}); allocations != 1 {
		t.Fatal("settings copy allocations", allocations)
	}
	if cap(source)+manifest.MaxSettingsBytes != 36384 {
		t.Fatal("simultaneous caller scratch and exact result account")
	}
}

// full_only: false
func TestProjectionWorkspaceCapacity(t *testing.T) {
	if unsafe.Sizeof(manifest.Projection{}) != 312 || unsafe.Sizeof(manifest.Entry{}) != 104 || unsafe.Sizeof(manifest.Destination{}) != 248 || unsafe.Sizeof(manifest.Header{}) != 248 || unsafe.Sizeof(manifest.DestinationMetadata{}) != 200 {
		t.Fatal("projection native layout", unsafe.Sizeof(manifest.Projection{}), unsafe.Sizeof(manifest.Entry{}), unsafe.Sizeof(manifest.Destination{}), unsafe.Sizeof(manifest.Header{}), unsafe.Sizeof(manifest.DestinationMetadata{}))
	}
	if manifest.PlainWindowBytes != 49152 || manifest.MaxArtifactBytes != 246313668 || manifest.MaxSettingsBytes != 16384 || manifest.MaxOutputBytes != 37748736 {
		t.Fatal("family bounds")
	}
}

func capacityID(n uint16) (id manifest.ID) {
	binary.BigEndian.PutUint16(id[:2], n)
	return id
}

// The independent fixture has 129 plain and 383 secret entries. The first 127
// plain values have 65,536 bytes and the final two have 32,768: exactly 8 MiB.
// Secret entries have 258*3+125*2=1,024 destinations. Each destination has
// 7,168 bytes of bounded strings/target data and 29,696 opaque policy bytes:
// 1,024*(7,168+29,696)=36 MiB. Every name and header setting uses its field bound.
func maximumProjection() *manifest.Projection {
	service := strings.Repeat("S", 256)
	p := &manifest.Projection{
		Schema: manifest.Schema, FormatContractID: strings.Repeat("F", 256), ConfigContractID: strings.Repeat("C", 256), Settings: []byte(`"` + strings.Repeat("s", 16382) + `"`),
		Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, ServiceFilter: &service,
		Observation: manifest.Observation{DomainID: capacityID(1000), HEADRevisionID: capacityID(1001), SnapshotID: capacityID(1002)}, TargetRecipientID: capacityID(1003),
		Entries: make([]manifest.Entry, 0, 512), ExcludedEntries: []manifest.ExcludedEntry{}, ResolvedEntries: make([]manifest.EntryIdentity, 0, 512),
	}
	for i := 0; i < 129; i++ {
		n := 65536
		if i >= 127 {
			n = 32768
		}
		name := fmt.Sprintf("p%03d", i) + strings.Repeat("n", 252)
		entry := manifest.Entry{Name: name, EntryIncarnationID: capacityID(uint16(i + 1)), Kind: manifest.Plain, PlainValue: bytes.Repeat([]byte{0xa5}, n)}
		p.Entries = append(p.Entries, entry)
		p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: name, EntryIncarnationID: entry.EntryIncarnationID})
	}
	target := 0
	for i := 0; i < 383; i++ {
		count := 2
		if i < 258 {
			count = 3
		}
		name := fmt.Sprintf("s%03d", i) + strings.Repeat("n", 252)
		entry := manifest.Entry{Name: name, EntryIncarnationID: capacityID(uint16(130 + i)), Kind: manifest.Secret, Destinations: make([]manifest.Destination, count)}
		for j := range entry.Destinations {
			entry.Destinations[j] = manifest.Destination{
				DestinationID: fmt.Sprintf("d%d", j) + strings.Repeat("d", 254), ServiceContractID: service,
				ConsumerLocator: fmt.Sprintf("local:%04d", target) + strings.Repeat("l", 1014), TargetContractID: strings.Repeat("T", 256),
				CanonicalTarget: fmt.Sprintf("target-%04d", target) + strings.Repeat("t", 1013), TargetData: bytes.Repeat([]byte{0x5a}, 4096),
				PolicyContractID: strings.Repeat("P", 256), PolicyData: bytes.Repeat([]byte{0x7f}, 29696), PolicyDigest: capacityID(700),
				BindingIncarnationID: capacityID(uint16(600 + j)), EntryIncarnationID: entry.EntryIncarnationID, PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true,
			}
			target++
		}
		p.Entries = append(p.Entries, entry)
		p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: name, EntryIncarnationID: entry.EntryIncarnationID})
	}
	return p
}

// full_only: false
func TestProjectionJointAggregateCapacityAndFirstExcess(t *testing.T) {
	p := maximumProjection()
	defer protocol.DisposeProjection(p)
	raw, output, targets := 0, 0, 0
	for _, e := range p.Entries {
		raw += len(e.PlainValue)
		for _, d := range e.Destinations {
			targets++
			output += len(d.DestinationID) + len(d.ServiceContractID) + len(d.ConsumerLocator) + len(d.TargetContractID) + len(d.CanonicalTarget) + len(d.TargetData) + len(d.PolicyContractID) + len(d.PolicyData)
		}
	}
	if len(p.Entries) != 512 || targets != 1024 || raw != 8388608 || output != 37748736 {
		t.Fatal("independent maximum fixture changed", len(p.Entries), targets, raw, output)
	}
	t.Run("joint-maximum", func(t *testing.T) {
		if f := manifest.Validate(t.Context(), p); f != "" {
			t.Fatal("joint maximum refused", f)
		}
		var encoded bytes.Buffer
		defer func() { clear(encoded.Bytes()) }()
		if err := protocol.WriteRequest(t.Context(), &encoded, protocol.Request{Operation: protocol.OperationRender, Correlation: capacityID(1004), DescriptorID: capacityID(1005), Projection: p}); err != nil {
			t.Fatal(err)
		}
		// 8 MiB raw + 36 MiB variable destination bytes + 512*297 entry
		// framing + 1,024*130 destination framing + 17,423 header bytes.
		// The fixed projection-schema text has 30 bytes rather than its 256-byte
		// conservative header allowance, making this 226 below the wire ceiling.
		if encoded.Len() != 46439951 {
			t.Fatal("independent complete wire length changed", encoded.Len())
		}
		decoded, f, err := protocol.ReadRequest(t.Context(), bytes.NewReader(encoded.Bytes()))
		defer protocol.Dispose(&decoded)
		if err != nil || f != "" || decoded.Projection == nil || len(decoded.Projection.Entries) != 512 || len(decoded.Projection.Entries[128].PlainValue) != 32768 || len(decoded.Projection.Entries[129].Destinations[0].PolicyData) != 29696 {
			t.Fatal("joint maximum did not survive native framing", f, err)
		}
	})
	t.Run("first-excess-raw-aggregate", func(t *testing.T) {
		previous := p.Entries[128].PlainValue
		p.Entries[128].PlainValue = append(previous, 0)
		defer func() { clear(p.Entries[128].PlainValue); p.Entries[128].PlainValue = previous }()
		if len(p.Entries[128].PlainValue) >= 65536 {
			t.Fatal("fixture exceeded a field before its aggregate")
		}
		if f := manifest.Validate(t.Context(), p); f != manifest.LimitExceeded {
			t.Fatal("first excess raw aggregate admitted", f)
		}
	})
	t.Run("first-excess-destination-aggregate", func(t *testing.T) {
		destination := &p.Entries[129].Destinations[0]
		previous := destination.PolicyData
		destination.PolicyData = append(previous, 0)
		defer func() { clear(destination.PolicyData); destination.PolicyData = previous }()
		if len(destination.PolicyData) >= 524546 {
			t.Fatal("fixture exceeded a field before its aggregate")
		}
		if f := manifest.Validate(t.Context(), p); f != manifest.LimitExceeded {
			t.Fatal("first excess destination aggregate admitted", f)
		}
	})
}
