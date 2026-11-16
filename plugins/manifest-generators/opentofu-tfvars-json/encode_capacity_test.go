package opentofutfvars

import (
	"bytes"
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
func TestOpenTofuManifestExpansionAccount(t *testing.T) {
	// Every public scalar byte is charged to36MiB; six output bytes cover either
	// worst JSON quoting or Base64. Entry names have a separate quoted allowance.
	// Each destination's fixed syntax and three hexadecimal IDs fit1024 bytes,
	// each included/excluded row's remaining syntax fits1024, and headers fit64KiB.
	const raw = 8 << 20
	const entries = 512
	const destinations = 1024
	const account = 4*((raw+2)/3) + 4*entries + 6*(36<<20) + 6*entries*256 + destinations*1024 + entries*1024 + 65536
	if account != 240104108 || account > manifest.MaxArtifactBytes || manifest.MaxArtifactBytes != 246313668 {
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
func TestOpenTofuManifestMaximumProjectionAndJointExcess(t *testing.T) {
	p := maximumProjection(t)
	const wantLength = 77509258
	const wantDigest = "dcb0ecbb6094816849c87fac28a322ca15d8282e061d0db22b8e0727a86b44a5"
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
	for _, name := range []string{"raw-set", "entry-vector", "per-entry-destinations", "joint-destinations"} {
		t.Run(name, func(t *testing.T) {
			candidate := *p
			candidate.Entries = append([]manifest.Entry(nil), p.Entries...)
			switch name {
			case "raw-set":
				old := candidate.Entries[0].PlainValue
				candidate.Entries[0].PlainValue = make([]byte, len(old)+1)
				copy(candidate.Entries[0].PlainValue, old)
			case "entry-vector":
				candidate.Entries = append(candidate.Entries, manifest.Entry{Name: "512" + strings.Repeat("\x00", 253), EntryIncarnationID: manifest.ID{9}, Kind: manifest.Plain, PlainValue: []byte{}})
				candidate.ResolvedEntries = append(append([]manifest.EntryIdentity(nil), p.ResolvedEntries...), manifest.EntryIdentity{Name: candidate.Entries[512].Name, EntryIncarnationID: manifest.ID{9}})
			case "per-entry-destinations":
				candidate.Entries[510].Destinations = candidate.Entries[510].Destinations[:7:7]
				if f := manifest.Validate(t.Context(), &candidate); f != "" {
					t.Fatal("per-entry baseline", f)
				}
				rows := make([]manifest.Destination, 9)
				copy(rows, candidate.Entries[511].Destinations)
				rows[8] = rows[7]
				rows[8].DestinationID = "zzzz" + strings.Repeat("\x00", 252)
				rows[8].PolicyPresent = false
				rows[8].PolicyContractID = ""
				rows[8].PolicyData = nil
				rows[8].PolicyDigest = manifest.ID{}
				candidate.Entries[511].Destinations = rows
			case "joint-destinations":
				first := &candidate.Entries[0]
				first.Kind, first.PlainValue = manifest.Secret, nil
				first.Destinations = []manifest.Destination{{DestinationID: "extra", BindingIncarnationID: manifest.ID{8}, EntryIncarnationID: first.EntryIncarnationID, ServiceContractID: "private/service", ConsumerLocator: "reference", TargetContractID: "target/v1", CanonicalTarget: "target", PayloadEncoding: manifest.EncodingRaw}}
				saved := candidate.Entries[511].Destinations
				candidate.Entries[511].Destinations = saved[:7:7]
				if f := manifest.Validate(t.Context(), &candidate); f != "" {
					t.Fatal("joint baseline", f)
				}
				candidate.Entries[511].Destinations = saved
			}
			r := Render(t.Context(), manifest.Borrow(&candidate))
			defer clear(r.Artifact[:cap(r.Artifact)])
			if r.Artifact != nil || r.Failure != manifest.LimitExceeded {
				t.Fatal("excess joint dimension", r.Failure)
			}
		})
		runtime.GC()
	}
}
