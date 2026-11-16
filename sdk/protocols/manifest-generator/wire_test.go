package manifestprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"unsafe"

	manifest "enkv.sh/sdk/manifest-generator"
)

func projectionFixture() *manifest.Projection {
	return &manifest.Projection{Schema: manifest.Schema, FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte("{}"), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4}, ResolvedEntries: []manifest.EntryIdentity{}, Entries: []manifest.Entry{}, ExcludedEntries: []manifest.ExcludedEntry{}}
}
func renderFixture(p *manifest.Projection) Request {
	return Request{Operation: OperationRender, Correlation: manifest.ID{8}, DescriptorID: manifest.ID{9}, Projection: p}
}
func literalText(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
func literalID(b []byte, first byte) []byte {
	b = append(b, first)
	return append(b, make([]byte, 31)...)
}

// This is the exact empty projection layout from the specification. It uses no
// production codec or reader to derive the expected bytes.
func emptyRequestLiteral() []byte {
	b := append([]byte("ENKV/MANIFEST/v2\x00"), 2)
	b = literalID(b, 8)
	b = literalID(b, 9)
	for _, text := range []string{"ENKV/CONSUMPTION-PROJECTION/v1", "private/format", "private/settings", "{}"} {
		b = literalText(b, text)
	}
	b = append(b, 2, 2, 0)
	for _, id := range []byte{1, 2, 3, 4} {
		b = literalID(b, id)
	}
	return append(b, 0, 0, 0, 0, 0, 0, 0, 0)
}

// full_only: false
func TestRequestMatchesIndependentLiteralAndExactEOF(t *testing.T) {
	var encoded bytes.Buffer
	if err := WriteRequest(t.Context(), &encoded, renderFixture(projectionFixture())); err != nil {
		t.Fatal(err)
	}
	want := emptyRequestLiteral()
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("wire differs\n%x\n%x", encoded.Bytes(), want)
	}
	got, f, err := ReadRequest(t.Context(), bytes.NewReader(want))
	if err != nil || f != "" || got.Correlation != (manifest.ID{8}) || got.DescriptorID != (manifest.ID{9}) || got.Operation != OperationRender || got.Projection.FormatContractID != "private/format" {
		t.Fatal(got.Operation, f, err)
	}
	Dispose(&got)
	for _, bad := range [][]byte{want[:len(want)-1], append(append([]byte(nil), want...), 0)} {
		request, f, err := ReadRequest(t.Context(), bytes.NewReader(bad))
		if err == nil && f == "" || request.Projection != nil {
			t.Fatal("incomplete request accepted", f, err)
		}
	}
}

// full_only: false
func TestStatusHasClosedCodesLengthsAndEOF(t *testing.T) {
	for _, failure := range failures {
		status := Status{Correlation: manifest.ID{8}, Failure: failure}
		if failure == "" {
			status.Length = 3
		}
		var encoded bytes.Buffer
		if err := WriteStatus(&encoded, status); err != nil {
			t.Fatal(err)
		}
		got, err := ReadStatus(bytes.NewReader(encoded.Bytes()))
		if err != nil || got != status || encoded.Len() != 58 {
			t.Fatal(got, err, encoded.Len())
		}
	}
	want := append([]byte("ENKV/MANIFEST/v2\x00"), 8)
	want = append(want, make([]byte, 31)...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 0, 3)
	var encoded bytes.Buffer
	if err := WriteStatus(&encoded, Status{Correlation: manifest.ID{8}, Length: 3}); err != nil || !bytes.Equal(encoded.Bytes(), want) {
		t.Fatal("independent status", err)
	}
	for _, status := range []Status{{Length: 1}, {Correlation: manifest.ID{8}}, {Correlation: manifest.ID{8}, Length: manifest.MaxArtifactBytes + 1}, {Correlation: manifest.ID{8}, Failure: "other"}, {Correlation: manifest.ID{8}, Failure: manifest.InvalidInput, Length: 1}} {
		if WriteStatus(io.Discard, status) == nil {
			t.Fatal("invalid status", status)
		}
	}
	for _, condition := range []string{"magic", "correlation", "failure", "trailing", "truncated"} {
		t.Run(condition, func(t *testing.T) {
			bad := append([]byte(nil), want...)
			switch condition {
			case "magic":
				bad[0] ^= 1
			case "correlation":
				clear(bad[17:49])
			case "failure":
				bad[49] = 99
			case "trailing":
				bad = append(bad, 0)
			case "truncated":
				bad = bad[:len(bad)-1]
			}
			if _, err := ReadStatus(bytes.NewReader(bad)); err == nil {
				t.Fatal("bad status accepted")
			}
		})
	}
}

// full_only: false
func TestRequestRejectsCountsTagsUTF8AndCancellation(t *testing.T) {
	base := emptyRequestLiteral()
	headerEnd := len(base) - 8
	for _, condition := range []string{"magic", "operation", "correlation", "descriptor", "entry-count", "excluded-count", "trailing"} {
		t.Run(condition, func(t *testing.T) {
			bad := append([]byte(nil), base...)
			switch condition {
			case "magic":
				bad[0] ^= 1
			case "operation":
				bad[17] = 3
			case "correlation":
				clear(bad[18:50])
			case "descriptor":
				clear(bad[50:82])
			case "entry-count":
				binary.BigEndian.PutUint32(bad[headerEnd:], 513)
			case "excluded-count":
				binary.BigEndian.PutUint32(bad[headerEnd+4:], 513)
			case "trailing":
				bad = append(bad, 0)
			}
			r, f, err := ReadRequest(t.Context(), bytes.NewReader(bad))
			if f == "" && err == nil || r.Projection != nil {
				t.Fatal("bad request accepted", f, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, f, _ := ReadRequest(ctx, bytes.NewReader(base)); f != manifest.Cancelled {
		t.Fatal(f)
	}
	if _, f, _ := ReadRequest(t.Context(), nil); f != manifest.InvalidInput {
		t.Fatal(f)
	}
	p := projectionFixture()
	p.FormatContractID = string([]byte{255})
	if WriteRequest(t.Context(), io.Discard, renderFixture(p)) == nil {
		t.Fatal("UTF8 escaped boundary")
	}
	p = projectionFixture()
	p.Entries = make([]manifest.Entry, 513)
	if WriteRequest(t.Context(), io.Discard, renderFixture(p)) == nil {
		t.Fatal("first excess entry count")
	}
}

// full_only: false
func TestRequestRoundTripsDestinationsPoliciesAndExcludedPartition(t *testing.T) {
	p := projectionFixture()
	service := "private/values/v42"
	p.ServiceFilter = &service
	p.Entries = []manifest.Entry{{Name: "a", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Plain, PlainValue: []byte{0, 255}}, {Name: "b", EntryIncarnationID: manifest.ID{6}, Kind: manifest.Secret, Destinations: []manifest.Destination{{DestinationID: "private", ServiceContractID: service, ConsumerLocator: "http://local/key", TargetContractID: "private/target", CanonicalTarget: "account/key", TargetData: []byte{0, 1, 255}, PolicyContractID: "private/policy", PolicyData: []byte{0xff, 0, 42}, BindingIncarnationID: manifest.ID{7}, EntryIncarnationID: manifest.ID{6}, PolicyDigest: manifest.ID{10}, PayloadEncoding: manifest.EncodingBase64, PolicyPresent: true}}}}
	p.ExcludedEntries = []manifest.ExcludedEntry{{Name: "c", EntryIncarnationID: manifest.ID{11}, Reason: manifest.NoMatchingService}}
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "a", EntryIncarnationID: manifest.ID{5}}, {Name: "b", EntryIncarnationID: manifest.ID{6}}, {Name: "c", EntryIncarnationID: manifest.ID{11}}}
	var encoded bytes.Buffer
	if err := WriteRequest(t.Context(), &encoded, renderFixture(p)); err != nil {
		t.Fatal(err)
	}
	got, f, err := ReadRequest(t.Context(), bytes.NewReader(encoded.Bytes()))
	if err != nil || f != "" {
		t.Fatal(f, err)
	}
	var roundTrip bytes.Buffer
	if err := WriteRequest(t.Context(), &roundTrip, got); err != nil || !bytes.Equal(roundTrip.Bytes(), encoded.Bytes()) {
		t.Fatal("round trip", err)
	}
	clear(encoded.Bytes())
	if got.Projection.Entries[0].PlainValue[1] != 255 || got.Projection.Entries[1].Destinations[0].PolicyData[0] != 255 {
		t.Fatal("decoder borrowed wire backing")
	}
	plain := got.Projection.Entries[0].PlainValue
	target := got.Projection.Entries[1].Destinations[0].TargetData
	policy := got.Projection.Entries[1].Destinations[0].PolicyData
	settings := got.Projection.Settings
	view := manifest.Borrow(got.Projection)
	Dispose(&got)
	if !allZero(plain) || !allZero(target) || !allZero(policy) || !allZero(settings) || view.Header() != (manifest.Header{}) {
		t.Fatal("request disposal")
	}
}
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// full_only: false
func TestSettingsRequestBindingCanonicalEqualityAndLimits(t *testing.T) {
	request := Request{Operation: OperationValidateSettings, Correlation: manifest.ID{8}, DescriptorID: manifest.ID{9}, Settings: manifest.SettingsRequest{FormatContractID: "private/format", ConfigContractID: "private/settings", Settings: []byte(`{"prefix":"dev"}`)}}
	want := append([]byte("ENKV/MANIFEST/v2\x00"), 1)
	want = literalID(want, 8)
	want = literalID(want, 9)
	want = literalText(want, "private/format")
	want = literalText(want, "private/settings")
	want = append(want, 0)
	want = literalText(want, `{"prefix":"dev"}`)
	var encoded bytes.Buffer
	if err := WriteRequest(t.Context(), &encoded, request); err != nil || !bytes.Equal(encoded.Bytes(), want) {
		t.Fatal("settings literal", err)
	}
	input := append([]byte("ENKV/MANIFEST-SETTINGS/v1\x00"), want...)
	expected := manifest.ID(sha256.Sum256(input))
	digest, err := SettingsRequestDigest(t.Context(), request)
	if err != nil || digest != expected {
		t.Fatal("settings digest", digest, expected, err)
	}
	got, f, err := ReadRequest(t.Context(), bytes.NewReader(want))
	if f != "" || err != nil || !bytes.Equal(got.Settings.Settings, request.Settings.Settings) {
		t.Fatal(f, err)
	}
	Dispose(&got)
	var response bytes.Buffer
	if err := WriteSettingsResponse(t.Context(), &response, SettingsResponse{RequestDigest: digest, Settings: []byte(`{"prefix":"dev"}`)}); err != nil {
		t.Fatal(err)
	}
	r, f, err := ReadSettingsResponse(t.Context(), bytes.NewReader(response.Bytes()), digest, request.Settings.Settings)
	if err != nil || f != "" || !bytes.Equal(r.Settings, request.Settings.Settings) {
		t.Fatal(f, err)
	}
	clear(r.Settings)
	for _, condition := range []string{"wrong-digest", "changed-canonical", "trailing", "malformed-json"} {
		t.Run(condition, func(t *testing.T) {
			body := append([]byte(nil), response.Bytes()...)
			canonical := request.Settings.Settings
			switch condition {
			case "wrong-digest":
				body[0] ^= 1
			case "changed-canonical":
				canonical = []byte(`{"prefix":"other"}`)
			case "trailing":
				body = append(body, 0)
			case "malformed-json":
				body[len(body)-1] = 'x'
			}
			r, f, err := ReadSettingsResponse(t.Context(), bytes.NewReader(body), digest, canonical)
			if f == "" && err == nil || r.Settings != nil {
				t.Fatal("bad response accepted", f, err)
			}
		})
	}
	request.Settings.Settings = []byte(`"` + strings.Repeat("x", 16382) + `"`)
	request.Settings.FormatContractID = strings.Repeat("f", 256)
	request.Settings.ConfigContractID = strings.Repeat("c", 256)
	encoded.Reset()
	if err := WriteRequest(t.Context(), &encoded, request); err != nil || encoded.Len() != 16991 {
		t.Fatal("maximum settings request", encoded.Len(), err)
	}
	request.Settings.Settings = append(request.Settings.Settings, ' ')
	if WriteRequest(t.Context(), io.Discard, request) == nil {
		t.Fatal("first excess settings")
	}
}

// full_only: false
func TestPolicyDecoderChecksFieldLimitBeforeReadingBody(t *testing.T) {
	p := projectionFixture()
	policy := []byte{0xba, 0xad, 0xfa, 0xce, 0x22, 0x33, 0x44}
	p.Entries = []manifest.Entry{{Name: "secret", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Secret, Destinations: []manifest.Destination{{DestinationID: "slot", ServiceContractID: "private/service", ConsumerLocator: "local://key", TargetContractID: "private/target", CanonicalTarget: "key", PolicyContractID: "private/policy", PolicyData: policy, BindingIncarnationID: manifest.ID{6}, EntryIncarnationID: manifest.ID{5}, PolicyDigest: manifest.ID{7}, PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true}}}}
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "secret", EntryIncarnationID: manifest.ID{5}}}
	var encoded bytes.Buffer
	if err := WriteRequest(t.Context(), &encoded, renderFixture(p)); err != nil {
		t.Fatal(err)
	}
	body := encoded.Bytes()
	at := bytes.Index(body, policy)
	if at < 4 {
		t.Fatal("fixture policy absent")
	}
	binary.BigEndian.PutUint32(body[at-4:at], 524547)
	request, f, err := ReadRequest(t.Context(), bytes.NewReader(body[:at]))
	if f != manifest.LimitExceeded || err != nil || request.Projection != nil {
		t.Fatal("excess body was read", f, err)
	}
}

// full_only: false
func TestStreamingWorkspaceHasOneBoundedWindowPerDirection(t *testing.T) {
	w := writer{}
	r := reader{}
	if cap(w.window[:]) != 49152 || cap(r.window[:]) != 49152 || unsafe.Sizeof(w) > 49152+256 || unsafe.Sizeof(r) > 49152+256 {
		t.Fatal("streaming workspace", unsafe.Sizeof(w), unsafe.Sizeof(r))
	}
}

type windowReader struct{ reader io.Reader }

func (r windowReader) Read(b []byte) (int, error) {
	if len(b) > 49152 {
		return 0, ErrWire
	}
	return r.reader.Read(b)
}

type windowWriter struct{ bytes.Buffer }

func (w *windowWriter) Write(b []byte) (int, error) {
	if len(b) > 49152 {
		return 0, ErrWire
	}
	return w.Buffer.Write(b)
}

// full_only: false
func TestLargeOpaquePolicyUsesBoundedWindows(t *testing.T) {
	p := projectionFixture()
	policy := bytes.Repeat([]byte{0xa5}, 524546)
	p.Entries = []manifest.Entry{{Name: "secret", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Secret, Destinations: []manifest.Destination{{DestinationID: "slot", ServiceContractID: "private/service", ConsumerLocator: "local://key", TargetContractID: "private/target", CanonicalTarget: "key", PolicyContractID: "private/policy", PolicyData: policy, BindingIncarnationID: manifest.ID{6}, EntryIncarnationID: manifest.ID{5}, PolicyDigest: manifest.ID{7}, PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true}}}}
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "secret", EntryIncarnationID: manifest.ID{5}}}
	var encoded windowWriter
	if err := WriteRequest(t.Context(), &encoded, renderFixture(p)); err != nil {
		t.Fatal(err)
	}
	request, f, err := ReadRequest(t.Context(), windowReader{bytes.NewReader(encoded.Bytes())})
	if err != nil || f != "" || !bytes.Equal(request.Projection.Entries[0].Destinations[0].PolicyData, policy) {
		t.Fatal(f, err)
	}
	Dispose(&request)
}

type endedContext struct {
	context.Context
	cause error
}

func (c *endedContext) Err() error { return c.cause }

// full_only: false
func TestRequestContextMappingPreservesOriginalPolicy(t *testing.T) {
	var typedNil *endedContext
	for _, row := range []struct {
		name string
		ctx  context.Context
		want manifest.Failure
	}{
		{"nil", nil, manifest.InvalidInput}, {"typed-nil", typedNil, manifest.InvalidInput}, {"valid", t.Context(), ""},
		{"cancelled", &endedContext{Context: t.Context(), cause: context.Canceled}, manifest.Cancelled},
		{"expired", &endedContext{Context: t.Context(), cause: context.DeadlineExceeded}, manifest.Expired},
	} {
		t.Run(row.name, func(t *testing.T) {
			request, failure, err := ReadRequest(row.ctx, bytes.NewReader(emptyRequestLiteral()))
			if err != nil || failure != row.want || failure != "" && request.Projection != nil {
				t.Fatal("context changed request result", failure, err)
			}
			Dispose(&request)
		})
	}
}

// full_only: false
func TestRequestLocatorBoundsAgreeWithTypedProjection(t *testing.T) {
	p := projectionFixture()
	p.ResolvedEntries = []manifest.EntryIdentity{{Name: "secret", EntryIncarnationID: manifest.ID{5}}}
	p.Entries = []manifest.Entry{{Name: "secret", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Secret, Destinations: []manifest.Destination{{DestinationID: "slot", ServiceContractID: "service", ConsumerLocator: strings.Repeat("L", 1024), TargetContractID: "target", CanonicalTarget: strings.Repeat("C", 1024), TargetData: []byte{}, BindingIncarnationID: manifest.ID{6}, EntryIncarnationID: manifest.ID{5}, PayloadEncoding: manifest.EncodingRaw}}}}
	var encoded bytes.Buffer
	if err := WriteRequest(t.Context(), &encoded, renderFixture(p)); err != nil {
		t.Fatal(err)
	}
	for _, letter := range []string{"L", "C"} {
		for _, row := range []struct {
			name, replacement string
			want              manifest.Failure
		}{
			{"at-bound", strings.Repeat(letter, 1024), ""},
			{"over-bound", strings.Repeat(letter, 1025), manifest.LimitExceeded},
			{"invalid-utf8", strings.Repeat(letter, 1023) + "\xff", manifest.InvalidUTF8},
		} {
			t.Run(letter+"/"+row.name, func(t *testing.T) {
				bad := bytes.Replace(encoded.Bytes(), literalText(nil, strings.Repeat(letter, 1024)), literalText(nil, row.replacement), 1)
				request, failure, err := ReadRequest(t.Context(), bytes.NewReader(bad))
				if err != nil || failure != row.want {
					t.Fatal("raw locator admission changed", failure, err)
				}
				Dispose(&request)
				candidate := *p
				destination := p.Entries[0].Destinations[0]
				if letter == "L" {
					destination.ConsumerLocator = row.replacement
				} else {
					destination.CanonicalTarget = row.replacement
				}
				candidate.Entries = []manifest.Entry{{Name: "secret", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Secret, Destinations: []manifest.Destination{destination}}}
				if got := manifest.Validate(t.Context(), &candidate); got != row.want {
					t.Fatal("typed locator admission changed", got)
				}
			})
		}
	}
}
