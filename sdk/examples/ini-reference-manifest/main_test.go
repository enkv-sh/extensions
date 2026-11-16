package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/sdk/examples/ini-reference-manifest/consumer"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/conformance"
	"enkv.sh/sdk/manifest-generator/jsonwriter"
	"enkv.sh/sdk/manifest-generator/native"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

func id(n byte) (id manifest.ID) {
	for i := range id {
		id[i] = n
	}
	return
}
func mixedProjection() *manifest.Projection {
	service := "private/values/v1"
	return &manifest.Projection{Schema: manifest.Schema, FormatContractID: formatContract, ConfigContractID: configContract, Settings: []byte(`{"section_prefix":"app"}`), Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, ServiceFilter: &service, Observation: manifest.Observation{DomainID: id(1), HEADRevisionID: id(2), SnapshotID: id(3)}, TargetRecipientID: id(4), Entries: []manifest.Entry{{Name: "greeting", EntryIncarnationID: id(5), Kind: manifest.Plain, PlainValue: []byte{0, 255, 10}}, {Name: "password", EntryIncarnationID: id(6), Kind: manifest.Secret, Destinations: []manifest.Destination{{DestinationID: "primary", ServiceContractID: service, ConsumerLocator: "http://127.0.0.1/values/password", TargetContractID: "private/key/v1", CanonicalTarget: "dev/password", TargetData: []byte{0, 1}, PolicyContractID: "private/access/v1", PolicyData: []byte{0xfe, 0}, BindingIncarnationID: id(7), EntryIncarnationID: id(6), PolicyDigest: id(8), PayloadEncoding: manifest.EncodingBase64, PolicyPresent: true}}}}, ExcludedEntries: []manifest.ExcludedEntry{{Name: "unused", EntryIncarnationID: id(9), Reason: manifest.NoMatchingService}}, ResolvedEntries: []manifest.EntryIdentity{{Name: "greeting", EntryIncarnationID: id(5)}, {Name: "password", EntryIncarnationID: id(6)}, {Name: "unused", EntryIncarnationID: id(9)}}}
}

// Expected bytes are a literal derivation of every fixture field. IDs repeat
// their fixed byte, and Base64 values below were derived from the listed bytes.
func expectedMixed() []byte {
	return []byte(`[app.manifest]
format="example/ini-reference/v1"
projection_schema="ENKV/CONSUMPTION-PROJECTION/v1"
config_contract="example/ini-reference-settings/v1"
settings_base64="eyJzZWN0aW9uX3ByZWZpeCI6ImFwcCJ9"
domain_id="` + strings.Repeat("01", 32) + `"
head_revision_id="` + strings.Repeat("02", 32) + `"
snapshot_id="` + strings.Repeat("03", 32) + `"
target_recipient_id="` + strings.Repeat("04", 32) + `"
target_mode="exact-recipient"
entry_mode="exact-names"
has_service_filter="true"
service_filter_base64="cHJpdmF0ZS92YWx1ZXMvdjE="
evidence_limit="authorized-input-and-exact-bytes"
included_count="2"
excluded_count="1"

[app.entry.0]
name_base64="Z3JlZXRpbmc="
incarnation_id="` + strings.Repeat("05", 32) + `"
kind="plain"
value_base64="AP8K"

[app.entry.1]
name_base64="cGFzc3dvcmQ="
incarnation_id="` + strings.Repeat("06", 32) + `"
kind="secret"
destination_count="1"

[app.entry.1.destination.0]
destination_id_base64="cHJpbWFyeQ=="
binding_incarnation_id="` + strings.Repeat("07", 32) + `"
entry_incarnation_id="` + strings.Repeat("06", 32) + `"
service_contract_base64="cHJpdmF0ZS92YWx1ZXMvdjE="
target_contract_base64="cHJpdmF0ZS9rZXkvdjE="
canonical_target_base64="ZGV2L3Bhc3N3b3Jk"
consumer_locator_base64="aHR0cDovLzEyNy4wLjAuMS92YWx1ZXMvcGFzc3dvcmQ="
target_data_base64="AAE="
payload_encoding="base64"
policy_present="true"
policy_contract_base64="cHJpdmF0ZS9hY2Nlc3MvdjE="
policy_digest="` + strings.Repeat("08", 32) + `"
policy_data_base64="/gA="

[app.excluded.0]
name_base64="dW51c2Vk"
incarnation_id="` + strings.Repeat("09", 32) + `"
reason="no-matching-service"

`)
}
func expectedConsumer(body []byte) error {
	document, err := consumer.Read(bytes.NewReader(body))
	if err != nil {
		return err
	}
	values, err := document.PlainValues()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(values, map[string][]byte{"greeting": {0, 255, 10}}) {
		return errors.New("plain values differ")
	}
	references, err := document.References()
	if err != nil {
		return err
	}
	want := []consumer.Reference{{EntryName: "password", DestinationID: "primary", ServiceContract: "private/values/v1", Locator: "http://127.0.0.1/values/password"}}
	if !reflect.DeepEqual(references, want) {
		return errors.New("references differ")
	}
	excluded := document.Sections["app.excluded.0"]
	if excluded["name_base64"] != "dW51c2Vk" || excluded["reason"] != "no-matching-service" {
		return errors.New("exclusion differs")
	}
	return nil
}

// full_only: false
func TestSettingsOwnDefaultsCanonicalizationAndRejection(t *testing.T) {
	implementation, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("fixture-field-diagnosis", func(t *testing.T) {
		fixture := conformance.SettingsFixture{Request: manifest.SettingsRequest{FormatContractID: "", ConfigContractID: configContract, Settings: []byte(`{"PRIVATE_SETTING_KEY":true}`)}, ExpectedSettings: []byte(`{"section_prefix":"app"}`)}
		err := conformance.CheckSettingsImplementation(t.Context(), native.Serve, implementation, fixture)
		if !errors.Is(err, protocol.ErrWire) || !strings.Contains(err.Error(), "fixture.settings_request: invalid structure") || strings.Contains(err.Error(), "PRIVATE_SETTING_KEY") {
			t.Fatal("unsafe fixture diagnosis", err)
		}
	})
	for _, test := range []struct {
		name, input, expected string
		canonical             bool
		failure               manifest.Failure
	}{{"default", `{}`, `{"section_prefix":"enkv"}`, false, ""}, {"custom", `{ "section_prefix": "app" }`, `{"section_prefix":"app"}`, false, ""}, {"canonical", `{"section_prefix":"app"}`, `{"section_prefix":"app"}`, true, ""}, {"canonical-spelling", `{ "section_prefix": "app" }`, "", true, manifest.InvalidInput}, {"duplicate", `{"section_prefix":"a","section_prefix":"b"}`, "", false, manifest.InvalidInput}, {"invalid-prefix", `{"section_prefix":"x]bad"}`, "", false, manifest.InvalidInput}, {"null-prefix", `{"section_prefix":null}`, "", false, manifest.InvalidInput}, {"unknown-field", `{"other":1}`, "", false, manifest.InvalidInput}} {
		t.Run(test.name, func(t *testing.T) {
			fixture := conformance.SettingsFixture{Request: manifest.SettingsRequest{FormatContractID: formatContract, ConfigContractID: configContract, Canonical: test.canonical, Settings: []byte(test.input)}, ExpectedFailure: test.failure}
			if test.failure == "" {
				fixture.ExpectedSettings = []byte(test.expected)
			}
			if err := conformance.CheckSettingsImplementation(t.Context(), native.Serve, implementation, fixture); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestINIReferenceCompleteBytesAndConsumer(t *testing.T) {
	implementation, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	fixture := conformance.Fixture{Projection: mixedProjection(), ExpectedArtifact: expectedMixed()}
	if err := conformance.CheckImplementation(t.Context(), native.Serve, implementation, fixture); err != nil {
		t.Fatal(err)
	}
	if err := expectedConsumer(fixture.ExpectedArtifact); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestINIReferenceEmptyAndExcludedPartitions(t *testing.T) {
	implementation, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	// This header is a literal derivation of the fixed observation and empty
	// exact-name selection. The excluded case adds only its independently
	// specified name, incarnation and no-output reason.
	const header = `[app.manifest]
format="example/ini-reference/v1"
projection_schema="ENKV/CONSUMPTION-PROJECTION/v1"
config_contract="example/ini-reference-settings/v1"
settings_base64="eyJzZWN0aW9uX3ByZWZpeCI6ImFwcCJ9"
domain_id="0101010101010101010101010101010101010101010101010101010101010101"
head_revision_id="0202020202020202020202020202020202020202020202020202020202020202"
snapshot_id="0303030303030303030303030303030303030303030303030303030303030303"
target_recipient_id="0404040404040404040404040404040404040404040404040404040404040404"
target_mode="exact-recipient"
entry_mode="exact-names"
has_service_filter="false"
service_filter_base64=""
evidence_limit="authorized-input-and-exact-bytes"
included_count="0"
excluded_count="0"

`
	for _, excluded := range []bool{false, true} {
		name := "empty"
		if excluded {
			name = "all-excluded"
		}
		t.Run(name, func(t *testing.T) {
			projection := mixedProjection()
			projection.ServiceFilter = nil
			projection.Entries = []manifest.Entry{}
			projection.ExcludedEntries = []manifest.ExcludedEntry{}
			projection.ResolvedEntries = []manifest.EntryIdentity{}
			expected := header
			if excluded {
				projection.ExcludedEntries = []manifest.ExcludedEntry{{Name: "unused", EntryIncarnationID: id(9), Reason: manifest.NoOutput}}
				projection.ResolvedEntries = []manifest.EntryIdentity{{Name: "unused", EntryIncarnationID: id(9)}}
				expected = strings.Replace(header, `excluded_count="0"`, `excluded_count="1"`, 1) + `[app.excluded.0]
name_base64="dW51c2Vk"
incarnation_id="0909090909090909090909090909090909090909090909090909090909090909"
reason="no-output"

`
			}
			if err := conformance.CheckImplementation(t.Context(), native.Serve, implementation, conformance.Fixture{Projection: projection, ExpectedArtifact: []byte(expected)}); err != nil {
				t.Fatal(err)
			}
			document, err := consumer.Read(strings.NewReader(expected))
			if err != nil {
				t.Fatal(err)
			}
			values, err := document.PlainValues()
			if err != nil || len(values) != 0 {
				t.Fatal("empty partition invented plain values", err)
			}
			references, err := document.References()
			if err != nil || len(references) != 0 {
				t.Fatal("empty partition invented references", err)
			}
		})
	}
}

// full_only: false
func TestAuthorCallbacksReturnClosedFailures(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name, failure := "cancelled", manifest.Cancelled
		ctx, cancel := context.WithCancel(t.Context())
		if expired {
			cancel()
			name, failure = "expired", manifest.Expired
			ctx, cancel = context.WithDeadline(t.Context(), time.Unix(0, 0))
		}
		cancel()
		t.Run(name, func(t *testing.T) {
			input := []byte(`{"section_prefix":"app"}`)
			settings := validateSettings(ctx, manifest.SettingsRequest{FormatContractID: formatContract, ConfigContractID: configContract, Settings: input})
			if settings.Failure != failure || settings.Settings != nil || manifest.ValidateSettingsResult(settings) != "" || string(input) != `{"section_prefix":"app"}` {
				t.Fatal("settings callback changed cancellation or borrowed input", settings.Failure)
			}
			artifact := render(ctx, manifest.Borrow(mixedProjection()))
			if artifact.Failure != failure || artifact.Artifact != nil || manifest.ValidateResult(artifact) != "" {
				t.Fatal("renderer returned bytes after cancellation", artifact.Failure)
			}
		})
	}
	t.Run("settings-cancel-after-copy", func(t *testing.T) {
		ctx := &lateSettingsCancelContext{Context: t.Context()}
		input := []byte(`{"section_prefix":"app"}`)
		got := validateSettings(ctx, manifest.SettingsRequest{FormatContractID: formatContract, ConfigContractID: configContract, Settings: input})
		if got.Failure != manifest.Cancelled || got.Settings != nil || ctx.calls != 3 || string(input) != `{"section_prefix":"app"}` {
			t.Fatal("settings copy cancellation", got.Failure, ctx.calls)
		}
	})
	implementation, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	projection := mixedProjection()
	projection.FormatContractID = "other/format/v1"
	if err := conformance.CheckImplementation(t.Context(), native.Serve, implementation, conformance.Fixture{Projection: projection, ExpectedFailure: manifest.InvalidInput}); err != nil {
		t.Fatal("author format refusal did not complete its closed exchange", err)
	}
}

type lateSettingsCancelContext struct {
	context.Context
	calls int
}

func (c *lateSettingsCancelContext) Err() error {
	c.calls++
	if c.calls >= 3 {
		return context.Canceled
	}
	return c.Context.Err()
}

type exchangeBuffer struct {
	bytes.Buffer
	closed bool
}

func (b *exchangeBuffer) Close() error {
	if b.closed {
		return errors.New("duplicate close")
	}
	b.closed = true
	return nil
}

// full_only: false
func TestDefectivePlainEncodingFailsAuthorAndConsumerChecks(t *testing.T) {
	implementation, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	correct := implementation.Render
	implementation.Render = func(ctx context.Context, view manifest.View) manifest.Result {
		result := correct(ctx, view)
		if result.Failure != "" {
			return result
		}
		at := bytes.Index(result.Artifact, []byte(`value_base64="AP8K"`))
		if at < 0 {
			t.Fatal("defect target absent")
		}
		copy(result.Artifact[at:], []byte(`value_base64="AAEK"`))
		return result
	}
	if err := conformance.CheckImplementation(t.Context(), native.Serve, implementation, conformance.Fixture{Projection: mixedProjection(), ExpectedArtifact: expectedMixed()}); err == nil {
		t.Fatal("actual encoder defect passed author fixture")
	}
	var request bytes.Buffer
	correlation := id(11)
	if err := protocol.WriteRequest(t.Context(), &request, protocol.Request{Operation: protocol.OperationRender, Correlation: correlation, DescriptorID: implementation.Identity().DescriptorID, Projection: mixedProjection()}); err != nil {
		t.Fatal(err)
	}
	var artifact, status exchangeBuffer
	if code := native.Serve(t.Context(), bytes.NewReader(request.Bytes()), &artifact, &status, implementation); code != 0 {
		t.Fatal("common exchange failed", code)
	}
	wire, err := protocol.ReadStatus(bytes.NewReader(status.Bytes()))
	if err != nil || wire.Correlation != correlation || wire.Failure != "" || wire.Length != uint64(artifact.Len()) || !artifact.closed || !status.closed {
		t.Fatal("common byte contract", wire, err)
	}
	if err := expectedConsumer(artifact.Bytes()); err == nil {
		t.Fatal("consumer comparison missed wrong plain bytes")
	}
}

// full_only: false
func TestLargeOpaquePolicyRemainsConsumable(t *testing.T) {
	p := mixedProjection()
	p.Entries[1].Destinations[0].PolicyData = bytes.Repeat([]byte{0xfe}, 524546)
	result := render(t.Context(), manifest.Borrow(p))
	defer clear(result.Artifact[:cap(result.Artifact)])
	if manifest.ValidateResult(result) != "" || result.Failure != "" {
		t.Fatal(result.Failure)
	}
	document, err := consumer.Read(bytes.NewReader(result.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	encoded := document.Sections["app.entry.1.destination.0"]["policy_data_base64"]
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 524546 || !bytes.Equal(decoded, p.Entries[1].Destinations[0].PolicyData) {
		t.Fatal("large policy", len(decoded), err)
	}
	if err := expectedConsumer(result.Artifact); err != nil {
		t.Fatal(fmt.Errorf("consumer: %w", err))
	}
}

// full_only: false
func TestINIReferenceMaximumPlainValueCompleteBytes(t *testing.T) {
	p := mixedProjection()
	prefix := strings.Repeat("s", 32)
	p.Settings = []byte(`{"section_prefix":"` + prefix + `"}`)
	p.Entries[0].PlainValue = bytes.Repeat([]byte{255}, 65536)
	encoded, err := json.Marshal(settings{SectionPrefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	marshalCapacity := cap(encoded)
	canonical := validateSettings(t.Context(), manifest.SettingsRequest{FormatContractID: formatContract, ConfigContractID: configContract, Settings: p.Settings})
	if !bytes.Equal(encoded, p.Settings) || canonical.Failure != "" || !bytes.Equal(canonical.Settings, p.Settings) || len(canonical.Settings) != 53 || cap(canonical.Settings) != 53 {
		t.Fatal("maximum prefix canonical settings", canonical.Failure)
	}
	normalizationBacking := marshalCapacity + cap(canonical.Settings)
	clear(encoded[:cap(encoded)])
	clear(canonical.Settings[:cap(canonical.Settings)])
	const writerBytes = 49152 + 12290 + 88 + 6
	namedBuffers := manifest.MaxSettingsBytes + 53 + int(unsafe.Sizeof(jsonwriter.Writer{})) + manifest.MaxRawValue
	if unsafe.Sizeof(jsonwriter.Writer{}) != writerBytes || namedBuffers != 143509 || namedBuffers+len(prefix) != 143541 || normalizationBacking > 2*manifest.MaxSettingsBytes {
		t.Fatal("scoped author storage account", marshalCapacity, normalizationBacking, namedBuffers)
	}
	t.Logf("normalization_source_capacity=%d normalization_owned_capacity=53 normalization_named_backing=%d render_named_buffers=%d render_prefix_bytes=32 render_named_retained_data=%d; parser, scalar, closure and runtime allocations excluded", marshalCapacity, normalizationBacking, namedBuffers, namedBuffers+len(prefix))
	result := render(t.Context(), manifest.Borrow(p))
	defer clear(result.Artifact[:cap(result.Artifact)])
	// 65,535 ff bytes form 21,845 complete Base64 groups; one ff adds /w==.
	want := bytes.Replace(expectedMixed(), []byte(`value_base64="AP8K"`), []byte(`value_base64="`+strings.Repeat("/", 87381)+`w=="`), 1)
	want = bytes.ReplaceAll(want, []byte("[app."), []byte("["+prefix+"."))
	want = bytes.Replace(want, []byte(`settings_base64="eyJzZWN0aW9uX3ByZWZpeCI6ImFwcCJ9"`), []byte(`settings_base64="`+base64.StdEncoding.EncodeToString(p.Settings)+`"`), 1)
	if result.Failure != "" || len(result.Artifact) != cap(result.Artifact) || !bytes.Equal(result.Artifact, want) {
		t.Fatal("maximum plain artifact", result.Failure, len(result.Artifact))
	}
	document, err := consumer.Read(bytes.NewReader(result.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	values, err := document.PlainValues()
	if err != nil || len(values) != 1 || !bytes.Equal(values["greeting"], p.Entries[0].PlainValue) {
		t.Fatal("maximum plain consumer", err)
	}
}

// full_only: false
func TestINIReferenceValidatesWholeDestinationCounts(t *testing.T) {
	impl, err := implementation()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name                  string
		entries, destinations int
		want                  manifest.Failure
	}{
		{"entry-bound", 1, 8, ""}, {"entry-over", 1, 9, manifest.LimitExceeded},
		{"aggregate-bound", 128, 8, ""}, {"aggregate-over", 129, 8, manifest.LimitExceeded},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := mixedProjection()
			p.ServiceFilter = nil
			p.Entries, p.ResolvedEntries, p.ExcludedEntries = []manifest.Entry{}, []manifest.EntryIdentity{}, []manifest.ExcludedEntry{}
			for i := range row.entries {
				name, incarnation := fmt.Sprintf("entry%03d", i), manifest.ID{byte(i + 1), 1}
				e := manifest.Entry{Name: name, EntryIncarnationID: incarnation, Kind: manifest.Secret}
				for j := range row.destinations {
					e.Destinations = append(e.Destinations, manifest.Destination{DestinationID: fmt.Sprintf("slot%02d", j), ServiceContractID: "service", ConsumerLocator: "locator", TargetContractID: "target", CanonicalTarget: "target", BindingIncarnationID: id(1), EntryIncarnationID: incarnation, PayloadEncoding: manifest.EncodingRaw})
				}
				p.Entries = append(p.Entries, e)
				p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: name, EntryIncarnationID: incarnation})
			}
			result := impl.Render(t.Context(), manifest.Borrow(p))
			if result.Failure != row.want || row.want != "" && result.Artifact != nil {
				t.Fatal("INI destination limit changed", result.Failure)
			}
			if row.want == "" {
				if _, err := consumer.Read(bytes.NewReader(result.Artifact)); err != nil {
					t.Fatal("accepted INI was not consumable", err)
				}
			}
		})
	}
}
