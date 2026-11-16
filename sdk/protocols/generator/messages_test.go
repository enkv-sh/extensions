package generator

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testIntent(mode uint8) Intent {
	v := Intent{Schema: 1, ConfigContractID: repeatedID(1), LifecycleMode: mode, Settings: []byte(`{}`)}
	if mode == LifecycleManaged {
		v.ResourceContractID = repeatedID(2)
	}
	return v
}

// full_only: false
func TestCommandValidationReportsSafeStructuralConditions(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		change      func(*Command)
	}{
		{"schema", "schema", func(v *Command) { v.Schema = 0 }},
		{"action", "action", func(v *Command) { v.Action = 255 }},
		{"deadline", "deadline_unix_millis", func(v *Command) { v.DeadlineUnixMillis = 0 }},
		{"identity", "domain_id", func(v *Command) { v.DomainID = ID{} }},
		{"intent", "intent", func(v *Command) { v.Intent = []byte("private-supplied-settings") }},
		{"lifecycle", "lifecycle_mode", func(v *Command) { v.LifecycleMode = LifecycleNone }},
		{"resource", "resource_contract_id", func(v *Command) { v.ResourceContractID = ID{} }},
		{"digest", "intent_digest", func(v *Command) { v.IntentDigest = repeatedID(99) }},
		{"original", "original_facts", func(v *Command) { v.OriginalFacts = []byte("private-supplied-facts") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := testCommand(t, LifecycleManaged)
			tc.change(&command)
			err := ValidateCommand(command)
			_, encodeErr := EncodeCommand(command)
			if encodeErr == nil || err == nil || encodeErr.Error() != err.Error() {
				t.Fatal("codec did not use structural validation", encodeErr, err)
			}
			if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), tc.field) || strings.Contains(err.Error(), "private-supplied") {
				t.Fatal("command refusal lost safe structural diagnosis", err)
			}
		})
	}
}

func testCommand(t *testing.T, mode uint8) Command {
	t.Helper()
	intent, err := EncodeIntent(testIntent(mode))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := IntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	return Command{Schema: 1, Action: ActionCreate, DeadlineUnixMillis: 4102444800000,
		DomainID: repeatedID(3), OperationID: repeatedID(4), RequestIdentityDigest: repeatedID(5), PlanGraphID: repeatedID(6),
		LineageID: repeatedID(7), AttemptID: repeatedID(8), TransmissionID: repeatedID(9), ResultID: repeatedID(10),
		ResultContractID: repeatedID(11), DescriptorID: repeatedID(15), ExecutorID: repeatedID(12), RequestDigest: repeatedID(13),
		IntentDigest: digest, ResourceContractID: testIntent(mode).ResourceContractID, CredentialRouteID: repeatedID(14),
		LifecycleMode: mode, Intent: intent}
}

// full_only: false
func TestIntentIndependentEncodingAndBounds(t *testing.T) {
	// U16(1), R(1), managed(2), R(2), B("{}"). No production codec derives this vector.
	literal := "0001" + repeatHex("01", 32) + "02" + repeatHex("02", 32) + "000000027b7d"
	want, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeIntent(testIntent(LifecycleManaged))
	if err != nil || !bytes.Equal(got, want) || len(got) != 73 {
		t.Fatal("independent intent differs", err)
	}
	decoded, err := DecodeIntent(want)
	if err != nil || decoded.ConfigContractID != repeatedID(1) || !bytes.Equal(decoded.Settings, []byte(`{}`)) || cap(decoded.Settings) != len(decoded.Settings) {
		t.Fatal("intent borrowing differs", err)
	}
	max := testIntent(LifecycleNone)
	max.Settings = append([]byte{'"'}, bytes.Repeat([]byte{'x'}, MaximumIntentLength-73)...)
	max.Settings = append(max.Settings, '"')
	if body, err := EncodeIntent(max); err != nil || len(body) != MaximumIntentLength {
		t.Fatal("maximum intent refused", len(body), err)
	}
	max.Settings = append(max.Settings[:len(max.Settings)-1], 'x', '"')
	if _, err := EncodeIntent(max); !errors.Is(err, ErrCapacity) {
		t.Fatal("intent excess admitted", err)
	}
	bad := testIntent(LifecycleNone)
	bad.ResourceContractID = repeatedID(2)
	if _, err := EncodeIntent(bad); err == nil {
		t.Fatal("unmanaged resource contract admitted")
	}
}

// full_only: false
func TestCommandAndResultBindOpenResourceFacts(t *testing.T) {
	command := testCommand(t, LifecycleManaged)
	body, err := EncodeCommand(command)
	if err != nil || len(body) != 500+len(command.Intent) {
		t.Fatal("command framing differs", len(body), err)
	}
	got, err := DecodeCommand(body)
	if err != nil || got.DescriptorID != command.DescriptorID || cap(got.Intent) != len(got.Intent) {
		t.Fatal("command decode failed", err)
	}
	facts := command.NewFacts(DispositionCompleteCreate, ReasonNone)
	facts.Target, facts.ResourceData = []byte("private-service/account"), []byte("handle-A")
	result := command.NewResult(facts, []byte{0, 255, 1, 7, 0})
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal("arbitrary bytes refused", err)
	}
	decoded, err := DecodeResult(encoded)
	if err != nil || ValidateResult(command, decoded) != nil || !bytes.Equal(decoded.Value, []byte{0, 255, 1, 7, 0}) {
		t.Fatal("open result failed", err)
	}
	decoded.SafeFacts.RequestDigest[0] ^= 1
	if ValidateResult(command, decoded) == nil {
		t.Fatal("foreign request facts admitted")
	}
	if _, err := DecodeCommand(append(body, 0)); err == nil {
		t.Fatal("trailing command accepted")
	}
	clear(body[3:11])
	if _, err := DecodeCommand(body); err == nil {
		t.Fatal("damaged deadline accepted")
	}
}

// full_only: false
func TestFactsAndValueAggregateMaxima(t *testing.T) {
	command := testCommand(t, LifecycleManaged)
	facts := command.NewFacts(DispositionCompleteCreate, ReasonNone)
	facts.Target, facts.ResourceData = []byte{1}, []byte{2}
	facts.ProviderFacts = bytes.Repeat([]byte{3}, MaximumSafeFactsBody-117)
	body, err := EncodeSafeFacts(facts)
	if err != nil || len(body) != 4096 {
		t.Fatal("facts aggregate maximum refused", len(body), err)
	}
	for _, tc := range []struct {
		name   string
		value  []byte
		length int
	}{
		{"raw", bytes.Repeat([]byte{'d'}, 65536), 69770},
		// Independent padded standard Base64 for 65,536 decoded d bytes.
		{"base64", []byte(strings.Repeat("ZGRk", 21845) + "ZA=="), 91618},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := command.NewResult(facts, tc.value)
			encoded, err := EncodeResult(result)
			if err != nil || len(encoded) != tc.length {
				t.Fatal("complete result framing differs", len(encoded), err)
			}
			decoded, decodeErr := DecodeResult(encoded)
			if decodeErr != nil || !reflect.DeepEqual(decoded, result) || ValidateResult(command, decoded) != nil {
				t.Error("valid maximum result refused or changed by decoder", decodeErr)
			}
			var framed bytes.Buffer
			if err := WriteFrame(&framed, Frame{Kind: KindResult, CommandID: command.AttemptID, Body: encoded}); err != nil {
				t.Fatal("maximum result frame refused by writer", err)
			}
			reader := bytes.NewReader(framed.Bytes())
			owned, err := ReadExpectedFrame(reader, KindResult, command.AttemptID, MaximumResultBody)
			if err != nil {
				t.Fatal("valid maximum result refused by frame reader", err)
			}
			defer clear(owned)
			if RequireEOF(reader) != nil || len(owned) != tc.length || !bytes.Equal(owned, encoded) {
				t.Fatal("frame reader changed or incompletely consumed result")
			}
			borrowed, err := DecodeResult(owned)
			if err != nil || !reflect.DeepEqual(borrowed, result) || cap(borrowed.Value) != len(tc.value) || cap(borrowed.SafeFacts.ProviderFacts) != len(facts.ProviderFacts) {
				t.Fatal("framed maximum result lost exact bounded borrows", err)
			}
			clear(owned)
			if !bytes.Equal(borrowed.Value, make([]byte, len(tc.value))) || !bytes.Equal(borrowed.SafeFacts.ProviderFacts, make([]byte, len(facts.ProviderFacts))) || !bytes.Equal(encoded[len(encoded)-len(tc.value):], tc.value) {
				t.Fatal("decoded result does not borrow only its owned frame body")
			}
		})
	}
	facts.ProviderFacts = append(facts.ProviderFacts, 3)
	if _, err := EncodeSafeFacts(facts); !errors.Is(err, ErrCapacity) {
		t.Fatal("facts aggregate excess admitted", err)
	}
	facts.ProviderFacts = nil
	excess := bytes.Repeat([]byte{'A'}, 87385)
	result := command.NewResult(facts, excess)
	if _, err := EncodeResult(result); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained value excess admitted by encoder", err)
	}
	// Assemble only the damaged outer result framing. Its smaller facts keep
	// the body below 91,618, so the decoder must enforce the value's own bound.
	shortFacts, err := EncodeSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	bad := binary.BigEndian.AppendUint16(nil, Schema)
	for _, id := range [...]ID{result.AttemptID, result.ResultID, result.ResultContractID, result.ExecutorID} {
		bad = append(bad, id[:]...)
	}
	bad = binary.BigEndian.AppendUint32(bad, uint32(len(shortFacts)))
	bad = append(bad, shortFacts...)
	bad = binary.BigEndian.AppendUint32(bad, uint32(len(excess)))
	bad = append(bad, excess...)
	if len(bad) >= 91618 {
		t.Fatal("value-bound damage does not isolate the retained value")
	}
	if _, err := DecodeResult(bad); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained value excess admitted by decoder", err)
	}
	carrier := make([]byte, 91619)
	if _, err := DecodeResult(carrier); !errors.Is(err, ErrCapacity) {
		t.Fatal("complete carrier excess admitted by decoder", err)
	}
	var framed bytes.Buffer
	if err := WriteFrame(&framed, Frame{Kind: KindResult, CommandID: command.AttemptID, Body: carrier}); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(framed.Bytes())
	if _, err := ReadExpectedFrame(reader, KindResult, command.AttemptID, MaximumResultBody); !errors.Is(err, ErrCapacity) || reader.Len() != len(carrier) {
		t.Fatal("complete carrier excess was not refused before reading body", err)
	}
	body[len(body)-1] = 1
	if _, err := DecodeSafeFacts(body); err == nil {
		t.Fatal("native scoped observation admitted")
	}
}

// full_only: false
func TestRetirementAndNoEffectRemainDifferent(t *testing.T) {
	created := testCommand(t, LifecycleManaged)
	facts := created.NewFacts(DispositionCompleteCreate, ReasonNone)
	facts.Target, facts.ResourceData = []byte("target"), []byte("handle")
	original, err := EncodeSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	retire := created
	retire.Action, retire.OriginalFacts, retire.RequestDigest = ActionRetire, original, repeatedID(90)
	// A compatible selected implementation can have a different descriptor.
	retire.DescriptorID = repeatedID(91)
	if _, err := EncodeCommand(retire); err != nil {
		t.Fatal("new executor contract refused", err)
	}
	ack := retire.NewFacts(DispositionRetirementAcknowledged, ReasonNone)
	ack.Target, ack.ResourceData = bytes.Clone(facts.Target), bytes.Clone(facts.ResourceData)
	if err := ValidateResult(retire, retire.NewResult(ack, nil)); err != nil {
		t.Fatal("retirement ack refused", err)
	}
	ack.Disposition = DispositionConfirmedNoEffect
	if err := ValidateResult(retire, retire.NewResult(ack, nil)); err == nil {
		t.Fatal("no-effect became retirement acknowledgement")
	}
	ack.Disposition = DispositionRetirementAcknowledged
	ack.ResourceData = []byte("other")
	if err := ValidateResult(retire, retire.NewResult(ack, nil)); err == nil {
		t.Fatal("foreign resource ack accepted")
	}
}

func repeatHex(s string, n int) string {
	var b bytes.Buffer
	for range n {
		b.WriteString(s)
	}
	return b.String()
}

// full_only: false
func TestCommandAcceptsCompleteMaximumAndRefusesFirstExcess(t *testing.T) {
	intent := testIntent(LifecycleManaged)
	intent.Settings = append([]byte{'"'}, bytes.Repeat([]byte{'x'}, MaximumSettingsLength-2)...)
	intent.Settings = append(intent.Settings, '"')
	command := testCommand(t, LifecycleManaged)
	command.Intent, _ = EncodeIntent(intent)
	command.IntentDigest, _ = IntentDigest(command.Intent)
	original := command.NewFacts(DispositionOwnedUnusableCreate, ReasonMissingValue)
	original.Target, original.ResourceData = []byte{1}, []byte{2}
	original.ProviderFacts = bytes.Repeat([]byte{3}, MaximumSafeFactsBody-117)
	command.Action = ActionRetire
	command.OriginalFacts, _ = EncodeSafeFacts(original)
	body, err := EncodeCommand(command)
	if err != nil || len(body) != 397812 {
		t.Fatal("complete command maximum differs", len(body), err)
	}
	if _, err := DecodeCommand(body); err != nil {
		t.Fatal("maximum command decode failed", err)
	}
	ack := command.NewFacts(DispositionRetirementAcknowledged, ReasonNone)
	ack.Target, ack.ResourceData = bytes.Clone(original.Target), bytes.Clone(original.ResourceData)
	result := command.NewResult(ack, nil)
	if err := ValidateResult(command, result); err != nil {
		t.Fatal("maximum command result refused", err)
	}
	for _, tc := range []struct {
		name, field string
		change      func(*Command)
	}{
		{"intent_oversize_result_command", "intent", func(v *Command) { v.Intent = append(bytes.Clone(v.Intent), 0) }},
		{"original_facts_oversize_result_command", "original_facts", func(v *Command) { v.OriginalFacts = append(bytes.Clone(v.OriginalFacts), 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := command
			tc.change(&changed)
			err := ValidateResult(changed, result)
			if !errors.Is(err, ErrProtocol) || !errors.Is(err, ErrCapacity) || !strings.Contains(err.Error(), tc.field) {
				t.Fatal("invalid result command lost protocol category or capacity cause", err)
			}
		})
	}
	command.OriginalFacts = append(command.OriginalFacts, 0)
	if _, err := EncodeCommand(command); !errors.Is(err, ErrCapacity) {
		t.Fatal("first command excess admitted", err)
	}
}
