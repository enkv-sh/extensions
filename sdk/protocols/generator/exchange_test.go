package generator

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// full_only: false
func TestPassiveExchangesBindExactInput(t *testing.T) {
	request := NormalizeRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, ConfigContractID: repeatedID(1), Settings: []byte(`{"private_limit":7}`)}
	request.InputDigest, _ = NormalizeInputDigest(request)
	body, err := EncodeNormalizeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNormalizeRequest(body)
	if err != nil || !bytes.Equal(decoded.Settings, request.Settings) || cap(decoded.Settings) != len(decoded.Settings) {
		t.Fatal("normalization request failed", err)
	}
	intent, _ := EncodeIntent(testIntent(LifecycleManaged))
	response := NormalizeResponse{Schema: 1, InputDigest: request.InputDigest, Accepted: true, Intent: intent}
	encoded, err := EncodeNormalizeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNormalizeResponse(encoded)
	if err != nil || got.InputDigest != request.InputDigest {
		t.Fatal("normalization response failed", err)
	}
	body[len(body)-2] ^= 1
	if _, err := DecodeNormalizeRequest(body); err == nil {
		t.Fatal("changed captured input accepted")
	}
	response.Accepted = false
	if _, err := EncodeNormalizeResponse(response); err == nil {
		t.Fatal("refusal retained accepted facts")
	}
}

// full_only: false
func TestCompatibilityBindsOriginalResourceAndCompletion(t *testing.T) {
	command := testCommand(t, LifecycleManaged)
	facts := command.NewFacts(DispositionCompleteCreate, ReasonNone)
	facts.Target, facts.ResourceData = []byte("account"), []byte("resource")
	original, _ := EncodeSafeFacts(facts)
	request := RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, CompletionClass: CompletionAcknowledged, Intent: command.Intent, OriginalFacts: original}
	request.InputDigest, _ = RetirementCompatibilityInputDigest(request)
	body, err := EncodeRetirementCompatibilityRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRetirementCompatibilityRequest(body)
	if err != nil || got.InputDigest != request.InputDigest {
		t.Fatal("compatibility request failed", err)
	}
	body[len(body)-2] ^= 1
	if _, err := DecodeRetirementCompatibilityRequest(body); err == nil {
		t.Fatal("changed original facts accepted")
	}
}

// full_only: false
func TestCanonicalPurposeBindsExactIndependentRequest(t *testing.T) {
	// Independent intent: U16(1), R(1), none(1), R(0), B("{}"). The
	// SHA-256 literals use canonical-input-v2 followed by B(body), where
	// body is schema, deadline, purpose and B(intent); InputDigest is excluded.
	intent, err := hex.DecodeString("0001" + repeatHex("01", 32) + "01" + repeatHex("00", 32) + "000000027b7d")
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range []struct {
		purpose CanonicalPurpose
		digest  string
	}{
		{CanonicalHistorical, "608c0d8e7668219bdd1042f139962654e3d5e73796bf0e878c877002cd323cd8"},
		{CanonicalFreshCreate, "c6b057b4ff445c0494103ddbdaef250e678ab89835d6ef9953934dc194825e0e"},
	} {
		t.Run(fmt.Sprint(vector.purpose), func(t *testing.T) {
			digest, err := hex.DecodeString(vector.digest)
			if err != nil {
				t.Fatal(err)
			}
			request := CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Purpose: vector.purpose, Intent: intent}
			copy(request.InputDigest[:], digest)
			want := binary.BigEndian.AppendUint16(nil, 1)
			want = binary.BigEndian.AppendUint64(want, 4102444800000)
			want = append(want, byte(vector.purpose))
			want = append(want, digest...)
			want = binary.BigEndian.AppendUint32(want, 73)
			want = append(want, intent...)
			got, err := EncodeCanonicalRequest(request)
			if err != nil || len(got) != 120 || !bytes.Equal(got, want) {
				t.Fatal("canonical request differs from independent vector", len(got), err)
			}
			decoded, err := DecodeCanonicalRequest(want)
			if err != nil || decoded.Purpose != vector.purpose || decoded.InputDigest != request.InputDigest || !bytes.Equal(decoded.Intent, intent) || cap(decoded.Intent) != len(decoded.Intent) {
				t.Fatal("canonical independent request refused or borrowed excess bytes", err)
			}
			for _, change := range []string{"missing-purpose", "zero-purpose", "unknown-purpose", "other-purpose", "deadline", "digest", "intent", "trailing"} {
				bad := bytes.Clone(want)
				switch change {
				case "missing-purpose":
					bad = append(bad[:10], bad[11:]...)
				case "zero-purpose":
					bad[10] = 0
				case "unknown-purpose":
					bad[10] = 3
				case "other-purpose":
					bad[10] = 3 - bad[10]
				case "deadline":
					bad[9]++
				case "digest":
					bad[11] ^= 1
				case "intent":
					copy(bad[len(bad)-2:], []byte(`[]`))
				case "trailing":
					bad = append(bad, 0)
				}
				if _, err := DecodeCanonicalRequest(bad); err == nil {
					t.Fatal("changed canonical request accepted", change)
				}
			}
		})
	}
}

// full_only: false
func TestCanonicalRequestExactMaximumAndFirstExcess(t *testing.T) {
	intent := testIntent(LifecycleNone)
	intent.Settings = append([]byte{'"'}, bytes.Repeat([]byte{'x'}, MaximumIntentLength-73)...)
	intent.Settings = append(intent.Settings, '"')
	encoded, err := EncodeIntent(intent)
	if err != nil || len(encoded) != 393216 {
		t.Fatal("maximum intent fixture differs", len(encoded), err)
	}
	request := CanonicalRequest{Schema: 1, DeadlineUnixMillis: 4102444800000, Purpose: CanonicalFreshCreate, Intent: encoded}
	request.InputDigest, err = CanonicalInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeCanonicalRequest(request)
	if err != nil || len(body) != 393263 || len(body) >= MaximumPublicBody {
		t.Fatal("canonical maximum exceeds its independent 47-byte framing account", len(body), err)
	}
	if _, err := DecodeCanonicalRequest(body); err != nil {
		t.Fatal("canonical maximum refused", err)
	}
	// Increase both the intent blob length and its canonical settings length by
	// one. The shape remains well formed but exceeds the unchanged intent bound.
	body = append(body, 0)
	copy(body[len(body)-2:], []byte{'x', '"'})
	binary.BigEndian.PutUint32(body[43:47], 393217)
	binary.BigEndian.PutUint32(body[47+67:47+71], uint32(len(intent.Settings)+1))
	if _, err := DecodeCanonicalRequest(body); !errors.Is(err, ErrCapacity) {
		t.Fatal("canonical first excess not refused by capacity", err)
	}
}
