package output

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// full_only: false
func TestWireRejectsVersionKindIdentityAndTruncation(t *testing.T) {
	frame := Frame{Kind: KindCommand, CorrelationID: testID(3), Body: []byte("safe")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatal(err)
	}
	original := buf.Bytes()
	got, err := ReadFrame(bytes.NewReader(original), MaximumCommandBytes)
	if err != nil || got.Kind != frame.Kind || got.CorrelationID != frame.CorrelationID || !bytes.Equal(got.Body, frame.Body) {
		t.Fatalf("frame=%#v err=%v", got, err)
	}
	for name, change := range map[string]func([]byte){
		"magic":         func(b []byte) { b[0] ^= 1 },
		"version":       func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 1) },
		"old wire":      func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 2) },
		"previous wire": func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 5) },
		"kind":          func(b []byte) { b[6] = 99 },
		"identity":      func(b []byte) { clear(b[7:39]) },
		"length":        func(b []byte) { binary.BigEndian.PutUint32(b[39:43], 999) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(original)
			change(bad)
			if _, err := ReadFrame(bytes.NewReader(bad), 100); err == nil {
				t.Fatal("bad frame accepted")
			}
		})
	}
	if _, err := ReadFrame(bytes.NewReader(original[:len(original)-1]), MaximumCommandBytes); err == nil {
		t.Fatal("truncated frame accepted")
	}
	if _, err := ReadExpectedFrame(bytes.NewReader(original), KindResult, frame.CorrelationID, MaximumCommandBytes); !errors.Is(err, ErrProtocol) {
		t.Fatalf("kind err=%v", err)
	}
	if err := RequireEOF(bytes.NewReader([]byte{0})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("trailing byte err=%v", err)
	}
	for _, kind := range []uint8{KindReadyForPayload, KindPreparationRefused, KindArm} {
		if err := WriteFrame(new(bytes.Buffer), Frame{Kind: kind, CorrelationID: frame.CorrelationID, Body: []byte{1}}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("nonempty zero-body kind %d written: %v", kind, err)
		}
		var valid bytes.Buffer
		if err := WriteFrame(&valid, Frame{Kind: kind, CorrelationID: frame.CorrelationID}); err != nil {
			t.Fatal(err)
		}
		bad := append(bytes.Clone(valid.Bytes()), 1)
		binary.BigEndian.PutUint32(bad[39:43], 1)
		if _, err := ReadFrame(bytes.NewReader(bad), 1); !errors.Is(err, ErrProtocol) {
			t.Fatalf("nonempty zero-body kind %d read: %v", kind, err)
		}
	}
}

// full_only: false
func TestWireV6ArmAndVersion(t *testing.T) {
	// Independent vector: Python hashlib.sha256 over ASCII
	// "ENKV/OUTPUT-WIRE/v6" followed by one NUL byte.
	want, err := hex.DecodeString("c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	if err != nil {
		t.Fatal(err)
	}
	identity := ProtocolID()
	if !bytes.Equal(identity[:], want) {
		t.Fatalf("output protocol identity=%x want=%x", identity, want)
	}
	hello, err := EncodeHello(Hello{ProtocolID: identity, DescriptorID: testID(8), ArtifactContractID: testID(9)})
	if err != nil || len(hello) != 96 || !bytes.Equal(hello[:32], want) {
		t.Fatalf("encoded Hello identity differs: body=%x err=%v", hello, err)
	}
	id := testID(7)
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, Frame{Kind: KindArm, CorrelationID: id}); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(encoded.Bytes()[4:6]); got != 6 {
		t.Fatalf("wire version=%d", got)
	}
	if body, err := ReadExpectedFrame(&encoded, KindArm, id, 0); err != nil || len(body) != 0 {
		t.Fatalf("arm body=%x err=%v", body, err)
	}
}

// full_only: false
func TestWireV6OneValuePayloadCeiling(t *testing.T) {
	id := testID(7)
	var frame bytes.Buffer
	if err := WriteFrame(&frame, Frame{Kind: KindPayload, CorrelationID: id,
		Body: make([]byte, MaximumPayloadBytes)}); err != nil {
		t.Fatal(err)
	}
	if body, err := ReadExpectedFrame(&frame, KindPayload, id, MaximumPayloadBytes); err != nil || len(body) != MaximumPayloadBytes {
		t.Fatalf("maximum payload=%d err=%v", len(body), err)
	}
	frame.Reset()
	if err := WriteFrame(&frame, Frame{Kind: KindPayload, CorrelationID: id,
		Body: make([]byte, MaximumPayloadBytes+1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExpectedFrame(&frame, KindPayload, id, MaximumPayloadBytes); !errors.Is(err, ErrCapacity) {
		t.Fatalf("payload maximum+1 err=%v", err)
	}
}
