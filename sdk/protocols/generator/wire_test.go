package generator

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func repeatedID(v byte) ID {
	var id ID
	for i := range id {
		id[i] = v
	}
	return id
}

// full_only: false
func TestHelloIndependentFrameVector(t *testing.T) {
	want, err := hex.DecodeString("454e4b47000501040404040404040404040404040404040404040404040404040404040404040400000060010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303")
	if err != nil || len(want) != 139 {
		t.Fatal("independent vector invalid", err)
	}
	body, err := EncodeHello(Hello{ProtocolID: repeatedID(1), DescriptorID: repeatedID(2), ArtifactContractID: repeatedID(3)})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := WriteFrame(&got, Frame{Kind: KindHello, CommandID: repeatedID(4), Body: body}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("hello frame differs from independent vector")
	}
	frame, err := ReadFrame(bytes.NewReader(want), HelloBodyLength)
	if err != nil || frame.Kind != KindHello || frame.CommandID != repeatedID(4) || !bytes.Equal(frame.Body, body) {
		t.Fatal("hello frame did not round-trip", err)
	}
}

// full_only: false
func TestFrameRejectsBoundsKindsVersionsAndDamage(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 32)
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, Frame{Kind: KindCommand, CommandID: repeatedID(1), Body: body}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"magic":       func(b []byte) []byte { b[0] ^= 1; return b },
		"version":     func(b []byte) []byte { b[5]++; return b },
		"old-version": func(b []byte) []byte { b[5] = 4; return b },
		"kind":        func(b []byte) []byte { b[6] = 255; return b },
		"command":     func(b []byte) []byte { clear(b[7:39]); return b },
		"truncated":   func(b []byte) []byte { return b[:len(b)-1] },
		"overlength":  func(b []byte) []byte { b[42]++; return b },
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(bytes.Clone(encoded.Bytes()))
			if _, err := ReadFrame(bytes.NewReader(bad), 32); err == nil {
				t.Fatal("damaged frame passed")
			}
		})
	}
	if _, err := ReadFrame(bytes.NewReader(encoded.Bytes()), 31); !errors.Is(err, ErrCapacity) {
		t.Fatal("body ceiling did not refuse before allocation", err)
	}
	if err := RequireEOF(bytes.NewReader([]byte{1})); !errors.Is(err, ErrProtocol) {
		t.Fatal("trailing byte passed", err)
	}
	if err := RequireEOF(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), 0); !errors.Is(err, io.EOF) {
		t.Fatal("empty input did not report EOF", err)
	}
	for _, length := range []int{1, HeaderLength - 1, HeaderLength, HeaderLength + 1} {
		if _, err := ReadFrame(bytes.NewReader(encoded.Bytes()[:length]), 32); err != io.ErrUnexpectedEOF {
			t.Fatalf("nonempty truncated frame reported absence: length=%d error=%v", length, err)
		}
	}
}

// full_only: false
func TestRejectedFrameBodiesAreCleared(t *testing.T) {
	command := repeatedID(1)
	body := bytes.Repeat([]byte{0xa5}, 32)
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, Frame{Kind: KindResult, CommandID: command, Body: body}); err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"wrong kind": bytes.Clone(encoded.Bytes()),
		"truncated":  bytes.Clone(encoded.Bytes()[:encoded.Len()-1]),
	} {
		t.Run(name, func(t *testing.T) {
			reader := &capturingReader{Reader: bytes.NewReader(input)}
			if name == "wrong kind" {
				if _, err := ReadExpectedFrame(reader, KindStatus, command, MaximumResultBody); err != ErrProtocol {
					t.Fatal("wrong-kind frame accepted", err)
				}
			} else if _, err := ReadFrame(reader, MaximumResultBody); err == nil {
				t.Fatal("truncated frame accepted")
			}
			if !bytes.Equal(reader.body, make([]byte, len(reader.body))) {
				t.Fatal("rejected frame body was not cleared")
			}
		})
	}
}

type capturingReader struct {
	io.Reader
	body  []byte
	reads int
}

func (r *capturingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.reads > 0 {
		r.body = p
	}
	r.reads++
	return n, err
}
