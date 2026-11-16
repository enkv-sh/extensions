package credentialroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sampleRoute() Route {
	return Route{Schema: Schema, ContractID: [32]byte{1}, Mode: ModeEnvironment, Names: []string{"A"}, PublicData: []byte{0x7f}}
}

// full_only: false
func TestRouteExactEncodingAndIdentity(t *testing.T) {
	// Fixed fields: 0001, 32-byte contract, mode1, count1, name1/A,
	// data length1 and byte7f. This literal does not use the encoder.
	want, err := hex.DecodeString("000101" + strings.Repeat("00", 31) + "01010141000000017f")
	if err != nil {
		t.Fatal(err)
	}
	body, err := Encode(sampleRoute())
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("route encoding differs", err)
	}
	decoded, err := Decode(want)
	if err != nil || decoded.Schema != Schema || decoded.ContractID != [32]byte{1} || decoded.Mode != ModeEnvironment || len(decoded.Names) != 1 || decoded.Names[0] != "A" || !bytes.Equal(decoded.PublicData, []byte{0x7f}) {
		t.Fatal("route decoding differs", decoded, err)
	}
	preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00\x00\x00\x00\x2b"), want...)
	wantID := sha256.Sum256(preimage)
	gotID, err := Identity(sampleRoute())
	if err != nil || gotID != wantID {
		t.Fatal("route identity differs", err)
	}
	body[len(body)-1] = 0
	if decoded.PublicData[0] != 0x7f {
		t.Fatal("decoded public data borrowed another buffer")
	}
}

// full_only: false
func TestRouteBoundsAndMalformedRecords(t *testing.T) {
	max := sampleRoute()
	max.PublicData = bytes.Repeat([]byte{1}, MaxRouteBytes-42)
	body, err := Encode(max)
	if err != nil || len(body) != MaxRouteBytes {
		t.Fatal("maximum complete route refused", len(body), err)
	}
	max.PublicData = append(max.PublicData, 1)
	if _, err := Encode(max); err == nil {
		t.Fatal("route aggregate overflow accepted")
	}
	for _, names := range [][]string{{"0A"}, {"A-B"}, {"A", "A"}, {"B", "A"}, {strings.Repeat("A", MaxNameBytes+1)}, {"A\x00"}} {
		v := sampleRoute()
		v.Names = names
		if _, err := Encode(v); err == nil {
			t.Fatal("invalid environment names accepted", names)
		}
	}
	valid, _ := Encode(sampleRoute())
	for i := range valid {
		if _, err := Decode(valid[:i]); err == nil {
			t.Fatal("truncated route accepted", i)
		}
	}
	if _, err := Decode(append(valid, 0)); err == nil {
		t.Fatal("trailing route bytes accepted")
	}
}

// full_only: false
func TestPrivateInputsDistinguishPresenceAndBorrowOwnedBody(t *testing.T) {
	route := Route{Schema: Schema, ContractID: [32]byte{1}, Mode: ModeSDK, Names: []string{"A", "B", "C"}}
	want, _ := hex.DecodeString("0001030141000000000001420100000000014301000000027879")
	body, err := EncodeInputs(route, []Input{{Name: "A"}, {Name: "B", Present: true}, {Name: "C", Present: true, Value: []byte("xy")}})
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("private input encoding differs", err)
	}
	inputs, err := DecodeInputs(route, body)
	if err != nil || len(inputs) != 3 || inputs[0].Present || !inputs[1].Present || len(inputs[1].Value) != 0 || !inputs[2].Present || string(inputs[2].Value) != "xy" {
		t.Fatal("private presence differs", err)
	}
	clear(body)
	if !bytes.Equal(inputs[2].Value, []byte{0, 0}) {
		t.Fatal("private value copied without ownership")
	}
}

// full_only: false
func TestPrivateInputsCompleteBoundAndRefusals(t *testing.T) {
	route := sampleRoute()
	max := []Input{{Name: "A", Present: true, Value: bytes.Repeat([]byte{'x'}, MaxInputsBytes-10)}}
	body, err := EncodeInputs(route, max)
	if err != nil || len(body) != MaxInputsBytes {
		t.Fatal("maximum private inputs refused", len(body), err)
	}
	max[0].Value = append(max[0].Value, 'x')
	if _, err := EncodeInputs(route, max); err == nil {
		t.Fatal("private aggregate overflow accepted")
	}
	for _, inputs := range [][]Input{nil, {{Name: "B", Present: true}}, {{Name: "A", Value: []byte("x")}}, {{Name: "A", Present: true, Value: []byte{'x', 0}}}} {
		if _, err := EncodeInputs(route, inputs); err == nil {
			t.Fatal("invalid private inputs accepted")
		}
	}
	valid, _ := EncodeInputs(route, []Input{{Name: "A", Present: true, Value: []byte("x")}})
	for i := range valid {
		if _, err := DecodeInputs(route, valid[:i]); err == nil {
			t.Fatal("truncated inputs accepted", i)
		}
	}
	if _, err := DecodeInputs(route, append(valid, 0)); err == nil {
		t.Fatal("trailing private inputs accepted")
	}
}

// full_only: false
func TestRouteIdentitySeparatesDiscoveryRulesFromPrivateValues(t *testing.T) {
	route := sampleRoute()
	first, err := Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"old-token", "rotated-token"} {
		body, err := EncodeInputs(route, []Input{{Name: "A", Present: true, Value: []byte(value)}})
		if err != nil {
			t.Fatal(err)
		}
		clear(body)
		id, err := Identity(route)
		if err != nil || id != first || route.ContractID != ([32]byte{1}) {
			t.Fatal("private rotation changed public route", err)
		}
	}
	renamed := route
	renamed.Names = []string{"B"}
	other, err := Identity(renamed)
	if err != nil || other == first || renamed.ContractID != route.ContractID {
		t.Fatal("public rename lost exact route distinction", err)
	}
	reinterpreted := route
	reinterpreted.ContractID = [32]byte{2}
	other, err = Identity(reinterpreted)
	if err != nil || other == first {
		t.Fatal("changed discovery rules lost their identity", err)
	}
}
