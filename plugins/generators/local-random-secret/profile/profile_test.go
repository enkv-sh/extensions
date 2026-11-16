package profile

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestLocalProfileUsesIndependentConstructionVectors(t *testing.T) {
	intent, err := Normalize([]byte(`{ }`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.EncodeIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	// Independent Python hashlib/struct: SHA256 of the config label, followed by
	// u16 schema, config ID, lifecycle 1, zero resource ID and blob32("{}").
	const expected = "0001663075a79a657cf8e281991deb3cbfac760eff6445ead7af60005dd27d9e0caa010000000000000000000000000000000000000000000000000000000000000000000000027b7d"
	if hex.EncodeToString(body) != expected {
		t.Fatal("canonical intent differs from independent bytes")
	}
	digest, err := protocol.IntentDigest(body)
	if err != nil || hex.EncodeToString(digest[:]) != "7cff5c980fb5350508be5e93551a714ce72f1345328e2943cd2f94397321cc88" {
		t.Fatal("canonical intent digest differs", err)
	}
	for _, input := range []string{`null`, `[]`, `{"unexpected":1}`} {
		if _, err := Normalize([]byte(input)); err == nil {
			t.Fatal("nonempty local settings accepted", input)
		}
	}
	intent.Settings = []byte(`{ }`)
	if ValidateCanonical(intent) == nil {
		t.Fatal("canonical validation rewrote semantic bytes")
	}
}

// full_only: false
func TestLocalProfileRefusesChangedRequestBeforeExecution(t *testing.T) {
	intent, err := Normalize([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.EncodeIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := protocol.IntentDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	id := protocol.ID{1}
	command := protocol.Command{Schema: 1, DomainID: id, OperationID: id, RequestIdentityDigest: id, PlanGraphID: id, LineageID: id, AttemptID: id, TransmissionID: id, ResultID: id, ResultContractID: id, ExecutorID: id, DescriptorID: id, CredentialRouteID: id,
		Action: protocol.ActionCreate, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), RequestDigest: id, IntentDigest: digest, Intent: body, LifecycleMode: protocol.LifecycleNone}
	if err := ValidateCommand(command); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*protocol.Command){
		func(v *protocol.Command) { v.DescriptorID = protocol.ID{} }, func(v *protocol.Command) { v.RequestDigest = protocol.ID{} },
		func(v *protocol.Command) { v.IntentDigest[0] ^= 1 }, func(v *protocol.Command) { v.Intent = []byte{0, 2} },
		func(v *protocol.Command) { v.Action = protocol.ActionRetire }, func(v *protocol.Command) { v.ResultID = protocol.ID{} },
	} {
		changed := command
		changed.Intent = bytes.Clone(command.Intent)
		edit(&changed)
		if ValidateCommand(changed) == nil {
			t.Fatal("changed local request admitted")
		}
	}
}
