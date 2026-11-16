package localrandom

import (
	"bytes"
	"context"
	"encoding/base64"
	"enkv.sh/plugins/generators/local-random-secret/profile"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	"enkv.sh/sdk/generator/conformance"
	protocol "enkv.sh/sdk/protocols/generator"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func localCommand() protocol.Command {
	id := protocol.ID{1}
	intent, _ := profile.Normalize([]byte(`{}`))
	body, _ := protocol.EncodeIntent(intent)
	digest, _ := protocol.IntentDigest(body)
	return protocol.Command{Schema: 1, DomainID: id, OperationID: id, RequestIdentityDigest: id, PlanGraphID: id, LineageID: id, AttemptID: id, TransmissionID: id, ResultID: id, ResultContractID: id, ExecutorID: id, DescriptorID: id, CredentialRouteID: id, LifecycleMode: protocol.LifecycleNone,
		Action: protocol.ActionCreate, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), RequestDigest: id, IntentDigest: digest, Intent: body}
}

// full_only: false
func TestExecuteProducesCanonicalLocalSecret(t *testing.T) {
	command := localCommand()
	facts, value, err := Execute(t.Context(), generator.Invocation{Command: command})
	defer clear(value[:cap(value)])
	if err != nil || facts.Disposition != protocol.DispositionCompleteCreate || facts.RequestDigest != command.RequestDigest || facts.IntentDigest != command.IntentDigest || len(value) != 43 {
		t.Fatal("local entropy result refused or changed", err)
	}
	var entropy [32]byte
	n, err := base64.RawURLEncoding.Strict().Decode(entropy[:], value)
	defer clear(entropy[:])
	var encoded [43]byte
	defer clear(encoded[:])
	base64.RawURLEncoding.Encode(encoded[:], entropy[:])
	if err != nil || n != 32 || !bytes.Equal(encoded[:], value) {
		t.Fatal("local entropy encoding is not canonical")
	}
}

// full_only: false
func TestExecuteRefusesWrongFamilyCredentialAndCancellation(t *testing.T) {
	for _, tc := range []string{"wrong family", "credential", "profile", "intent", "cancelled"} {
		t.Run(tc, func(t *testing.T) {
			command := localCommand()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var inputs []credentialroute.Input
			switch tc {
			case "wrong family":
				command.LifecycleMode = protocol.LifecycleManaged
			case "credential":
				inputs = []credentialroute.Input{{Name: "UNWANTED"}}
			case "profile":
				command.DescriptorID = protocol.ID{}
			case "intent":
				command.Intent = []byte{0, 2}
			case "cancelled":
				cancel()
			}
			facts, value, err := Execute(ctx, generator.Invocation{Command: command, Inputs: inputs})
			defer clear(value[:cap(value)])
			if err == nil || facts.Schema != 0 || len(value) != 0 {
				t.Fatal("invalid local invocation returned an owned value")
			}
		})
	}
}

// full_only: false
func TestImplementationPreservesDescriptorDiagnosis(t *testing.T) {
	_, err := NewImplementation([]byte(`{"SCHEMA":"private-supplied-value"}`))
	if !errors.Is(err, protocol.ErrProtocol) || !errors.Is(err, artifact.ErrRecord) || !strings.Contains(err.Error(), "record.schema") || strings.Contains(err.Error(), "private-supplied-value") || strings.Contains(err.Error(), "SCHEMA") {
		t.Fatal("constructor lost safe descriptor diagnosis", err)
	}
}

// full_only: false
func TestAuthorConformanceChecksIndependentRandomValue(t *testing.T) {
	descriptor, err := os.ReadFile("cmd/enkv-generator-local-random-secret/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid-output"}[invalid], func(t *testing.T) {
			impl, err := NewImplementation(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			intent := protocol.Intent{Schema: 1, ConfigContractID: profile.ConfigContractID(), LifecycleMode: protocol.LifecycleNone, Settings: []byte(`{}`)}
			var capture []byte
			fixture, err := conformance.NewFixture(impl, conformance.Request{Action: protocol.ActionCreate, Intent: intent}, conformance.Expectation{Disposition: protocol.DispositionCompleteCreate, CheckValue: func(value []byte) error {
				capture = value
				if len(value) != 43 {
					return errors.New("invalid independent length")
				}
				var raw [32]byte
				defer clear(raw[:])
				n, err := base64.RawURLEncoding.Strict().Decode(raw[:], value)
				if err != nil || n != 32 {
					return errors.New("invalid independent encoding")
				}
				var encoded [43]byte
				defer clear(encoded[:])
				base64.RawURLEncoding.Encode(encoded[:], raw[:])
				if !bytes.Equal(value, encoded[:]) {
					return errors.New("noncanonical independent encoding")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if invalid {
				create := impl.Create
				impl.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
					f, v, e := create(ctx, inv)
					if len(v) > 0 {
						v[0] = '!'
					}
					return f, v, e
				}
			}
			err = conformance.CheckImplementation(t.Context(), generator.Run, impl, fixture)
			if (err != nil) != invalid {
				t.Fatal("independent random property changed", err)
			}
			for _, b := range capture[:cap(capture)] {
				if b != 0 {
					t.Fatal("private property capture retained")
				}
			}
		})
	}
}
