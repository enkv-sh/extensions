package generator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestRunDisposesCompleteTransferredAllocations(t *testing.T) {
	for _, outcome := range []string{"success", "callback-error", "invalid-facts", "overlength-value", "partial-result-write", "status-write-failure", "borrowed-value", "borrowed-facts"} {
		t.Run(outcome, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			control, environment, _ := processInput(t, implementation, command)
			allocation := bytes.Repeat([]byte{'s'}, protocol.MaximumSecretLength+1)
			value := allocation[:5]
			public := bytes.Repeat([]byte{'p'}, 64)
			if outcome == "overlength-value" {
				value = allocation
			}
			var result, status bytes.Buffer
			var resultWriter io.Writer = &result
			var statusWriter io.Writer = &status
			partial := &partialWriter{remaining: 44, beforeWrite: func() { assertCleared(t, allocation) }}
			if outcome == "partial-result-write" {
				resultWriter = partial
			}
			if outcome == "status-write-failure" {
				statusWriter = &partialWriter{remaining: 139}
			}
			implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
				facts := completeFacts(inv.Command)
				facts.ProviderFacts = public[:4]
				if outcome == "invalid-facts" {
					facts.Schema = 99
				}
				if outcome == "callback-error" {
					return facts, value, errors.New(processToken)
				}
				if outcome == "borrowed-value" {
					return facts, inv.Inputs[0].Value, nil
				}
				if outcome == "borrowed-facts" {
					facts.ProviderFacts = inv.Command.Intent
				}
				return facts, value, nil
			}
			code := Run(context.Background(), &control, &environment, resultWriter, statusWriter, implementation)
			want := map[string]int{"success": 0, "callback-error": 29, "invalid-facts": 30, "overlength-value": 30, "partial-result-write": 31, "status-write-failure": 32, "borrowed-value": 30, "borrowed-facts": 30}[outcome]
			if code != want || bytes.Contains(status.Bytes(), []byte(processToken)) {
				t.Fatal("disposal outcome differs", code, want)
			}
			if outcome != "borrowed-value" {
				assertCleared(t, allocation)
			}
			if outcome != "borrowed-facts" {
				assertCleared(t, public)
			}
			for _, b := range partial.borrowed {
				assertCleared(t, b)
			}
		})
	}
}

type partialWriter struct {
	remaining   int
	borrowed    [][]byte
	beforeWrite func()
}

func (w *partialWriter) Write(b []byte) (int, error) {
	if w.beforeWrite != nil {
		w.beforeWrite()
	}
	if len(b) <= w.remaining {
		w.remaining -= len(b)
		return len(b), nil
	}
	w.borrowed = append(w.borrowed, b)
	n := w.remaining
	w.remaining = 0
	return n, io.ErrClosedPipe
}

// full_only: false
func TestRunCapsCallbackDeadlineAndRetainsManagedLateResult(t *testing.T) {
	implementation := processImplementation()
	command := processCommand(t, implementation)
	control, environment, id := processInput(t, implementation, command)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	deadline, _ := ctx.Deadline()
	var callbackContext context.Context
	implementation.Create = func(ctx context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
		callbackContext = ctx
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Fatal("callback deadline widened")
		}
		cancel()
		return completeFacts(inv.Command), bytes.Clone(processValue), nil
	}
	var result, status bytes.Buffer
	if code := Run(ctx, &control, &environment, &result, &status, implementation); code != 0 || callbackContext.Err() == nil {
		t.Fatal("original late resource evidence lost", code)
	}
	got := readResult(t, &result, id)
	if !bytes.Equal(got.Value, processValue) {
		t.Fatal("late value changed")
	}
}

// full_only: false
func TestRunRefusesCancellationAndExpiryBeforeCallback(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired"} {
		t.Run(condition, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			if condition == "expired" {
				command.DeadlineUnixMillis = 1
			}
			control, environment, _ := processInput(t, implementation, command)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if condition == "cancelled" {
				cancel()
			}
			called := false
			implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
				called = true
				return protocol.SafeFacts{}, nil, nil
			}
			var result, status bytes.Buffer
			if code := Run(ctx, &control, &environment, &result, &status, implementation); code == 0 || called || result.Len() != 0 {
				t.Fatal("cancelled/expired callback entered", code)
			}
		})
	}
}

// full_only: false
func TestInProcessRunDoesNotChangeAmbientEnvironment(t *testing.T) {
	t.Setenv("PRIVATE_TOKEN", "ambient-unchanged")
	implementation := processImplementation()
	command := processCommand(t, implementation)
	control, environment, _ := processInput(t, implementation, command)
	implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
		if os.Getenv("PRIVATE_TOKEN") != "ambient-unchanged" || string(inv.Inputs[0].Value) != processToken {
			t.Fatal("process environment changed")
		}
		return completeFacts(inv.Command), bytes.Clone(processValue), nil
	}
	var result, status bytes.Buffer
	if code := Run(context.Background(), &control, &environment, &result, &status, implementation); code != 0 || os.Getenv("PRIVATE_TOKEN") != "ambient-unchanged" {
		t.Fatal("in-process environment mutated", code)
	}
}

// full_only: false
func TestRunNoResourceGeneratorDiscardsLateValue(t *testing.T) {
	implementation := processImplementation()
	implementation.Retire = nil
	implementation.CheckRetirementCompatibility = nil
	command := processCommand(t, implementation)
	intent := protocol.Intent{Schema: 1, ConfigContractID: implementation.ConfigContractID(), LifecycleMode: protocol.LifecycleNone, Settings: []byte(`{}`)}
	command.Intent, _ = protocol.EncodeIntent(intent)
	command.IntentDigest, _ = protocol.IntentDigest(command.Intent)
	command.LifecycleMode = protocol.LifecycleNone
	command.ResourceContractID = protocol.ID{}
	control, environment, _ := processInput(t, implementation, command)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	value := []byte{0, 255, 7}
	implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
		cancel()
		return inv.Command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone), value, nil
	}
	var result, status bytes.Buffer
	if code := Run(ctx, &control, &environment, &result, &status, implementation); code == 0 || result.Len() != 0 {
		t.Fatal("late unmanaged value escaped", code)
	}
	assertCleared(t, value)
}

// full_only: false
func TestRunRefusesNilArgumentsWithoutExecution(t *testing.T) {
	for _, missing := range []string{"context", "control", "environment", "result", "status", "descriptor", "protocol", "route"} {
		t.Run(missing, func(t *testing.T) {
			implementation := processImplementation()
			ctx := context.Background()
			var control, environment io.Reader = new(bytes.Buffer), new(bytes.Buffer)
			var result, status io.Writer = new(bytes.Buffer), new(bytes.Buffer)
			called := false
			implementation.Create = func(context.Context, Invocation) (protocol.SafeFacts, []byte, error) {
				called = true
				return protocol.SafeFacts{}, nil, nil
			}
			switch missing {
			case "context":
				ctx = nil
			case "control":
				control = nil
			case "environment":
				environment = nil
			case "result":
				result = nil
			case "status":
				status = nil
			case "descriptor":
				implementation.identity.DescriptorID = protocol.ID{}
			case "protocol":
				implementation.identity.ProtocolID = protocol.ID{}
			case "route":
				implementation.route.Schema = 99
			}
			if code := Run(ctx, control, environment, result, status, implementation); code != 20 || called {
				t.Fatal("invalid argument reached serving", code)
			}
		})
	}
}

// full_only: false
func TestReturnedValueRequiresSeparatePublicStorage(t *testing.T) {
	backing := make([]byte, 12)
	for _, field := range []string{"target", "resource", "provider"} {
		t.Run(field, func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				value, public []byte
				overlap       bool
			}{
				{"same", backing[:4:4], backing[:4:4], true},
				{"value-starts-first", backing[1:6:6], backing[4:8:8], true},
				{"field-starts-first", backing[4:8:8], backing[1:6:6], true},
				{"public-capacity", backing[6:8:8], backing[1:2:7], true},
				{"value-capacity", backing[1:1:7], backing[6:8:8], true},
				{"adjacent", backing[1:4:4], backing[4:6:6], false},
				{"independent", make([]byte, 4), backing[:4], false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var facts protocol.SafeFacts
					switch field {
					case "target":
						facts.Target = tc.public
					case "resource":
						facts.ResourceData = tc.public
					case "provider":
						facts.ProviderFacts = tc.public
					}
					if got := overlapsReturned(facts, tc.value); got != tc.overlap {
						t.Fatalf("overlap = %v, want %v", got, tc.overlap)
					}
				})
			}
		})
	}
}

// full_only: false
func TestRunRefusesSharedValueAndFactBackingBeforeEncoding(t *testing.T) {
	for _, field := range []string{"target", "resource", "provider"} {
		t.Run(field, func(t *testing.T) {
			implementation := processImplementation()
			command := processCommand(t, implementation)
			control, environment, id := processInput(t, implementation, command)
			backing := []byte("ordinary-test-bytes")
			implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
				facts := completeFacts(inv.Command)
				public := backing[9:13]
				switch field {
				case "target":
					facts.Target = public
				case "resource":
					facts.ResourceData = public
				case "provider":
					facts.ProviderFacts = public
				}
				return facts, backing[:4], nil
			}
			var result, status bytes.Buffer
			if code := Run(t.Context(), &control, &environment, &result, &status, implementation); code != exitResultEncode || result.Len() != 0 {
				t.Fatal("invalid ownership reached result delivery", code)
			}
			finalStatus(t, &status, id, protocol.Status{Stage: protocol.StatusStageResponse, Category: protocol.StatusProtocol})
			assertCleared(t, backing)
		})
	}
}
