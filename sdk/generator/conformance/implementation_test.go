package conformance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestSemanticFixtureReportsSafeBindingFailures(t *testing.T) {
	checkCallerContextDiagnosis(t)
	implementation, fixture, err := synthetic()
	if err != nil {
		t.Fatal(err)
	}
	fixture.Command.CredentialRouteID = protocol.ID{99}
	calls := 0
	actual := implementation.Create
	implementation.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
		calls++
		return actual(ctx, inv)
	}
	err = CheckImplementation(t.Context(), generator.Run, implementation, fixture)
	if calls != 0 || !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), "fixture.command.credential_route_id: binding mismatch") {
		t.Fatal("fixture route diagnosis lost its field or cause", err, calls)
	}
	for _, condition := range []string{"valid", "callback-failure", "explicit-invalid-failure", "expected-facts", "value-conflict", "wrong-config", "invalid-action"} {
		t.Run(condition, func(t *testing.T) {
			impl, raw, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			intent, err := protocol.DecodeIntent(raw.Command.Intent)
			if err != nil {
				t.Fatal(err)
			}
			request := Request{Action: protocol.ActionCreate, Intent: intent}
			expected := Expectation{Disposition: raw.ExpectedFacts.Disposition, Target: raw.ExpectedFacts.Target, ResourceData: raw.ExpectedFacts.ResourceData, Value: raw.ExpectedValue}
			if condition == "callback-failure" || condition == "explicit-invalid-failure" {
				expected = Expectation{Failure: true}
				if condition == "explicit-invalid-failure" {
					expected.Target = []byte("PRIVATE_FACT")
				}
			}
			if condition == "expected-facts" {
				expected.Reason = 255
			}
			if condition == "value-conflict" {
				expected.CheckValue = func([]byte) error { return nil }
			}
			if condition == "wrong-config" {
				request.Intent.ConfigContractID = protocol.ID{99}
			}
			if condition == "invalid-action" {
				request.Action = 99
			}
			fixture, err := NewFixture(impl, request, expected)
			valid := condition == "valid" || condition == "callback-failure"
			if (err == nil) != valid {
				t.Fatal("semantic fixture acceptance changed", err)
			}
			if !valid {
				if !errors.Is(err, protocol.ErrProtocol) || strings.Contains(err.Error(), "PRIVATE_FACT") {
					t.Fatal("unsafe fixture cause", err)
				}
				return
			}
			impl.Create = func(_ context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
				facts := inv.Command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
				facts.Target = bytes.Clone(raw.ExpectedFacts.Target)
				facts.ResourceData = bytes.Clone(raw.ExpectedFacts.ResourceData)
				return facts, bytes.Clone(raw.ExpectedValue), nil
			}
			if condition == "callback-failure" {
				impl.Create = func(context.Context, generator.Invocation) (protocol.SafeFacts, []byte, error) {
					return protocol.SafeFacts{}, nil, errors.New("PRIVATE_CALLBACK_TEXT")
				}
			}
			if err := CheckImplementation(t.Context(), generator.Run, impl, fixture); err != nil {
				t.Fatal("valid semantic expectation refused", err)
			}
		})
	}

	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "retire", true: "retire-input-corrected-by-callback"}[changed], func(t *testing.T) {
			impl, raw, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			intent, err := protocol.DecodeIntent(raw.Command.Intent)
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := NewFixture(impl, Request{Action: protocol.ActionRetire, Intent: intent, OriginalFacts: &raw.ExpectedFacts}, Expectation{Disposition: protocol.DispositionRetirementAcknowledged, Target: raw.ExpectedFacts.Target, ResourceData: raw.ExpectedFacts.ResourceData})
			if err != nil {
				t.Fatal(err)
			}
			impl.Retire = func(_ context.Context, inv generator.Invocation) (protocol.SafeFacts, error) {
				inv.Command.DomainID = fixture.Command.DomainID
				facts := inv.Command.NewFacts(protocol.DispositionRetirementAcknowledged, protocol.ReasonNone)
				facts.Target = bytes.Clone(raw.ExpectedFacts.Target)
				facts.ResourceData = bytes.Clone(raw.ExpectedFacts.ResourceData)
				return facts, nil
			}
			serve := Serve(generator.Run)
			if changed {
				serve = func(ctx context.Context, c, e io.Reader, r, s io.Writer, implementation generator.Implementation) int {
					retire := implementation.Retire
					implementation.Retire = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, error) {
						inv.Command.DomainID[0] ^= 1
						return retire(ctx, inv)
					}
					return generator.Run(ctx, c, e, r, s, implementation)
				}
			}
			err = CheckImplementation(t.Context(), serve, impl, fixture)
			if (err != nil) != changed {
				t.Fatal("retirement input or outcome changed", err)
			}
		})
	}

}

// full_only: false
func TestAuthorCheckComparesProtocolMeaning(t *testing.T) {
	for _, condition := range []string{"nil-inputs", "empty-original-facts", "nil-value", "empty-value", "presence", "order", "name", "identity"} {
		t.Run(condition, func(t *testing.T) {
			implementation, fixture, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "nil-inputs":
				fixture.Inputs = nil
			case "empty-original-facts":
				fixture.Command.OriginalFacts = []byte{}
			default:
				route := implementation.CredentialRoute()
				route.Names = []string{"ALPHA", "BETA"}
				encoded, err := credentialroute.Encode(route)
				if err != nil {
					t.Fatal(err)
				}
				descriptor, err := artifact.EncodeDescriptor(artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "paired-inputs", Role: "generator", Version: "1.0.0", Wire: generator.DescriptorWire(), Generator: &artifact.GeneratorDeclaration{ConfigContractID: artifact.Digest(implementation.ConfigContractID()), CredentialRoute: encoded}})
				if err != nil {
					t.Fatal(err)
				}
				implementation.Binding, err = generator.Bind(descriptor, implementation.ConfigContractID())
				if err != nil {
					t.Fatal(err)
				}
				routeID, err := credentialroute.Identity(route)
				if err != nil {
					t.Fatal(err)
				}
				fixture.Command.DescriptorID = implementation.Identity().DescriptorID
				fixture.Command.CredentialRouteID = protocol.ID(routeID)
				fixture.Inputs = []credentialroute.Input{{Name: "ALPHA", Present: true}, {Name: "BETA", Present: true}}
				if condition != "nil-value" {
					fixture.Inputs[0].Value = []byte{}
				}
			}
			serve := Serve(generator.Run)
			wantField := ""
			switch condition {
			case "presence", "order", "name":
				wantField = "inputs"
			case "identity":
				wantField = "command"
			}
			if wantField != "" {
				serve = func(ctx context.Context, control, environment io.Reader, result, status io.Writer, implementation generator.Implementation) int {
					create := implementation.Create
					implementation.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
						switch condition {
						case "presence":
							inv.Inputs[0].Present = false
						case "order":
							inv.Inputs[0], inv.Inputs[1] = inv.Inputs[1], inv.Inputs[0]
						case "name":
							inv.Inputs[0].Name = "PRIVATE_NAME"
						case "identity":
							inv.Command.DomainID[0] ^= 1
						}
						return create(ctx, inv)
					}
					return generator.Run(ctx, control, environment, result, status, implementation)
				}
			}
			err = CheckImplementation(t.Context(), serve, implementation, fixture)
			if wantField == "" {
				if err != nil {
					t.Fatal("equivalent protocol meaning refused", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), wantField) || strings.Contains(err.Error(), "PRIVATE_NAME") {
				t.Fatal("changed input lacks a safe field diagnosis", err)
			}
		})
	}
}

// full_only: false
func TestServingConformanceUsesGenericImplementation(t *testing.T) {
	if err := Check(generator.Run); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestAuthorCheckDetectsWrongRawReturnEvenWhenServingRefuses(t *testing.T) {
	for _, condition := range []string{"wrong-value", "wrong-facts", "borrowed-value", "callback-not-entered"} {
		t.Run(condition, func(t *testing.T) {
			implementation, fixture, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			serve := Serve(generator.Run)
			original := implementation.Create
			implementation.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
				f, v, e := original(ctx, inv)
				switch condition {
				case "wrong-value":
					v[0] ^= 1
				case "wrong-facts":
					f.RequestDigest[0] ^= 1
				case "borrowed-value":
					clear(v)
					v = inv.Command.Intent[:3]
				}
				return f, v, e
			}
			if condition == "callback-not-entered" {
				serve = func(context.Context, io.Reader, io.Reader, io.Writer, io.Writer, generator.Implementation) int {
					return 0
				}
			}
			if err := CheckImplementation(context.Background(), serve, implementation, fixture); err == nil {
				t.Fatal("defective implementation passed")
			}
		})
	}
}

// full_only: false
func TestAuthorCheckRandomValuePropertyAndExactWire(t *testing.T) {
	for _, condition := range []string{"valid", "invalid-property", "property-mutates-capture", "property-mutates-result", "wire-corruption", "wrong-facts", "input-mutation", "callback-error", "conflicting-expectation", "maximum", "maximum-wire-failure", "first-excess"} {
		t.Run(condition, func(t *testing.T) {
			implementation, fixture, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			fixture.ExpectedValue = nil
			var propertyBorrow, returned []byte
			propertyCalls := 0
			fixture.CheckValue = func(value []byte) error {
				propertyCalls++
				propertyBorrow = value
				if condition == "property-mutates-capture" {
					value[0] ^= 1
				}
				if condition == "property-mutates-result" {
					returned[0] ^= 1
				}
				if len(value) == 0 || value[0] != 7 {
					return errors.New("PRIVATE_PROPERTY_TEXT")
				}
				return nil
			}
			if condition == "conflicting-expectation" {
				fixture.ExpectedValue = []byte{7}
			}
			create := implementation.Create
			implementation.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
				facts, old, err := create(ctx, inv)
				clear(old[:cap(old)])
				size := 3
				if condition == "maximum" || condition == "maximum-wire-failure" {
					size = protocol.MaximumSecretLength
				}
				if condition == "first-excess" {
					size = protocol.MaximumSecretLength + 1
				}
				returned = bytes.Repeat([]byte{7}, size)
				if condition == "invalid-property" {
					returned[0] = 8
				}
				if condition == "wrong-facts" {
					facts.RequestDigest[0] ^= 1
				}
				if condition == "input-mutation" {
					inv.Command.Intent[0] ^= 1
				}
				if condition == "callback-error" {
					err = errors.New("PRIVATE_CALLBACK_TEXT")
				}
				return facts, returned, err
			}
			serve := Serve(generator.Run)
			if condition == "wire-corruption" || condition == "maximum-wire-failure" {
				serve = func(ctx context.Context, c, e io.Reader, r, s io.Writer, impl generator.Implementation) int {
					var wire bytes.Buffer
					code := generator.Run(ctx, c, e, &wire, s, impl)
					capturedWire := wire.Bytes()
					defer clear(capturedWire[:cap(capturedWire)])
					frame, err := protocol.ReadFrame(&wire, protocol.MaximumResultBody)
					if err != nil {
						t.Fatal(err)
					}
					defer clear(frame.Body[:cap(frame.Body)])
					frame.Body[len(frame.Body)-1] ^= 1
					if err := protocol.WriteFrame(r, frame); err != nil {
						t.Fatal(err)
					}
					return code
				}
			}
			err = CheckImplementation(t.Context(), serve, implementation, fixture)
			want := condition == "valid" || condition == "maximum"
			if (err == nil) != want {
				t.Fatal("property or exact capture acceptance changed", err)
			}
			if err != nil && (strings.Contains(err.Error(), "PRIVATE_PROPERTY_TEXT") || strings.Contains(err.Error(), "PRIVATE_CALLBACK_TEXT")) {
				t.Fatal("private error text escaped")
			}
			if !allZero(propertyBorrow[:cap(propertyBorrow)]) || !allZero(returned[:cap(returned)]) {
				t.Fatal("full capture or callback backing retained")
			}
			if condition == "first-excess" || condition == "conflicting-expectation" {
				if propertyCalls != 0 {
					t.Fatal("invalid fixture/value reached property")
				}
			}
			if condition == "maximum" || condition == "maximum-wire-failure" {
				if len(propertyBorrow) != 87384 || cap(propertyBorrow) != 87384 {
					t.Fatalf("maximum capture length/capacity = %d/%d, want 87384/87384", len(propertyBorrow), cap(propertyBorrow))
				}
			}
		})
	}
}
