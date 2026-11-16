package output

import (
	"bytes"
	"encoding/json"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
	"errors"
	"io"
	"strings"
	"testing"
)

// full_only: false
func TestBindingChecksFamilyWireSemanticsAndRoute(t *testing.T) {
	if _, err := acknowledge(forbiddenRead{}, io.Discard, (Binding{}).Identity()); err == nil {
		t.Fatal("zero binding accepted")
	}
	config := "supported/config"
	routeBytes, err := credentialroute.Encode(credentialroute.Route{Schema: credentialroute.Schema, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "bound-plugin", Role: "output", Version: "1.0.0", Wire: DescriptorWire(), Output: &artifact.OutputDeclaration{ConfigContractID: config, CredentialRoute: routeBytes}}
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := Bind(body, config)
	if err != nil {
		t.Fatal(err)
	}
	canonicalID, err := descriptor.Identity()
	if err != nil || binding.Identity().DescriptorID != protocol.ID(canonicalID) || binding.Identity().ProtocolID != protocol.ProtocolID() {
		t.Fatal("canonical binding differs", err)
	}
	// Reverse key order independently and add whitespace; identity remains semantic.
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	var reordered bytes.Buffer
	reordered.WriteString("{\n")
	keys := []string{"manifest", "output", "generator", "wire", "version", "role", "name", "schema"}
	for i, key := range keys {
		if i != 0 {
			reordered.WriteString(",\n")
		}
		keyBytes, _ := json.Marshal(key)
		reordered.Write(keyBytes)
		reordered.WriteString(": ")
		reordered.Write(object[key])
	}
	reordered.WriteString("\n}")
	equivalent, err := Bind(reordered.Bytes(), config)
	if err != nil || equivalent.Identity() != binding.Identity() {
		t.Fatal("spacing/order changed identity", err)
	}
	route := binding.CredentialRoute()
	route.Names[0] = "OTHER"
	if binding.CredentialRoute().Names[0] != "TOKEN" {
		t.Fatal("binding exposed route storage")
	}
	for _, condition := range []string{"wrong-family", "missing-declaration", "wire-identity", "wire-version", "route", "config"} {
		t.Run(condition, func(t *testing.T) {
			candidate, err := artifact.DecodeDescriptor(body)
			if err != nil {
				t.Fatal(err)
			}
			supported := config
			switch condition {
			case "wrong-family":
				candidate.Role = "manifest-generator"
				candidate.Output = nil
				candidate.Manifest = &artifact.ManifestDeclaration{ConfigContractID: "other/config", FormatContractID: "other/format"}
			case "missing-declaration":
				candidate.Output = nil
			case "wire-identity":
				candidate.Wire.Identity = artifact.Digest{9}.String()
			case "wire-version":
				candidate.Wire.Version++
			case "route":
				candidate.Output.CredentialRoute = []byte{1}
			case "config":
				supported = "other/config"
			}
			// JSON encoding admits damaged descriptors for the startup boundary test.
			damaged, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Bind(damaged, supported)
			if err == nil {
				t.Fatal("invalid startup accepted")
			}
			switch condition {
			case "wrong-family", "wire-identity", "wire-version", "config":
				field := "descriptor.wire"
				if condition == "wrong-family" {
					field = "descriptor.role"
				}
				if condition == "config" {
					field = "descriptor.output.config_contract_id"
				}
				if !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), field) || strings.Contains(err.Error(), "other/") {
					t.Fatal("binding lost safe field diagnosis", err)
				}
			default:
				if !errors.Is(err, artifact.ErrRecord) {
					t.Fatal("descriptor refusal lost its cause", err)
				}
			}
		})
	}
}
