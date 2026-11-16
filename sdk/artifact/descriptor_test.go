package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact/credentialroute"
)

func authorDescriptor(role string) Descriptor {
	d := Descriptor{Schema: DescriptorSchema, Name: "private-local-inventory", Role: role, Version: "1.0.0", Wire: Contract{Kind: "wire", Identity: Digest{1}.String(), Version: 9}}
	route, _ := credentialroute.Encode(credentialroute.Route{Schema: credentialroute.Schema, ContractID: [32]byte{2}, Mode: credentialroute.ModeEnvironment, Names: []string{"PRIVATE_PLUGIN_TOKEN"}})
	switch role {
	case "generator":
		d.Generator = &GeneratorDeclaration{ConfigContractID: Digest{3}, CredentialRoute: route}
	case "output":
		d.Output = &OutputDeclaration{ConfigContractID: "private-output-settings/v1", CredentialRoute: route}
	case "manifest-generator":
		d.Manifest = &ManifestDeclaration{ConfigContractID: "private-format-settings/v1", FormatContractID: "private-inventory/v1"}
	}
	return d
}

// full_only: false
func TestDescriptorRejectsNoncanonicalFieldNames(t *testing.T) {
	for _, tc := range []struct{ role, field, value, path string }{
		{"generator", "name", `"private-local-inventory"`, "record.name"},
		{"generator", "kind", `"wire"`, "record.wire.kind"},
		{"generator", "config_contract_id", `"` + Digest{3}.String() + `"`, "record.generator.config_contract_id"},
		{"output", "config_contract_id", `"private-output-settings/v1"`, "record.output.config_contract_id"},
		{"manifest-generator", "format_contract_id", `"private-inventory/v1"`, "record.manifest.format_contract_id"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			body, err := EncodeDescriptor(authorDescriptor(tc.role))
			if err != nil {
				t.Fatal(err)
			}
			field := `"` + tc.field + `":` + tc.value
			variant := `"` + strings.ToUpper(tc.field) + `":` + tc.value
			for _, damage := range []struct{ name, replacement, condition, path string }{
				{"variant", variant, "noncanonical field", tc.path},
				{"variant_first", variant + "," + field, "noncanonical field", tc.path},
				{"variant_last", field + "," + variant, "noncanonical field", tc.path},
				{"duplicate", field + "," + field, "duplicate field", tc.path},
				{"unknown", field + `,"private-credential-key":"private-supplied-value"`, "unknown field", strings.TrimSuffix(tc.path, "."+tc.field)},
			} {
				t.Run(damage.name, func(t *testing.T) {
					_, err := DecodeDescriptor(bytes.Replace(body, []byte(field), []byte(damage.replacement), 1))
					if !errors.Is(err, ErrRecord) || !strings.Contains(err.Error(), damage.path) || !strings.Contains(err.Error(), damage.condition) || strings.Contains(err.Error(), strings.ToUpper(tc.field)) || strings.Contains(err.Error(), tc.value) || strings.Contains(err.Error(), "private-credential-key") || strings.Contains(err.Error(), "private-supplied-value") {
						t.Fatal("field admission lost safe canonical diagnosis", err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestDescriptorCanonicalIdentityUsesAuthorFactsOnly(t *testing.T) {
	d := authorDescriptor("manifest-generator")
	want := `{"schema":1,"name":"private-local-inventory","role":"manifest-generator","version":"1.0.0","wire":{"kind":"wire","identity":"01` + strings.Repeat("00", 31) + `","version":9},"generator":null,"output":null,"manifest":{"config_contract_id":"private-format-settings/v1","format_contract_id":"private-inventory/v1"}}`
	body, err := EncodeDescriptor(d)
	if err != nil || string(body) != want {
		t.Fatal("author descriptor canonical bytes differ", err)
	}
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/PLUGIN-DESCRIPTOR/v1\x00"), uint32(len(want)))
	wantID := sha256.Sum256(append(preimage, want...))
	id, err := d.Identity()
	if err != nil || id != wantID {
		t.Fatal("descriptor identity differs", err)
	}
	formatted := " {\n" + strings.Replace(want[1:len(want)-1], `,"role":`, ",\n\"role\":", 1) + "\n} "
	readable, err := DecodeDescriptor([]byte(formatted))
	if err != nil {
		t.Fatal("ordinary author formatting refused", err)
	}
	readableID, err := readable.Identity()
	if err != nil || readableID != wantID {
		t.Fatal("formatting changed descriptor meaning", err)
	}
	for _, role := range []string{"generator", "output", "manifest-generator"} {
		d := authorDescriptor(role)
		body, err := EncodeDescriptor(d)
		if err != nil {
			t.Fatal("unlisted family implementation refused", role, err)
		}
		decoded, err := DecodeDescriptor(body)
		if err != nil || decoded.Name != d.Name || decoded.Role != role {
			t.Fatal("family descriptor changed", role, err)
		}
	}
}

// full_only: false
func TestDescriptorRejectsMeasuredFieldsAndInvalidFamilyArms(t *testing.T) {
	valid, _ := EncodeDescriptor(authorDescriptor("manifest-generator"))
	for _, body := range [][]byte{
		bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1,"executable":{}`), 1),
		bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
	} {
		if _, err := DecodeDescriptor(body); err == nil {
			t.Fatal("unknown or duplicate descriptor field accepted")
		}
	}
	for _, change := range []func(*Descriptor){
		func(v *Descriptor) { v.Name = "../plugin" },
		func(v *Descriptor) { v.Name = strings.Repeat("a", 256) },
		func(v *Descriptor) { v.Role = "new-family" },
		func(v *Descriptor) { v.Wire.Identity = "format-name" },
		func(v *Descriptor) { v.Wire.Version = 0 },
		func(v *Descriptor) { v.Manifest = nil },
		func(v *Descriptor) { v.Generator = &GeneratorDeclaration{} },
		func(v *Descriptor) { v.Manifest.FormatContractID = strings.Repeat("x", MaxSemanticBytes+1) },
	} {
		d := authorDescriptor("manifest-generator")
		change(&d)
		if _, err := EncodeDescriptor(d); err == nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
}
