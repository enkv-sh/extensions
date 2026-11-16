package native

import (
	"bytes"
	"context"
	"encoding/json"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	manifest "enkv.sh/sdk/manifest-generator"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestBindingChecksFamilyWireAndSupportedContracts(t *testing.T) {
	descriptor := artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "bound-manifest", Role: "manifest-generator", Version: "1.0.0", Wire: DescriptorWire(), Manifest: &artifact.ManifestDeclaration{ConfigContractID: "supported/config", FormatContractID: "supported/format"}}
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	callbacks := manifest.Implementation{ValidateFormatSettings: func(context.Context, manifest.SettingsRequest) manifest.SettingsResult {
		t.Fatal("startup entered settings callback")
		return manifest.SettingsResult{}
	}, Render: func(context.Context, manifest.View) manifest.Result {
		t.Fatal("startup entered renderer")
		return manifest.Result{}
	}}
	events := []string{}
	artifactWriter, statusWriter := &writerFixture{events: &events}, &writerFixture{events: &events}
	if Serve(t.Context(), bytes.NewReader(nil), artifactWriter, statusWriter, Implementation{Implementation: callbacks}) != 2 {
		t.Fatal("zero binding accepted")
	}
	bound, err := Bind(body, "supported/config", "supported/format", callbacks)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := descriptor.Identity()
	if err != nil || bound.Identity().DescriptorID != manifest.ID(identity) {
		t.Fatal("canonical identity differs", err)
	}
	var spaced bytes.Buffer
	if err := json.Indent(&spaced, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	equivalent, err := Bind(spaced.Bytes(), "supported/config", "supported/format", callbacks)
	if err != nil || equivalent.Identity() != bound.Identity() {
		t.Fatal("whitespace changed identity", err)
	}
	for _, condition := range []string{"wrong-family", "missing-declaration", "wire-identity", "wire-version", "config", "format"} {
		t.Run(condition, func(t *testing.T) {
			candidate, err := artifact.DecodeDescriptor(body)
			if err != nil {
				t.Fatal(err)
			}
			config, format := "supported/config", "supported/format"
			switch condition {
			case "wrong-family":
				candidate.Role = "output"
				candidate.Manifest = nil
				route, err := credentialroute.Encode(credentialroute.Route{Schema: credentialroute.Schema, ContractID: [32]byte{1}, Mode: credentialroute.ModeSDK})
				if err != nil {
					t.Fatal(err)
				}
				candidate.Output = &artifact.OutputDeclaration{ConfigContractID: "supported/config", CredentialRoute: route}
			case "missing-declaration":
				candidate.Manifest = nil
			case "wire-identity":
				candidate.Wire.Identity = artifact.Digest{9}.String()
			case "wire-version":
				candidate.Wire.Version++
			case "config":
				config = "other/config"
			case "format":
				format = "other/format"
			}
			damaged, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Bind(damaged, config, format, callbacks)
			if !errors.Is(err, artifact.ErrRecord) {
				t.Fatal("invalid startup lost record cause", err)
			}
			field := "descriptor.wire"
			switch condition {
			case "wrong-family":
				field = "descriptor.role"
			case "config":
				field = "descriptor.manifest.config_contract_id"
			case "format":
				field = "descriptor.manifest.format_contract_id"
			case "missing-declaration":
				return
			}
			if !strings.Contains(err.Error(), field) || strings.Contains(err.Error(), "other/") {
				t.Fatal("binding lost safe field diagnosis", err)
			}
		})
	}
}
