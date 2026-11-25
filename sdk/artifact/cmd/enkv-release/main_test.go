package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestOfficialReleaseInventory(t *testing.T) {
	inv, err := readInventory("../../../../distribution/release.json")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range inv.Plugins {
		names = append(names, p.Name)
	}
	want := []string{"aws-secrets-manager", "cloudflare-account-token", "gcp-secret-manager", "generic-json", "github-actions-environment", "github-actions-organization", "github-actions-repository", "local-random-secret", "opentofu-tfvars-json"}
	if !reflect.DeepEqual(names, want) || inv.CLIVersion != "0.1.0-beta.2" || inv.PluginTag != "plugins-v0.1.1" {
		t.Fatalf("release inventory differs: %+v", inv)
	}
	for _, plugin := range inv.Plugins {
		body, err := os.ReadFile(filepath.Join("../../../..", plugin.Directory, plugin.Descriptor))
		if err != nil {
			t.Fatal(err)
		}
		var descriptor struct{ Name, Version string }
		if err := json.Unmarshal(body, &descriptor); err != nil {
			t.Fatal(err)
		}
		if descriptor.Name != plugin.Name || descriptor.Version != plugin.Version || plugin.Version != "0.1.1" {
			t.Fatalf("descriptor differs: %+v", descriptor)
		}
	}
}

// full_only: false
func TestIncompleteCandidateRefuses(t *testing.T) {
	inv, err := readInventory("../../../../distribution/release.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCandidate(t.Context(), inv, t.TempDir(), "plugins", "production"); err == nil {
		t.Fatal("incomplete candidate accepted")
	}
}

// full_only: false
func TestNativeFloorUsesNumericGLIBCMaximum(t *testing.T) {
	got, err := glibcMaximum([]elf.ImportedSymbol{{Version: "GLIBC_2.9"}, {Version: "GLIBC_2.34"}, {Version: "GLIBC_2.2.5"}})
	if err != nil || got != "GLIBC_2.34" {
		t.Fatalf("wrong glibc maximum %q: %v", got, err)
	}
	if _, err := glibcMaximum([]elf.ImportedSymbol{{Version: "GLIBC_2.35"}}); err == nil {
		t.Fatal("glibc floor violation accepted")
	}
}

// full_only: false
func TestInstallationPageUsesExactInventoryLinks(t *testing.T) {
	inv, err := readInventory("../../../../distribution/release.json")
	if err != nil {
		t.Fatal(err)
	}
	page := installationPage(inv)
	for _, name := range []string{"enkv-full-0.1.0-beta.2-darwin-arm64.tar.gz", "enkv-full-0.1.0-beta.2-linux-amd64.tar.gz"} {
		if !strings.Contains(page, "https://github.com/enkv-sh/core/releases/download/v0.1.0-beta.2/"+name) {
			t.Fatal("missing exact CLI link", name)
		}
	}
	if destination := os.Getenv("ENKV_RELEASE_PAGE_EXAMPLE"); destination != "" {
		if err := os.WriteFile(destination, []byte(page), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// full_only: false
func TestStaticELFFloorAndMalformedDynamicELF(t *testing.T) {
	body := make([]byte, 121)
	copy(body, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(body[16:], 2)
	binary.LittleEndian.PutUint16(body[18:], 62)
	binary.LittleEndian.PutUint32(body[20:], 1)
	binary.LittleEndian.PutUint16(body[52:], 64)
	binary.LittleEndian.PutUint16(body[54:], 56)
	binary.LittleEndian.PutUint16(body[58:], 64)
	binary.LittleEndian.PutUint64(body[24:], 0x400000)
	binary.LittleEndian.PutUint64(body[32:], 64)
	binary.LittleEndian.PutUint16(body[56:], 1)
	binary.LittleEndian.PutUint32(body[64:], 1)
	binary.LittleEndian.PutUint32(body[68:], 5)
	binary.LittleEndian.PutUint64(body[72:], 120)
	binary.LittleEndian.PutUint64(body[80:], 0x400000)
	binary.LittleEndian.PutUint64(body[88:], 0x400000)
	binary.LittleEndian.PutUint64(body[96:], 1)
	binary.LittleEndian.PutUint64(body[104:], 1)
	binary.LittleEndian.PutUint64(body[112:], 1)
	body[120] = 0xc3
	path := filepath.Join(t.TempDir(), "static")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAssembly(path, []string{"installedPluginKeys"}); err == nil {
		t.Fatal("missing CLI symbols accepted")
	}
	var output strings.Builder
	if err := checkFloor(path, &output); err != nil || !strings.Contains(output.String(), "linkage=static glibc_max=none") {
		t.Fatalf("static ELF floor: %s %v", output.String(), err)
	}
	dynamic := append(body, make([]byte, 56)...)
	binary.LittleEndian.PutUint64(dynamic[32:], 64)
	binary.LittleEndian.PutUint16(dynamic[56:], 1)
	binary.LittleEndian.PutUint32(dynamic[64:], 2)
	if err := os.WriteFile(path, dynamic, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkFloor(path, &output); err == nil {
		t.Fatal("dynamic ELF without symbol table accepted")
	}
	if err := os.WriteFile(path, []byte("bad ELF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkFloor(path, &output); err == nil {
		t.Fatal("malformed executable accepted")
	}
}
