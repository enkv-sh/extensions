package main

import (
	"debug/buildinfo"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestAssemblyReadsStockGoLinuxELFWithoutExecution(t *testing.T) {
	module := t.TempDir()
	mustWrite(t, filepath.Join(module, "go.mod"), []byte("module enkv.sh/compositions/full\n\ngo 1.27.0\n"))
	expected := map[string]string{"installedCLIVerificationKey": "cli-root", "installedPluginKeys": "plugin-root", "installedPluginOrigin": "https://enkv.sh/releases/", "installedPluginRedirectHosts": "github.com,release-assets.githubusercontent.com", "installedPluginTLSRoots": ""}
	names := []string{"installedCLIVerificationKey", "installedPluginKeys", "installedPluginOrigin", "installedPluginRedirectHosts", "installedPluginTLSRoots"}
	var declarations, flags []string
	for _, name := range names {
		declarations = append(declarations, "var "+name+" string")
		flags = append(flags, "-X=enkv.sh/compositions/full."+name+"="+expected[name])
	}
	mustWrite(t, filepath.Join(module, "full.go"), []byte("package full\n"+strings.Join(declarations, "\n")+"\nfunc Values()string{return "+strings.Join(names, "+")+"}\n"))
	mustWrite(t, filepath.Join(module, "cmd/enkv/main.go"), []byte("package main\nimport \"enkv.sh/compositions/full\"\nfunc main(){panic(full.Values())}\n"))
	binary := filepath.Join(t.TempDir(), "enkv-linux-amd64")
	command := exec.CommandContext(t.Context(), "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags="+strings.Join(flags, " "), "-o", binary, "./cmd/enkv")
	command.Dir = module
	fixed := map[string]string{"GOWORK": "off", "GOENV": "off", "GOTOOLCHAIN": "local", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOPROXY": "off", "GOSUMDB": "off"}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := fixed[key]; !ok {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range fixed {
		command.Env = append(command.Env, key+"="+value)
	}
	if out, e := command.CombinedOutput(); e != nil {
		t.Fatalf("ELF fixture compilation: %v %s", e, out)
	}
	info, e := buildinfo.ReadFile(binary)
	if e != nil || info.GoVersion != "go1.27.3" {
		t.Fatalf("ELF fixture compiler: %v %+v", e, info)
	}
	file, e := elf.Open(binary)
	if e != nil {
		t.Fatal(e)
	}
	if file.Machine != elf.EM_X86_64 {
		t.Fatal("fixture is not amd64 ELF")
	}
	if e := file.Close(); e != nil {
		t.Fatal(e)
	}
	actual, e := readAssembly(binary, names)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("ELF assembly differs: %#v", actual)
	}
	if _, e := readAssembly(binary, []string{"missingAssemblySymbol"}); e == nil {
		t.Fatal("missing ELF symbol accepted")
	}
	var floor strings.Builder
	if e := checkFloor(binary, &floor); e != nil || !strings.Contains(floor.String(), "linkage=static glibc_max=none") {
		t.Fatalf("ELF floor: %s %v", floor.String(), e)
	}
}
