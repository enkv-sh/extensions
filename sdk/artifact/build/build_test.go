package build

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"

	"enkv.sh/sdk/artifact/credentialroute"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestResolvedDependenciesPreserveActualRepresentations(t *testing.T) {
	source := artifact.Hash([]byte("selected input"))
	modules := []artifact.SourceModule{{Path: "example.test/author", Main: true}, {Path: "example.test/helper", Version: "v1.2.3", Replace: &artifact.SourceModule{Path: "../helper", Dir: "/helper"}}}
	rows, err := resolvedDependencies(modules, []artifact.Source{{Module: "example.test/author", Digest: source}, {Module: "example.test/helper", Digest: source}})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Version != "" || rows[0].Replacement != nil {
		t.Fatal("workspace main representation changed")
	}
	if rows[1].Replacement == nil || rows[1].Replacement.Version != "" || rows[1].Replacement.SourceDigest != source {
		t.Fatal("local replacement representation changed")
	}
	if _, err := resolvedDependencies(modules, nil); err == nil {
		t.Fatal("unbound local replacement accepted")
	}
}

// full_only: false
func TestBuildEnvironmentRejectsCompilerOverridesAndImplicitWorkspace(t *testing.T) {
	t.Setenv("GOFLAGS", "-overlay=other.json")
	if _, err := buildEnvironment(Config{Versioned: true}); err == nil {
		t.Fatal("compiler override accepted")
	}
	t.Setenv("GOFLAGS", "")
	if _, err := buildEnvironment(Config{}); err == nil {
		t.Fatal("implicit local workspace accepted")
	}
}

// full_only: false
func TestRunRequiresMetadataForCompilerSelectedOwners(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, name := range []string{"LICENSE", "go.mod", "group_writable_compiler_output"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			root := t.TempDir()
			for path, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/main\n\ngo 1.27.0\n", "main.go": "package main\nfunc main(){}\n"} {
				if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			config := publicBuildFixtureConfig(t, root, []string{root})
			marker, err := Run(ctx, config)
			if err != nil {
				t.Fatal("complete compiler-selected owner refused", err)
			}
			metadata, err := artifact.VerifyBuild(ctx, config.Output)
			if err != nil || metadata.Toolchain != "go1.27.3" {
				t.Fatal("build did not record the exact supported compiler", metadata.Toolchain, err)
			}
			if name == "group_writable_compiler_output" {
				originalInfo, err := os.Stat(filepath.Join(config.Output, filepath.FromSlash(marker.Directory), "plugin"))
				if err != nil || originalInfo.Mode().Perm()&0222 != 0 || originalInfo.Mode().Perm()&0100 == 0 {
					t.Fatal("published executable is not read-only and owner-executable", err)
				}
				publishedMode := originalInfo.Mode().Perm()
				publicBuildGoCommand(t, "go1.27.3", filepath.Join(config.Output, filepath.FromSlash(marker.Directory), "plugin"))
				fresh := publicBuildFixtureConfig(t, root, []string{root})
				completed, err := Run(ctx, fresh)
				if err != nil || !reflect.DeepEqual(completed, marker) {
					t.Fatal("group-writable compiler output did not produce the same complete marker", completed, err)
				}
				after, err := artifact.VerifyBuild(ctx, fresh.Output)
				if err != nil || !reflect.DeepEqual(after, metadata) {
					t.Fatal("compiler output mode changed verified build facts", err)
				}
				info, err := os.Stat(filepath.Join(fresh.Output, filepath.FromSlash(completed.Directory), "plugin"))
				if err != nil || info.Mode().Perm() != publishedMode {
					t.Fatal("published executable mode differs", err)
				}
				return
			}
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			if _, err := Run(ctx, config); err == nil {
				t.Fatal("public build accepted compiler-selected owner without required metadata", name)
			}
		})
	}
}

// full_only: false
func TestRunRefusesUnsupportedExecutingCompilerBeforeSourceSelection(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, version := range []string{"go1.27.0", "go1.27.2", "devel go1.27.3"} {
		t.Run(version, func(t *testing.T) {
			config := publicBuildFixtureConfig(t, t.TempDir(), nil)
			publicBuildGoCommand(t, version, "")
			marker, err := Run(t.Context(), config)
			if err == nil || err.Error() != "go 1.27.3 is required" || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
				t.Fatal("unsupported executing compiler did not refuse before source selection", marker, err)
			}
			if _, err := os.Lstat(filepath.Join(config.Output, "build.json")); !os.IsNotExist(err) {
				t.Fatal("unsupported executing compiler published a build marker", err)
			}
		})
	}
}

// full_only: false
func TestRunRefusesCompiledCompilerMismatch(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	config, metadata, _, _ := archiveBuildFixture(t, "generic-json", "1.2.3")
	executable := publicBuildChangedCompiler(t, config, metadata, "go1.27.0")
	config.Output = t.TempDir()
	publicBuildGoCommand(t, "go1.27.3", executable)
	marker, err := Run(t.Context(), config)
	if err == nil || err.Error() != "compiled toolchain differs from Go 1.27.3" || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
		t.Fatal("compiled compiler mismatch did not refuse", marker, err)
	}
	if _, err := os.Lstat(filepath.Join(config.Output, "build.json")); !os.IsNotExist(err) {
		t.Fatal("compiled compiler mismatch published a build marker", err)
	}
}

func publicBuildGoCommand(t *testing.T, version, executable string) {
	t.Helper()
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	const script = `#!/bin/sh
if [ -n "$ENKV_TEST_GO_COMMAND_LOG" ]; then
  printf '%s\n' "$1" >> "$ENKV_TEST_GO_COMMAND_LOG"
fi
if [ "$1" = list ] && [ -n "$ENKV_TEST_GO_BLOCK_READY" ]; then
  printf ready > "$ENKV_TEST_GO_BLOCK_READY"
  kill -STOP "$$"
  exit 1
fi
if [ "$1 $2" = 'env GOVERSION' ]; then
  printf '%s\n' "$ENKV_TEST_GO_VERSION"
  exit 0
fi
if [ "$1" = build ] && [ -n "$ENKV_TEST_GO_EXECUTABLE" ]; then
  cp "$ENKV_TEST_GO_EXECUTABLE" "$6" && chmod 0775 "$6"
  exit $?
fi
if [ "$1" = build ] && [ -n "$ENKV_TEST_DESCRIPTOR_CHANGE" ]; then
  "$ENKV_TEST_REAL_GO" "$@" || exit $?
  printf '\n' >> "$ENKV_TEST_DESCRIPTOR_CHANGE"
  exit $?
fi
exec "$ENKV_TEST_REAL_GO" "$@"
`
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_TEST_REAL_GO", goPath)
	t.Setenv("ENKV_TEST_GO_VERSION", version)
	t.Setenv("ENKV_TEST_GO_EXECUTABLE", executable)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func publicBuildChangedCompiler(t *testing.T, config Config, metadata artifact.Metadata, version string) string {
	t.Helper()
	identity, err := metadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(config.Output, "builds", identity.String(), "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	// Equal-length replacement preserves the executable layout. Read the result
	// independently to ensure this fixture reaches the compiler-identity gate.
	if metadata.Toolchain != "go1.27.3" || len(version) != len(metadata.Toolchain) || !bytes.Contains(body, []byte(metadata.Toolchain)) {
		t.Fatal("compiler mismatch fixture requires an exact supported build")
	}
	body = bytes.ReplaceAll(body, []byte(metadata.Toolchain), []byte(version))
	executable := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(executable, body, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil || info.GoVersion != version {
		t.Fatal("compiler mismatch fixture has the wrong build identity", err)
	}
	return executable
}

// full_only: false
func TestRunAcceptsSupportedLicenseFilenamesAndBindsTheirBytes(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			root := t.TempDir()
			for path, body := range map[string]string{name: "license", "go.mod": "module example.test/main\n\ngo 1.27.0\n", "main.go": "package main\nfunc main(){}\n"} {
				if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			config := publicBuildFixtureConfig(t, root, []string{root})
			first, err := Run(ctx, config)
			if err != nil {
				t.Fatal("supported regular license refused", err)
			}
			before, err := artifact.VerifyBuild(ctx, config.Output)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte("changed license"), 0600); err != nil {
				t.Fatal(err)
			}
			second, err := Run(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			after, err := artifact.VerifyBuild(ctx, config.Output)
			if err != nil {
				t.Fatal(err)
			}
			if first.Artifact == second.Artifact || before.Sources[0].Digest == after.Sources[0].Digest {
				t.Fatal("public build omitted changed license bytes", name)
			}
		})
	}
}

// full_only: false
func TestRunRejectsInvalidPresentLicenseAliasDespiteValidLicense(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			root := t.TempDir()
			for name, body := range map[string]string{"LICENSE": "valid license", "go.mod": "module example.test/main\n\ngo 1.27.0\n", "main.go": "package main\nfunc main(){}\n"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(root, "LICENSE.txt")
			var err error
			if kind == "directory" {
				err = os.Mkdir(alias, 0700)
			} else {
				err = os.Symlink(filepath.Join(root, "LICENSE"), alias)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Run(ctx, publicBuildFixtureConfig(t, root, []string{root})); err == nil {
				t.Fatal("public build ignored an invalid present license alias", kind)
			}
		})
	}
}

// full_only: false
func TestRunRequiresModuleFileForUnusedOwnerAndLicenseWhenImported(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	helper := t.TempDir()
	const helperModule = "example.test/helper"
	helperMod := []byte("module " + helperModule + "\n\ngo 1.27.0\n")
	for path, body := range map[string]string{filepath.Join(root, "LICENSE"): "L", filepath.Join(root, "go.mod"): "module example.test/main\n\ngo 1.27.0\n", filepath.Join(root, "main.go"): "package main\nfunc main(){}\n", filepath.Join(helper, "go.mod"): string(helperMod), filepath.Join(helper, "helper.go"): "package helper\nimport \"os\"\nfunc init(){if len(os.Args)==0{panic(\"helper\")}}\n"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root, helper})
	if _, err := Run(ctx, config); err != nil {
		t.Fatal("unused module owner without a license was refused", err)
	}
	if err := os.Remove(filepath.Join(helper, "go.mod")); err != nil {
		t.Fatal(err)
	}
	_, missingModuleErr := Run(ctx, config)
	if err := os.WriteFile(filepath.Join(helper, "go.mod"), helperMod, 0600); err != nil {
		t.Fatal(err)
	}
	if missingModuleErr == nil {
		t.Error("public build accepted unused local owner without go.mod")
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nimport _ \""+helperModule+"\"\nfunc main(){}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, config); err == nil {
		t.Error("public build accepted imported helper without LICENSE")
	}
	if err := os.WriteFile(filepath.Join(helper, "LICENSE"), []byte("L"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, config); err != nil {
		t.Fatal("complete imported helper refused", err)
	}
}

func cleanPublicBuildEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
}
func publicBuildFixtureConfig(t *testing.T, root string, owners []string) Config {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "go.work")
	body := "go 1.27.0\n\nuse (\n"
	for _, owner := range owners {
		body += fmt.Sprintf("\t%q\n", filepath.ToSlash(owner))
	}
	body += ")\n"
	if err := os.WriteFile(workspace, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(output, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	descriptor := writeBuildDescriptor(t, root, "generic-json", "manifest-generator", "1.2.3")
	return Config{Directory: root, Descriptor: descriptor, Command: ".", Output: output, Workspace: workspace}
}

func writeBuildDescriptor(t *testing.T, root, name, role, version string) string {
	t.Helper()
	descriptor := artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: name, Role: role, Version: version, Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest{1}.String(), Version: 9}}
	route, err := credentialroute.Encode(credentialroute.Route{Schema: credentialroute.Schema, ContractID: [32]byte{2}, Mode: credentialroute.ModeEnvironment, Names: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	switch role {
	case "generator":
		descriptor.Generator = &artifact.GeneratorDeclaration{ConfigContractID: artifact.Digest{3}, CredentialRoute: route}
	case "output":
		descriptor.Output = &artifact.OutputDeclaration{ConfigContractID: "private-output/v1", CredentialRoute: route}
	case "manifest-generator":
		descriptor.Manifest = &artifact.ManifestDeclaration{ConfigContractID: "private-settings/v1", FormatContractID: "private-format/v1"}
	}
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "enkv-plugin.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bindBuildMetadataFixture(t *testing.T, m artifact.Metadata) (artifact.Metadata, []byte) {
	t.Helper()
	descriptor, err := m.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := artifact.EncodeDependency(m.BuildFacts())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.DependencyID(m.Role, dependency)
	if err != nil {
		t.Fatal(err)
	}
	execution := artifact.ExecutionFacts{Module: m.MainModule, Command: m.Command, GoVersion: m.Toolchain, NativeTuple: m.Platform}
	facts, err := artifact.BindManifestFacts(artifact.ManifestFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, m.Executable.SHA256, m.Executable.Length, identity)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	m.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}
	return m, dependency
}

// full_only: false
func TestRunRefusesLibraryBeforeSourceCaptureAndCompilation(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	root := t.TempDir()
	for path, body := range map[string]string{"go.mod": "module private.example/library\n\ngo 1.27.0\n", "LICENSE": "local author license\n", "author.go": "package library\n"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root})
	log := filepath.Join(t.TempDir(), "go-commands")
	publicBuildGoCommand(t, "go1.27.3", "")
	t.Setenv("ENKV_TEST_GO_COMMAND_LOG", log)
	for _, defect := range []bool{true, false} {
		t.Run(map[bool]string{true: "source-capture-defect", false: "valid-library-source"}[defect], func(t *testing.T) {
			assembly := filepath.Join(root, "selected.s")
			if defect {
				if err := os.WriteFile(assembly, []byte("// selected local assembly\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(assembly); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(log, nil, 0600); err != nil {
				t.Fatal(err)
			}
			marker, err := Run(t.Context(), config)
			if err == nil || err.Error() != "plugin build: command.package: main package required" || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
				t.Error("library did not fail at the package-kind boundary", marker, err)
			}
			body, readErr := os.ReadFile(log)
			if readErr != nil || strings.Contains(string(body), "build\n") {
				t.Error("library reached compilation", string(body), readErr)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(root, "author.go"), []byte("package main\nfunc main(){panic(\"must not execute\")}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "selected.s"), []byte("// selected local assembly\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), config); err == nil || err.Error() != "local and first-party assembly inputs are unsupported" {
		t.Fatal("main control did not reach source capture", err)
	}
	if err := os.Remove(filepath.Join(root, "selected.s")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	config.Command = "private.example/library"
	marker, err := Run(t.Context(), config)
	if err != nil || marker.Artifact.IsZero() {
		t.Fatal("qualified main did not build", err)
	}
	body, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(body), "build\n") {
		t.Fatal("main control did not enter the compiler", string(body), err)
	}
}

// full_only: false
func TestRunPreservesCallerCancellation(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	root := t.TempDir()
	for path, body := range map[string]string{"go.mod": "module private.example/cancelled\n\ngo 1.27.0\n", "LICENSE": "local author license\n", "main.go": "package main\nfunc main(){}\n"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if marker, err := Run(ctx, config); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
		t.Fatal("initial cancellation lost its cause", marker, err)
	}
	expired, stop := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer stop()
	if marker, err := Run(expired, config); !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
		t.Fatal("initial deadline lost its cause", marker, err)
	}
	publicBuildGoCommand(t, "go1.27.3", "")
	ready := filepath.Join(t.TempDir(), "selected-child-ready")
	t.Setenv("ENKV_TEST_GO_BLOCK_READY", ready)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		marker artifact.BuildMarker
		err    error
	}
	joined := make(chan result, 1)
	go func() { marker, err := Run(ctx, config); joined <- result{marker, err} }()
	limit := time.NewTimer(10 * time.Second)
	defer limit.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case <-limit.C:
			cancel()
			<-joined
			t.Fatal("selected Go child did not enter")
		case <-tick.C:
		}
	}
	cancel()
	var got result
	select {
	case got = <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled selected child did not join")
	}
	if !errors.Is(got.err, context.Canceled) || !reflect.DeepEqual(got.marker, artifact.BuildMarker{}) {
		t.Fatal("selected-child cancellation lost its cause", got.marker, got.err)
	}
	if _, err := os.Stat(filepath.Join(config.Output, "build.json")); !os.IsNotExist(err) {
		t.Fatal("cancelled build published a marker", err)
	}
}

// full_only: false
func TestRunRefusesExecutableMainMismatch(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	config, metadata, _, _ := archiveBuildFixture(t, "generic-json", "1.2.3")
	identity, err := metadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(config.Output, "builds", identity.String(), "plugin")
	other := filepath.Join(config.Directory, "cmd", "other")
	if err := os.MkdirAll(other, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "main.go"), []byte("package main\nfunc main(){panic(\"must not execute\")}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config.Command = "./cmd/other"
	config.Output = t.TempDir()
	publicBuildGoCommand(t, "go1.27.3", executable)
	marker, err := Run(t.Context(), config)
	if err == nil || err.Error() != "selected main differs from executable main" || !reflect.DeepEqual(marker, artifact.BuildMarker{}) {
		t.Fatal("early package admission replaced the executable-main check", marker, err)
	}
	if _, err := os.Lstat(filepath.Join(config.Output, "build.json")); !os.IsNotExist(err) {
		t.Fatal("mismatched main published a marker", err)
	}
}
