// Package build produces complete local plugin builds with a stock Go toolchain.
package build

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"enkv.sh/sdk/artifact"
)

// Config selects a single main package and the author descriptor used to build it.
// Directory, Descriptor, Command and Output are required; the library supplies no
// CLI defaults. Descriptor is relative to Directory unless absolute. Directory and
// Output resolve from the current working directory. Local mode requires an
// absolute Workspace file; Versioned instead disables the workspace and requires
// versioned dependencies without filesystem replacements.
type Config struct {
	Directory, Descriptor, Command, Output, Workspace string
	Versioned                                         bool
}

// Run builds exactly one selected main with stock Go 1.27.3 on darwin/arm64 or
// linux/amd64. It fixes CGO, trimpath and VCS settings, checks the descriptor and
// selected sources before and after compilation, then publishes a complete build.
// It never runs the plugin. A nonnil context controls Go commands and file work;
// errors preserve cancellation where observed. Failure may leave complete build
// bytes or a published marker if later cleanup fails; it does not prove no output.
// Build facts do not prove plugin semantics or native-code confinement.
func Run(ctx context.Context, config Config) (marker artifact.BuildMarker, err error) {
	var zero artifact.BuildMarker
	if ctx == nil {
		return zero, errors.New("plugin build: context: required")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	for _, field := range []struct{ name, value string }{
		{"directory", config.Directory}, {"descriptor", config.Descriptor}, {"command", config.Command}, {"output", config.Output},
	} {
		if field.value == "" {
			return zero, fmt.Errorf("plugin build: %s: required", field.name)
		}
	}
	if strings.Contains(config.Command, "...") || strings.HasPrefix(config.Command, "-") {
		return zero, errors.New("plugin build: command: exact package required")
	}
	directory, err := filepath.Abs(config.Directory)
	if err != nil {
		return zero, err
	}
	output, err := filepath.Abs(config.Output)
	if err != nil {
		return zero, err
	}
	descriptorPath := config.Descriptor
	if !filepath.IsAbs(descriptorPath) {
		descriptorPath = filepath.Join(directory, descriptorPath)
	}
	descriptor, descriptorBefore, err := artifact.ReadDescriptor(ctx, descriptorPath)
	if err != nil {
		return zero, err
	}
	environment, err := buildEnvironment(config)
	if err != nil {
		return zero, err
	}
	version, err := goCommand(ctx, directory, environment, "env", "GOVERSION")
	if err != nil {
		return zero, err
	}
	if strings.TrimSpace(string(version)) != "go1.27.3" {
		return zero, errors.New("go 1.27.3 is required")
	}
	before, modules, err := selectedInputs(ctx, directory, environment, config.Command, config.Versioned)
	if err != nil {
		return zero, err
	}
	if err := requireModuleMetadata(ctx, before, modules); err != nil {
		return zero, err
	}
	sources, err := artifact.CaptureSourcesForModules(ctx, descriptor.Role, before, modules)
	if err != nil {
		return zero, err
	}
	temporary, err := os.MkdirTemp("", "enkv-plugin-build-")
	if err != nil {
		return zero, err
	}
	defer func() {
		if errors.Is(err, errGoCommandUnsettled) {
			err = fmt.Errorf("plugin build scratch retained at %s: %w", temporary, err)
			return
		}
		err = errors.Join(err, os.RemoveAll(temporary))
	}()
	executable := filepath.Join(temporary, "plugin")
	if _, err := goCommand(ctx, directory, environment, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", executable, "--", config.Command); err != nil {
		return zero, err
	}
	if err := os.Chmod(executable, 0700); err != nil {
		return zero, err
	}
	after, afterModules, err := selectedInputs(ctx, directory, environment, config.Command, config.Versioned)
	if err != nil {
		return zero, err
	}
	if err := requireModuleMetadata(ctx, after, afterModules); err != nil {
		return zero, err
	}
	afterSources, err := artifact.CaptureSourcesForModules(ctx, descriptor.Role, after, afterModules)
	if err != nil {
		return zero, err
	}
	_, descriptorAfter, err := artifact.ReadDescriptor(ctx, descriptorPath)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(descriptorBefore, descriptorAfter) {
		return zero, errors.New("author descriptor changed during build")
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(modules, afterModules) || !reflect.DeepEqual(sources, afterSources) {
		return zero, errors.New("selected source inputs changed during build")
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		return zero, err
	}
	if info.GoVersion != "go1.27.3" {
		return zero, errors.New("compiled toolchain differs from Go 1.27.3")
	}
	options, err := artifact.BuildOptions(info)
	if err != nil {
		return zero, err
	}
	compiled, err := artifact.CompiledDependencies(info, sources)
	if err != nil {
		return zero, err
	}
	resolved, err := resolvedDependencies(modules, sources)
	if err != nil {
		return zero, err
	}
	metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: descriptor.Name, Role: descriptor.Role, Version: descriptor.Version, MainModule: info.Main.Path, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: sources, Resolved: resolved, Compiled: compiled}
	mainCount := 0
	for _, pkg := range before {
		if pkg.Name == "main" && pkg.ImportPath == info.Path && pkg.Module != nil && pkg.Module.Path == info.Main.Path {
			mainCount++
		}
	}
	if mainCount != 1 {
		return zero, errors.New("selected main differs from executable main")
	}
	if err := artifact.VerifyBuildInfo(info, metadata.BuildFacts()); err != nil {
		return zero, err
	}
	metadata.Executable, err = artifact.ExecutableIdentity(ctx, executable)
	if err != nil {
		return zero, err
	}
	dependency, err := artifact.EncodeDependency(metadata.BuildFacts())
	if err != nil {
		return zero, err
	}
	identity, err := artifact.DependencyID(descriptor.Role, dependency)
	if err != nil {
		return zero, err
	}
	execution := artifact.ExecutionFacts{Module: metadata.MainModule, Command: metadata.Command, GoVersion: metadata.Toolchain, NativeTuple: metadata.Platform}
	var facts any
	switch descriptor.Role {
	case "generator":
		facts, err = artifact.BindGeneratorFacts(artifact.GeneratorFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, metadata.Executable.SHA256, metadata.Executable.Length, identity)
	case "output":
		facts, err = artifact.BindOutputFacts(artifact.OutputFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, metadata.Executable.SHA256, metadata.Executable.Length, identity)
	case "manifest-generator":
		facts, err = artifact.BindManifestFacts(artifact.ManifestFacts{Schema: artifact.FamilySchema, Descriptor: descriptor, ExecutionFacts: execution}, metadata.Executable.SHA256, metadata.Executable.Length, identity)
	}
	if err != nil {
		return zero, err
	}
	body, err := json.Marshal(facts)
	if err != nil {
		return zero, err
	}
	metadata.Family = &artifact.Family{Schema: artifact.FamilySchema, Facts: body, Dependency: artifact.DigestLength{SHA256: artifact.Hash(dependency), Length: uint64(len(dependency))}}
	return artifact.PublishBuild(ctx, output, metadata, executable, dependency)
}

func buildEnvironment(config Config) ([]string, error) {
	if runtime.GOOS+"/"+runtime.GOARCH != "darwin/arm64" && runtime.GOOS+"/"+runtime.GOARCH != "linux/amd64" {
		return nil, errors.New("unsupported native platform")
	}
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		if os.Getenv(key) != "" {
			return nil, fmt.Errorf("custom compiler input %s is unsupported", key)
		}
	}
	workspace := "off"
	if config.Versioned {
		if config.Workspace != "" {
			return nil, errors.New("versioned mode cannot select a workspace")
		}
	} else {
		if config.Workspace == "" || config.Workspace == "off" || !filepath.IsAbs(config.Workspace) {
			return nil, errors.New("local mode requires an explicit absolute workspace file")
		}
		info, err := os.Lstat(config.Workspace)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("workspace file type refused")
		}
		workspace = config.Workspace
	}
	fixed := map[string]string{"GOENV": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOWORK": workspace, "GOFLAGS": "", "GOEXPERIMENT": "", "CGO_ENABLED": "0", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0"}
	environment := make([]string, 0, len(os.Environ())+len(fixed))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, override := fixed[key]; !override {
			environment = append(environment, entry)
		}
	}
	for key, value := range fixed {
		environment = append(environment, key+"="+value)
	}
	slices.Sort(environment)
	return environment, nil
}

type commandBuffer struct{ buffer bytes.Buffer }

var errGoCommandUnsettled = errors.New("go command work did not settle")

// Write refuses an entire chunk that would exceed the Go-command output bound;
// stdout and diagnostics cannot grow without limit while the command runs.
func (b *commandBuffer) Write(body []byte) (int, error) {
	if b.buffer.Len()+len(body) > 64<<20 {
		return 0, errors.New("go command output exceeds limit")
	}
	return b.buffer.Write(body)
}
func goCommand(ctx context.Context, directory string, environment []string, args ...string) ([]byte, error) {
	command := exec.Command("go", args...)
	command.Dir = directory
	command.Env = make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "PWD=") {
			command.Env = append(command.Env, entry)
		}
	}
	// With an explicit environment, os/exec does not update PWD for Dir. Keep
	// Go's logical directory consistent with workspace paths through symlinks.
	command.Env = append(command.Env, "PWD="+directory)
	var output, diagnostic commandBuffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	settled, err := runGoCommand(ctx, command)
	if !settled {
		return nil, fmt.Errorf("go %s: %w", args[0], errors.Join(errGoCommandUnsettled, err))
	}
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", args[0], err, strings.TrimSpace(diagnostic.buffer.String()))
	}
	return output.buffer.Bytes(), nil
}
func selectedInputs(ctx context.Context, directory string, environment []string, command string, versioned bool) ([]artifact.SourcePackage, []artifact.SourceModule, error) {
	body, err := goCommand(ctx, directory, environment, "list", "-mod=readonly", "-trimpath", "-buildvcs=false", "-deps", "-json", "--", command)
	if err != nil {
		return nil, nil, err
	}
	var packages []artifact.SourcePackage
	selected, main := 0, false
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		var pkg struct {
			artifact.SourcePackage
			DepOnly bool
		}
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if !pkg.DepOnly {
			selected++
			main = pkg.Name == "main"
		}
		packages = append(packages, pkg.SourcePackage)
	}
	if selected != 1 {
		return nil, nil, errors.New("plugin build: command.package: exactly one package required")
	}
	if !main {
		return nil, nil, errors.New("plugin build: command.package: main package required")
	}
	body, err = goCommand(ctx, directory, environment, "list", "-mod=readonly", "-m", "-json", "all")
	if err != nil {
		return nil, nil, err
	}
	var modules []artifact.SourceModule
	decoder = json.NewDecoder(bytes.NewReader(body))
	for {
		var module artifact.SourceModule
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if len(modules) >= 256 {
			return nil, nil, errors.New("resolved module count refused")
		}
		if versioned && (!module.Main && (module.Version == "" || module.Version == "(devel)") || module.Replace != nil && (module.Replace.Version == "" || module.Replace.Version == "(devel)")) {
			return nil, nil, errors.New("versioned dependencies require real versions")
		}
		modules = append(modules, module)
	}
	slices.SortFunc(modules, func(a, b artifact.SourceModule) int { return strings.Compare(a.Path, b.Path) })
	owners := map[string]*artifact.SourceModule{}
	for i := range modules {
		if _, exists := owners[modules[i].Path]; exists {
			return nil, nil, errors.New("duplicate resolved module")
		}
		owners[modules[i].Path] = &modules[i]
	}

	for i := range packages {
		pkg := &packages[i]
		if !pkg.Standard {
			if pkg.Module == nil {
				return nil, nil, errors.New("selected package has no module")
			}
			owner, ok := owners[pkg.Module.Path]
			if !ok || !reflect.DeepEqual(*owner, *pkg.Module) {
				return nil, nil, errors.New("selected package source owner differs from resolved module")
			}
			pkg.Module = owner
		}
	}
	return packages, modules, nil
}
func resolvedDependencies(modules []artifact.SourceModule, sources []artifact.Source) ([]artifact.Dependency, error) {
	digests := map[string]artifact.Digest{}
	for _, source := range sources {
		digests[source.Module] = source.Digest
	}
	result := make([]artifact.Dependency, 0, len(modules))
	for _, module := range modules {
		row := artifact.Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if module.Replace != nil {
			replacement := module.Replace
			if replacement.Replace != nil {
				return nil, errors.New("nested module replacement refused")
			}
			row.Replacement = &artifact.Replacement{Path: replacement.Path, Version: replacement.Version, Sum: replacement.Sum}
			if replacement.Version == "" {
				digest, ok := digests[module.Path]
				if !ok {
					return nil, errors.New("resolved local replacement has no selected source digest")
				}
				row.Replacement.SourceDigest = digest
			}
		}
		result = append(result, row)
	}
	return result, nil
}

func requireModuleMetadata(ctx context.Context, packages []artifact.SourcePackage, modules []artifact.SourceModule) error {
	selected := make(map[string]bool)
	for _, pkg := range packages {
		if !pkg.Standard && pkg.Module != nil {
			selected[pkg.Module.Path] = true
		}
	}
	for _, module := range modules {
		compiled := selected[module.Path]
		local := module.Main && module.Version == "" && module.Sum == "" && module.Replace == nil
		actual := module
		if module.Replace != nil {
			actual = *module.Replace
			local = actual.Version == ""
		}
		if !compiled && !local {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(filepath.Join(actual.Dir, "go.mod"))
		if err != nil {
			return fmt.Errorf("required source file go.mod for %s: %w", module.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("required source file go.mod for %s is not regular", module.Path)
		}
		if compiled {
			hasLicenseFile := false
			for _, name := range artifact.SourceLicenseFiles() {
				if err := ctx.Err(); err != nil {
					return err
				}
				info, err := os.Lstat(filepath.Join(actual.Dir, name))
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return fmt.Errorf("source license file %s for %s: %w", name, module.Path, err)
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("source license file %s for %s is not regular", name, module.Path)
				}
				hasLicenseFile = true
			}
			if !hasLicenseFile {
				return fmt.Errorf("source owner %s requires LICENSE, LICENSE.txt or LICENSE.md", module.Path)
			}
		}
	}
	return nil
}
