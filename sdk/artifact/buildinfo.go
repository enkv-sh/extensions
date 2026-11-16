package artifact

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"unicode/utf8"
)

// BuildOptions captures every admitted build setting from the executable.
func BuildOptions(info *debug.BuildInfo) ([]BuildOption, error) {
	if info == nil {
		return nil, errors.New("build information is missing")
	}
	options, err := CaptureBuildOptions(info)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, setting := range info.Settings {
		if seen[setting.Key] {
			return nil, errors.New("duplicate build setting")
		}
		seen[setting.Key] = true
		valid := false
		switch setting.Key {
		case "-buildmode":
			valid = setting.Value == "exe"
		case "-compiler":
			valid = setting.Value == "gc"
		case "-trimpath":
			valid = setting.Value == "true"
		case "CGO_ENABLED":
			valid = setting.Value == "0"
		case "GOOS":
			valid = setting.Value == "darwin" || setting.Value == "linux"
		case "GOARCH":
			valid = setting.Value == "arm64" || setting.Value == "amd64"
		case "GOAMD64":
			valid = setting.Value == "v1"
		case "GOARM64":
			valid = setting.Value == "v8.0"
		case "DefaultGODEBUG":
			valid = true
		}
		if !valid {
			return nil, fmt.Errorf("unsupported build setting %q", setting.Key)
		}
	}
	for _, key := range []string{"-buildmode", "-compiler", "-trimpath", "CGO_ENABLED", "GOOS", "GOARCH"} {
		if !seen[key] {
			return nil, fmt.Errorf("required build setting %q is missing", key)
		}
	}
	return options, nil
}

// CaptureBuildOptions preserves the exact bounded settings without deciding a
// producer's permitted construction. BuildOptions enforces the public tool's
// stock production policy.
func CaptureBuildOptions(info *debug.BuildInfo) ([]BuildOption, error) {
	if info == nil || len(info.Settings) > maxBuildOptions {
		return nil, errors.New("build settings count refused")
	}
	options := make([]BuildOption, 0, len(info.Settings))
	seen := map[string]bool{}
	for _, setting := range info.Settings {
		if !utf8.ValidString(setting.Key) || !utf8.ValidString(setting.Value) || setting.Key == "" || len(setting.Key) > 1024 || len(setting.Value) > 1024 || strings.ContainsRune(setting.Key, 0) || strings.ContainsRune(setting.Value, 0) || seen[setting.Key] {
			return nil, errors.New("build setting refused")
		}
		seen[setting.Key] = true
		options = append(options, BuildOption{Name: setting.Key, Value: setting.Value})
	}
	slices.SortFunc(options, func(a, b BuildOption) int { return strings.Compare(a.Name, b.Name) })
	return options, nil
}

// CompiledDependencies preserves actual debug/buildinfo representations and
// attaches only already bound local source digests.
func CompiledDependencies(info *debug.BuildInfo, sources []Source) ([]Dependency, error) {
	if info == nil || len(sources) > maxSourceOwners {
		return nil, errors.New("build information or source count refused")
	}
	sourceMap := map[string]Digest{}
	for _, source := range sources {
		if _, ok := sourceMap[source.Module]; ok {
			return nil, ErrRecord
		}
		sourceMap[source.Module] = source.Digest
	}
	modules := make([]*debug.Module, 0, len(info.Deps)+1)
	modules = append(modules, &info.Main)
	modules = append(modules, info.Deps...)
	if len(modules) > maxCompiledModules {
		return nil, errors.New("compiled module count refused")
	}
	result := make([]Dependency, 0, len(modules))
	seen := map[string]bool{}
	for _, module := range modules {
		if module == nil || module.Path == "" || seen[module.Path] {
			return nil, errors.New("compiled module set refused")
		}
		seen[module.Path] = true
		source, ok := sourceMap[module.Path]
		if !ok || source.IsZero() {
			return nil, errors.New("compiled module source is missing")
		}
		row := Dependency{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if module.Replace != nil {
			replacement := module.Replace
			if replacement.Replace != nil {
				return nil, errors.New("nested module replacement refused")
			}
			row.Replacement = &Replacement{Path: replacement.Path, Version: replacement.Version, Sum: replacement.Sum}
			if replacement.Version == "(devel)" && replacement.Sum == "" {
				row.Replacement.SourceDigest = source
			}
		}
		result = append(result, row)
	}
	slices.SortFunc(result, func(a, b Dependency) int { return strings.Compare(a.Path, b.Path) })
	return result, nil
}

// VerifyBuildInfo compares executable toolchain, main, platform, exact settings
// and compiled closure with supplied build facts, including resolved owner relations.
// It does not authenticate the executable, recapture source bytes or impose the
// stock-builder policy; use BuildOptions for that policy.
func VerifyBuildInfo(info *debug.BuildInfo, facts BuildFacts) error {
	if info == nil || info.GoVersion != facts.Toolchain || info.Path != facts.Command || info.Main.Path != facts.MainModule {
		return errors.New("executable build identity differs")
	}
	options, err := CaptureBuildOptions(info)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(options, facts.BuildOptions) {
		return errors.New("executable build options differ")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"]+"/"+settings["GOARCH"] != facts.Platform {
		return errors.New("executable platform differs")
	}
	compiled, err := CompiledDependencies(info, facts.Sources)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(compiled, facts.Compiled) {
		return errors.New("executable compiled module set differs")
	}
	resolved := map[string]Dependency{}
	for _, row := range facts.Resolved {
		if _, exists := resolved[row.Path]; exists {
			return ErrRecord
		}
		resolved[row.Path] = row
	}
	sources := map[string]Digest{}
	for _, row := range facts.Sources {
		sources[row.Module] = row.Digest
	}
	for _, row := range compiled {
		owner, ok := resolved[row.Path]
		if !ok {
			return errors.New("compiled module has no resolved owner")
		}
		if !resolvedMatchesCompiled(owner, row, sources[row.Path], row.Path == facts.MainModule) {
			return errors.New("resolved and compiled module representations differ")
		}
	}
	return nil
}

func resolvedMatchesCompiled(resolved, compiled Dependency, source Digest, main bool) bool {
	if resolved.Path != compiled.Path {
		return false
	}
	if resolved.Replacement == nil && compiled.Replacement == nil {
		if resolved.Version == compiled.Version && resolved.Sum == compiled.Sum {
			return true
		}
		return resolved.Version == "" && resolved.Sum == "" && compiled.Version == "(devel)" && compiled.Sum == "" && !source.IsZero()
	}
	if resolved.Replacement == nil || compiled.Replacement == nil {
		return false
	}
	if resolved.Version != compiled.Version || resolved.Sum != compiled.Sum {
		if !main || resolved.Version != "" || resolved.Sum != "" || compiled.Version != "(devel)" || compiled.Sum != "" {
			return false
		}
	}
	a, b := resolved.Replacement, compiled.Replacement
	if a.Path != b.Path || a.SourceDigest != b.SourceDigest {
		return false
	}
	if a.Version == "" && a.Sum == "" {
		return b.Version == "(devel)" && b.Sum == "" && a.SourceDigest == source && !source.IsZero()
	}
	return a.Version == b.Version && a.Sum == b.Sum && a.SourceDigest.IsZero()
}

// ExecutableIdentity measures a regular executable without running it.
func ExecutableIdentity(ctx context.Context, path string) (DigestLength, error) {
	file, before, err := openExecutable(ctx, path)
	if err != nil {
		return DigestLength{}, err
	}
	identity, readErr := executableIdentity(ctx, file, before.Size())
	if err := errors.Join(readErr, checkObservedPath(path, before), file.Close()); err != nil {
		return DigestLength{}, err
	}
	return identity, nil
}

func openExecutable(ctx context.Context, path string) (*os.File, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || before.Mode().Perm()&0022 != 0 || before.Size() < 1 || before.Size() > MaxExecutableBytes {
		return nil, nil, errors.New("executable type, mode or size refused")
	}
	file, err := openObservedFile(path, before)
	return file, before, err
}

func executableIdentity(ctx context.Context, file *os.File, expectedSize int64) (DigestLength, error) {
	var result DigestLength
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			count += int64(n)
			if count > MaxExecutableBytes {
				return result, errors.New("executable exceeds limit")
			}
			h.Write(buffer[:n])
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return result, readErr
			}
			break
		}
	}
	if count != expectedSize {
		return result, errors.New("executable changed while measuring")
	}
	copy(result.SHA256[:], h.Sum(nil))
	result.Length = uint64(count)
	return result, nil
}

// VerifyExecutable validates metadata, measures one opened regular executable and
// checks its build information and observed path identity. It requires a nonnil
// context, preserves cancellation errors, and never executes the file. Success
// does not establish source trust or a source-to-binary proof.
func VerifyExecutable(ctx context.Context, path string, metadata Metadata) (result error) {
	if _, err := EncodeMetadata(metadata); err != nil {
		return err
	}
	file, before, err := openExecutable(ctx, path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	actual, err := executableIdentity(ctx, file, before.Size())
	if err != nil {
		return err
	}
	if actual != metadata.Executable {
		return errors.New("executable digest or length differs")
	}
	info, err := buildinfo.Read(io.NewSectionReader(contextReaderAt{ctx, file}, 0, before.Size()))
	if err != nil {
		return errors.Join(err, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(VerifyBuildInfo(info, metadata.BuildFacts()), checkObservedPath(path, before))
}

type contextReaderAt struct {
	ctx    context.Context
	reader io.ReaderAt
}

// ReadAt checks cancellation before build-information reads of the held file.
func (r contextReaderAt) ReadAt(body []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.ReadAt(body, offset)
}
