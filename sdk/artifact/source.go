package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/scanner"
)

// SourceModule preserves the selected module facts from go list. Dir names its
// source directory; Replace names the actual source owner when present.
type SourceModule struct {
	Path, Version, Sum, Dir string
	Main                    bool
	Replace                 *SourceModule
}

// SourcePackage preserves one go list package and compiler-selected filenames.
// Module names its source owner; Standard packages use the declared toolchain.
// Unsupported compiler input families cause source capture to refuse.
type SourcePackage struct {
	Dir, ImportPath, Name                                                                                               string
	Standard                                                                                                            bool
	Module                                                                                                              *SourceModule
	GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles []string
}

// CaptureSources hashes the complete selected supported module inputs. Standard
// library inputs belong to the declared stock toolchain, not a module source set.
func CaptureSources(ctx context.Context, role string, packages []SourcePackage) ([]Source, error) {
	return CaptureSourcesForModules(ctx, role, packages, nil)
}

// SourceLicenseFiles returns the supported module-root license filenames.
func SourceLicenseFiles() [3]string {
	return [3]string{"LICENSE", "LICENSE.txt", "LICENSE.md"}
}

// SourceMetadataFiles returns the module-root metadata filenames bound by source capture.
func SourceMetadataFiles() [21]string {
	var files [21]string
	legal := sourceLegalNames()
	copy(files[:], legal[:])
	files[19], files[20] = "go.mod", "go.sum"
	return files
}

// CaptureSourcesForModules also binds local resolved owners which have no
// selected package. Such owners contribute their module and legal files, and no
// invented compiler inputs.
func CaptureSourcesForModules(ctx context.Context, role string, packages []SourcePackage, modules []SourceModule) ([]Source, error) {
	selected := map[string]bool{}
	for _, pkg := range packages {
		if pkg.Module != nil {
			selected[pkg.Module.Path] = true
		}
	}
	packages = slices.Clone(packages)
	for i := range modules {
		module := &modules[i]
		if selected[module.Path] {
			continue
		}
		directory := ""
		if module.Replace != nil && module.Replace.Version == "" {
			directory = module.Replace.Dir
		} else if module.Main && module.Version == "" && module.Sum == "" && module.Replace == nil {
			directory = module.Dir
		}
		if directory != "" {
			packages = append(packages, SourcePackage{Dir: directory, Module: module})
			selected[module.Path] = true
		}
	}

	domains := map[string]string{"generator": "ENKV/GENERATOR/v1/source-set", "output": "ENKV/OUTPUT/v1/source-set", "manifest-generator": "ENKV/MANIFEST/v1/source-set"}
	domain, ok := domains[role]
	if !ok {
		return nil, ErrRecord
	}
	type owner struct {
		root  string
		paths map[string]bool
	}
	owners := map[string]*owner{}
	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil || pkg.Module.Path == "" {
			return nil, errors.New("selected package has no source owner")
		}
		module := pkg.Module
		actual := module
		if module.Replace != nil {
			actual = module.Replace
		}
		root, err := filepath.EvalSymlinks(actual.Dir)
		if err != nil {
			return nil, fmt.Errorf("source owner %s: %w", module.Path, err)
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		directory, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil {
			return nil, err
		}
		if !inside(root, directory) {
			return nil, errors.New("source package escapes module owner")
		}
		current := owners[module.Path]
		if current == nil {
			if len(owners) >= maxSourceOwners {
				return nil, errors.New("source owner count refused")
			}
			current = &owner{root: root, paths: map[string]bool{}}
			owners[module.Path] = current
		} else if current.root != root {
			return nil, errors.New("source owner has conflicting roots")
		}
		if len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.MFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.SysoFiles) != 0 {
			return nil, errors.New("unsupported selected compiler input")
		}
		extended := !strings.HasPrefix(module.Path, "enkv.sh/") && !module.Main && actual.Version != "" && actual.Version != "(devel)"
		if !extended && len(pkg.SFiles)+len(pkg.HFiles) != 0 {
			return nil, errors.New("local and first-party assembly inputs are unsupported")
		}
		headers := map[string]bool{}
		for _, name := range pkg.HFiles {
			if !simpleName(name) {
				return nil, errors.New("assembler header name refused")
			}
			headers[name] = true
		}
		for _, names := range [][]string{pkg.GoFiles, pkg.SFiles, pkg.HFiles, pkg.EmbedFiles} {
			for _, name := range names {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !safeRelative(name) {
					return nil, errors.New("source input path refused")
				}
				path := filepath.Join(directory, filepath.FromSlash(name))
				relative, err := filepath.Rel(root, path)
				if err != nil || !inside(root, path) {
					return nil, errors.New("source input escapes module owner")
				}
				if err := visitSourceFile(ctx, root, path, nil, nil); err != nil {
					return nil, err
				}
				current.paths[filepath.ToSlash(relative)] = true
			}
		}
		for _, name := range append(slices.Clone(pkg.SFiles), pkg.HFiles...) {
			if err := checkIncludes(ctx, root, directory, name, headers); err != nil {
				return nil, err
			}
		}
		legal, err := sourceLegalPaths(ctx, root, directory, append(selectedSourceFiles(pkg), pkg.EmbedFiles...))
		if err != nil {
			return nil, err
		}
		for _, name := range legal {
			current.paths[name] = true
		}
	}
	if len(owners) == 0 || len(owners) > maxSourceOwners {
		return nil, errors.New("source owner count refused")
	}
	paths := make([]string, 0, len(owners))
	for module := range owners {
		paths = append(paths, module)
	}
	slices.Sort(paths)
	result := make([]Source, 0, len(paths))
	for _, module := range paths {
		owner := owners[module]
		for _, name := range SourceMetadataFiles() {
			path := filepath.Join(owner.root, name)
			if _, err := os.Lstat(path); err == nil {
				owner.paths[name] = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		names := make([]string, 0, len(owner.paths))
		for name := range owner.paths {
			names = append(names, name)
		}
		slices.Sort(names)
		if len(names) == 0 || uint64(len(names)) > math.MaxUint32 {
			return nil, errors.New("source input count refused")
		}
		h := sha256.New()
		h.Write([]byte(domain))
		h.Write([]byte{0})
		if err := sourceBlob(h, []byte(module)); err != nil {
			return nil, err
		}
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(names))))
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := sourceBlob(h, []byte(name)); err != nil {
				return nil, err
			}
			err := visitSourceFile(ctx, owner.root, filepath.Join(owner.root, filepath.FromSlash(name)), func(size uint32) {
				h.Write(binary.BigEndian.AppendUint32(nil, size))
			}, func(body []byte) {
				h.Write(body)
			})
			if err != nil {
				return nil, err
			}
		}
		var digest Digest
		copy(digest[:], h.Sum(nil))
		result = append(result, Source{Module: module, Digest: digest})
	}
	return result, nil
}

func inside(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
func safeRelative(name string) bool {
	return name != "" && !filepath.IsAbs(name) && !strings.Contains(name, "\\") && filepath.ToSlash(filepath.Clean(name)) == name && name != ".." && !strings.HasPrefix(name, "../")
}
func simpleName(name string) bool { return safeRelative(name) && !strings.Contains(name, "/") }
func sourceFile(ctx context.Context, root, path string) ([]byte, error) {
	var body bytes.Buffer
	if err := visitSourceFile(ctx, root, path, nil, func(chunk []byte) { body.Write(chunk) }); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func visitSourceFile(ctx context.Context, root, path string, start func(uint32), consume func([]byte)) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if !inside(root, resolved) {
		return errors.New("source symlink escapes module owner")
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > math.MaxUint32 {
		return errors.New("source file type or length refused")
	}
	file, err := openObservedFile(resolved, info)
	if err != nil {
		return err
	}
	if start != nil {
		start(uint32(info.Size()))
	}
	var count uint64
	chunk := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, file.Close())
		}
		n, readErr := file.Read(chunk)
		if n > 0 {
			if count+uint64(n) > math.MaxUint32 {
				return errors.Join(errors.New("source exceeds framing"), file.Close())
			}
			count += uint64(n)
			if consume != nil {
				consume(chunk[:n])
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return errors.Join(readErr, file.Close())
			}
			break
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	if int64(count) != info.Size() {
		return errors.New("source file changed or exceeds framing")
	}
	return nil
}
func sourceBlob(h hash.Hash, body []byte) error {
	if uint64(len(body)) > math.MaxUint32 {
		return errors.New("source blob exceeds framing")
	}
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(body))))
	h.Write(body)
	return nil
}

func checkIncludes(ctx context.Context, root, directory, name string, headers map[string]bool) error {
	body, err := sourceFile(ctx, root, filepath.Join(directory, name))
	if err != nil {
		return err
	}
	var tokens scanner.Scanner
	tokens.Init(bytes.NewReader(body))
	tokens.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments
	tokens.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	tokens.Error = func(*scanner.Scanner, string) {}
	next := func() rune {
		for {
			token := tokens.Scan()
			if token != scanner.Comment {
				return token
			}
		}
	}
	lineStart, escaped := true, false
	for token := next(); token != scanner.EOF; token = next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if token == '\n' {
			lineStart, escaped = !escaped, false
			continue
		}
		if token == '\\' {
			lineStart, escaped = false, !escaped
			continue
		}
		escaped = false
		if token != '#' {
			lineStart = false
			continue
		}
		if !lineStart {
			return errors.New("nonliteral assembler directive refused")
		}
		lineStart = false
		if next() != scanner.Ident {
			return errors.New("assembler directive refused")
		}
		if tokens.TokenText() != "include" {
			continue
		}
		if next() != scanner.String {
			return errors.New("assembler include directive refused")
		}
		header, err := strconv.Unquote(tokens.TokenText())
		if err != nil || !simpleName(header) {
			return errors.New("assembler include directive refused")
		}
		if headers[header] {
			continue
		}
		if header == "textflag.h" {
			if _, err := os.Lstat(filepath.Join(directory, header)); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
		}
		return errors.New("assembler include is outside selected headers")
	}
	if tokens.ErrorCount != 0 {
		return errors.New("assembler input could not be scanned")
	}
	return nil
}
