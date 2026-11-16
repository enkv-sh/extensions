package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
)

// CollectLegalFiles collects supported legal files, all Go source comments and
// leading native source comments from selected inputs and their ancestors, plus
// the Go toolchain's licence. It does not classify licences or inspect unused trees.
func CollectLegalFiles(ctx context.Context, packages []SourcePackage, mainModule, goRoot string) (map[string][]byte, error) {
	if goRoot == "" {
		return nil, errors.New("go toolchain directory is required")
	}
	owners := map[string]SourceModule{}
	legalPaths := map[string]map[string]bool{}
	commentPaths := map[string]map[string]bool{}
	for _, pkg := range packages {
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil || pkg.Module.Path == "" {
			return nil, errors.New("selected package has no legal source owner")
		}
		if previous, ok := owners[pkg.Module.Path]; ok && !reflect.DeepEqual(previous, *pkg.Module) {
			return nil, errors.New("selected legal source owners differ")
		}
		owners[pkg.Module.Path] = *pkg.Module
		actual := pkg.Module
		if actual.Replace != nil {
			actual = actual.Replace
			if actual.Replace != nil {
				return nil, errors.New("nested legal source replacement refused")
			}
		}
		if actual.Dir == "" || pkg.Dir == "" {
			return nil, errors.New("legal source directory is required")
		}
		root, err := filepath.EvalSymlinks(actual.Dir)
		if err != nil {
			return nil, err
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		directory, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil {
			return nil, err
		}
		sources := selectedSourceFiles(pkg)
		legal, err := sourceLegalPaths(ctx, root, directory, append(slices.Clone(sources), pkg.EmbedFiles...))
		if err != nil {
			return nil, err
		}
		key := pkg.Module.Path
		if legalPaths[key] == nil {
			legalPaths[key], commentPaths[key] = map[string]bool{}, map[string]bool{}
		}
		for _, name := range legal {
			legalPaths[key][name] = true
		}
		for _, name := range sources {
			path := filepath.Join(directory, filepath.FromSlash(name))
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			commentPaths[key][filepath.ToSlash(relative)] = true
		}
	}
	if _, ok := owners[mainModule]; !ok || len(owners) > maxSourceOwners {
		return nil, errors.New("main legal source owner is missing or owner count exceeds limit")
	}
	paths := make([]string, 0, len(owners))
	for path := range owners {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	files := make(map[string][]byte)
	var notices, thirdParty bytes.Buffer
	remaining := int64(MaxArchiveBytes)
	licenses := SourceLicenseFiles()
	for _, path := range paths {
		owner := owners[path]
		actual := owner
		if owner.Replace != nil {
			actual = *owner.Replace
			if actual.Replace != nil {
				return nil, errors.New("nested legal source replacement refused")
			}
		}
		if actual.Dir == "" {
			return nil, fmt.Errorf("legal source directory missing for %s", path)
		}
		root, err := filepath.EvalSymlinks(actual.Dir)
		if err != nil {
			return nil, err
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		hasLicense := false
		names := make([]string, 0, len(legalPaths[path]))
		for name := range legalPaths[path] {
			names = append(names, name)
		}
		slices.Sort(names)
		var mainLicenses = map[string][]byte{}
		for _, name := range names {
			body, present, err := legalFileBytes(ctx, filepath.Join(actual.Dir, name), remaining)
			if err != nil {
				return nil, fmt.Errorf("legal source %s/%s: %w", path, name, err)
			}
			if !present {
				return nil, errors.New("selected legal file disappeared")
			}
			if slices.Contains(licenses[:], name) {
				hasLicense = true
				if path == mainModule {
					mainLicenses[name] = body
				}
			}
			header := legalHeader(owner, name)
			if err := appendLegalSection(&thirdParty, header, body, &remaining); err != nil {
				return nil, err
			}
			if path == mainModule && (name == "NOTICE" || name == "NOTICE.txt" || name == "NOTICE.md") {
				if err := appendLegalSection(&notices, header, body, &remaining); err != nil {
					return nil, err
				}
			}
		}
		if !hasLicense {
			return nil, fmt.Errorf("legal source owner %s requires LICENSE, LICENSE.txt or LICENSE.md", path)
		}
		for _, name := range licenses {
			if body, ok := mainLicenses[name]; ok {
				if int64(len(body)) > remaining {
					return nil, errors.New("legal material exceeds archive limit")
				}
				files["LICENSE"] = bytes.Clone(body)
				remaining -= int64(len(body))
				break
			}
		}
		names = names[:0]
		for name := range commentPaths[path] {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				return nil, err
			}
			if !inside(root, resolved) {
				return nil, errors.New("legal source input escapes module owner")
			}
			body, present, err := legalFileBytes(ctx, resolved, int64(MaxArchiveBytes))
			if err != nil {
				return nil, fmt.Errorf("legal source %s/%s: %w", path, name, err)
			}
			if !present {
				return nil, errors.New("selected source file disappeared")
			}
			comments, err := leadingSourceComments(body)
			if err != nil {
				return nil, err
			}
			if len(comments) != 0 {
				if err := appendLegalSection(&thirdParty, legalHeader(owner, name+" (leading comments)"), comments, &remaining); err != nil {
					return nil, err
				}
			}
			if filepath.Ext(name) == ".go" {
				if err := appendGoComments(ctx, &thirdParty, owner, name, body, len(comments), &remaining); err != nil {
					return nil, err
				}
			}
		}
	}
	goLicense, present, err := legalFileBytes(ctx, filepath.Join(goRoot, "LICENSE"), remaining)
	if err != nil || !present {
		return nil, fmt.Errorf("go toolchain LICENSE is required: %w", errors.Join(ErrRecord, err))
	}
	if err := appendLegalSection(&thirdParty, "Go toolchain\nSource file: LICENSE\n\n", goLicense, &remaining); err != nil {
		return nil, err
	}
	files["THIRD_PARTY_NOTICES.md"] = thirdParty.Bytes()
	if notices.Len() != 0 {
		files["NOTICE"] = notices.Bytes()
	}
	return files, nil
}

func legalHeader(owner SourceModule, name string) string {
	header := fmt.Sprintf("Module: %s\nVersion: %s\n", owner.Path, owner.Version)
	if owner.Replace != nil {
		header += fmt.Sprintf("Replacement: %s\nReplacement version: %s\n", owner.Replace.Path, owner.Replace.Version)
	}
	return header + "Source file: " + name + "\n\n"
}

func leadingSourceComments(body []byte) ([]byte, error) {
	position, found := 0, false
	if bytes.HasPrefix(body, []byte{0xef, 0xbb, 0xbf}) {
		position = 3
	}
	for position < len(body) {
		switch body[position] {
		case ' ', '\t', '\r', '\n', '\f':
			position++
			continue
		}
		if bytes.HasPrefix(body[position:], []byte("//")) {
			found = true
			end := bytes.IndexByte(body[position:], '\n')
			if end < 0 {
				position = len(body)
			} else {
				position += end + 1
			}
		} else if bytes.HasPrefix(body[position:], []byte("/*")) {
			found = true
			end := bytes.Index(body[position+2:], []byte("*/"))
			if end < 0 {
				return nil, errors.New("unterminated leading source comment")
			}
			position += end + 4
		} else {
			break
		}
	}
	if !found {
		return nil, nil
	}
	return body[:position], nil
}

func appendGoComments(ctx context.Context, output *bytes.Buffer, owner SourceModule, name string, body []byte, leading int, remaining *int64) error {
	file := token.NewFileSet().AddFile(name, -1, len(body))
	var tokens scanner.Scanner
	var scanErr error
	tokens.Init(file, body, func(_ token.Position, message string) {
		if scanErr == nil {
			scanErr = fmt.Errorf("source comment scan: %s", message)
		}
	}, scanner.ScanComments)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		position, kind, _ := tokens.Scan()
		if kind == token.EOF {
			return scanErr
		}
		start := file.Offset(position)
		if kind != token.COMMENT || start < leading {
			continue
		}
		end := len(body)
		if bytes.HasPrefix(body[start:], []byte("//")) {
			if newline := bytes.IndexByte(body[start:], '\n'); newline >= 0 {
				end = start + newline
			}
		} else {
			close := bytes.Index(body[start+2:], []byte("*/"))
			if close < 0 {
				return errors.New("unterminated source comment")
			}
			end = start + close + 4
		}
		// Scanner literals remove carriage returns; retain the raw source range.
		header := legalHeader(owner, fmt.Sprintf("%s:%d (comment)", name, file.PositionFor(position, false).Line))
		if err := appendLegalSection(output, header, body[start:end], remaining); err != nil {
			return err
		}
	}
}

func appendLegalSection(output *bytes.Buffer, header string, body []byte, remaining *int64) error {
	length := int64(len(header)) + int64(len(body)) + 2
	if length > *remaining {
		return errors.New("legal material exceeds archive limit")
	}
	output.WriteString(header)
	output.Write(body)
	output.WriteString("\n\n")
	*remaining -= length
	return nil
}

func legalFileBytes(ctx context.Context, path string, limit int64) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, false, errors.New("legal file type or size refused")
	}
	file, err := openObservedFile(path, before)
	if err != nil {
		return nil, false, err
	}
	body, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, before.Size()+1))
	if err := errors.Join(readErr, checkObservedPath(path, before), file.Close()); err != nil {
		return nil, false, err
	}
	if int64(len(body)) != before.Size() || int64(len(body)) > limit {
		return nil, false, errors.New("legal file changed or exceeds limit")
	}
	return body, true, nil
}
