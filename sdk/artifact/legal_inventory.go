package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

func sourceLegalNames() [19]string {
	licenses := SourceLicenseFiles()
	return [19]string{
		licenses[0], licenses[1], licenses[2], "NOTICE", "NOTICE.txt", "NOTICE.md", "THIRD_PARTY_NOTICES.md",
		"AUTHORS", "AUTHORS.txt", "AUTHORS.md", "COPYING", "COPYING.txt", "COPYING.md",
		"COPYRIGHT", "COPYRIGHT.txt", "COPYRIGHT.md", "PATENTS", "PATENTS.txt", "PATENTS.md",
	}
}

func selectedSourceFiles(pkg SourcePackage) []string {
	var names []string
	for _, group := range [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles} {
		names = append(names, group...)
	}
	return names
}

func sourceLegalPaths(ctx context.Context, root, directory string, inputs []string) ([]string, error) {
	directories := map[string]bool{}
	add := func(dir string) error {
		if !inside(root, dir) {
			return errors.New("legal source directory escapes module owner")
		}
		for !directories[dir] {
			resolved, err := filepath.EvalSymlinks(dir)
			if err != nil {
				return err
			}
			if !inside(root, resolved) {
				return errors.New("legal source directory symlink escapes module owner")
			}
			directories[dir] = true
			if dir == root {
				break
			}
			dir = filepath.Dir(dir)
		}
		return nil
	}
	if err := add(directory); err != nil {
		return nil, err
	}
	for _, name := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !safeRelative(name) {
			return nil, errors.New("legal source input path refused")
		}
		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := add(filepath.Dir(path)); err != nil {
			return nil, err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		if !inside(root, resolved) {
			return nil, errors.New("legal source input escapes module owner")
		}
		if err := add(filepath.Dir(resolved)); err != nil {
			return nil, err
		}
	}
	var paths []string
	for dir := range directories {
		for _, name := range sourceLegalNames() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			path := filepath.Join(dir, name)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("legal source file must be regular")
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			paths = append(paths, filepath.ToSlash(relative))
		}
	}
	slices.Sort(paths)
	return paths, nil
}
