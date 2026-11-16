package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"enkv.sh/sdk/artifact"
)

type catalogArchive struct {
	record          artifact.ArchiveRecord
	body, signature []byte
}

type catalogRecords struct {
	archives map[string]catalogArchive
	indexes  map[string]indexSelection
}

func catalogPayloads(dir string) (map[string]string, error) {
	var redirects []redirect
	if e := decode(filepath.Join(dir, "redirects.json"), &redirects); e != nil {
		return nil, e
	}
	payloads := map[string]string{}
	for _, r := range redirects {
		if !validRedirect(r) {
			return nil, errors.New("invalid payload redirect")
		}
		if _, ok := payloads[r.Path]; ok {
			return nil, errors.New("duplicate payload redirect")
		}
		payloads[r.Path] = r.URL
	}
	return payloads, nil
}

func readCatalogIndex(dir, root, name string, key ed25519.PublicKey, archives map[string]catalogArchive) (indexSelection, error) {
	folder := filepath.Join(dir, root, name)
	body, e := verifyRecord(folder, "index", "plugin-index", key)
	if e != nil {
		return indexSelection{}, e
	}
	index, e := artifact.DecodeReleaseIndex(body)
	if e != nil || index.Name != name {
		return indexSelection{}, errors.New("index name differs")
	}
	for _, r := range index.Releases {
		version := "plugins/" + name + "/" + r.Version + "/" + strings.ReplaceAll(r.Platform, "/", "-")
		artifactPath := "artifacts/" + r.Artifact.String()
		a, versionFound := archives[version]
		b, artifactFound := archives[artifactPath]
		if !versionFound || !artifactFound || !bytes.Equal(a.body, b.body) || !bytes.Equal(a.signature, b.signature) {
			return indexSelection{}, errors.New("indexed version and artifact routes are missing or differ")
		}
		record := a.record
		if record.Name != name || record.Version != r.Version || record.Platform != r.Platform || record.Artifact != r.Artifact {
			return indexSelection{}, errors.New("index route identity differs")
		}
	}
	signature, e := read(filepath.Join(folder, "index.sig"), 64)
	return indexSelection{name, body, signature}, e
}

func authenticatedCatalog(inv inventory, dir string, key ed25519.PublicKey) (catalogRecords, error) {
	result := catalogRecords{archives: map[string]catalogArchive{}, indexes: map[string]indexSelection{}}
	payloads, e := catalogPayloads(dir)
	if e != nil {
		return result, e
	}
	indexNames := map[string]bool{}
	e = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("catalog contains a nonregular file")
		}
		relative, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		route := filepath.ToSlash(filepath.Dir(relative))
		parts := strings.Split(route, "/")
		if entry.Name() == "index.json" || entry.Name() == "index.sig" {
			if len(parts) == 2 && parts[0] == "plugins" {
				indexNames[parts[1]] = true
			}
			return nil
		}
		if entry.Name() != "archive.json" && entry.Name() != "archive.sig" {
			return nil
		}
		if _, ok := result.archives[route]; ok {
			return nil
		}
		body, e := verifyRecord(filepath.Dir(path), "archive", "plugin-archive", key)
		if e != nil {
			return e
		}
		record, e := artifact.DecodeArchiveRecord(body)
		if e != nil {
			return e
		}
		version := "plugins/" + record.Name + "/" + record.Version + "/" + strings.ReplaceAll(record.Platform, "/", "-")
		if route != version && route != "artifacts/"+record.Artifact.String() {
			return errors.New("archive route identity differs")
		}
		target := payloads["/releases/"+route+"/"+record.Archive.Filename]
		if !strings.HasPrefix(target, "https://github.com/enkv-sh/extensions/releases/download/") || !strings.HasSuffix(target, "/"+record.Archive.Filename) {
			return errors.New("payload asset identity differs")
		}
		signature, e := read(filepath.Join(filepath.Dir(path), "archive.sig"), 64)
		if e != nil {
			return e
		}
		result.archives[route] = catalogArchive{record, body, signature}
		return nil
	})
	if e != nil {
		return result, e
	}
	for route, a := range result.archives {
		counterpart := "artifacts/" + a.record.Artifact.String()
		if strings.HasPrefix(route, "artifacts/") {
			counterpart = "plugins/" + a.record.Name + "/" + a.record.Version + "/" + strings.ReplaceAll(a.record.Platform, "/", "-")
		}
		if _, ok := result.archives[counterpart]; !ok && strings.HasPrefix(route, "plugins/") {
			return result, errors.New("version route is missing its retained artifact route")
		}
		if b, ok := result.archives[counterpart]; ok {
			if !bytes.Equal(a.body, b.body) || !bytes.Equal(a.signature, b.signature) || payloads["/releases/"+route+"/"+a.record.Archive.Filename] != payloads["/releases/"+counterpart+"/"+a.record.Archive.Filename] {
				return result, errors.New("retained version and artifact routes differ")
			}
		}
	}
	for path, target := range payloads {
		relative := strings.TrimPrefix(path, "/releases/")
		if strings.HasPrefix(relative, "plugins/") || strings.HasPrefix(relative, "artifacts/") {
			route := relative[:strings.LastIndex(relative, "/")]
			record, ok := result.archives[route]
			if !ok || relative != route+"/"+record.record.Archive.Filename {
				return result, errors.New("payload redirect has no authenticated archive record")
			}
			continue
		}
		parts := strings.Split(relative, "/")
		if !validCLIPayload(inv, parts, target) {
			return result, errors.New("CLI payload redirect identity differs")
		}
	}
	for name := range indexNames {
		index, e := readCatalogIndex(dir, "plugins", name, key, result.archives)
		if e != nil {
			return result, e
		}
		result.indexes[name] = index
	}
	return result, nil
}

func checkedPriorCatalog(inv inventory, dir, keyPath string) error {
	if _, e := os.Lstat(filepath.Join(dir, "pending")); e == nil {
		return errors.New("previous catalog contains pending indexes")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	key, e := publicKey(keyPath)
	if e != nil {
		return e
	}
	records, e := authenticatedCatalog(inv, dir, key)
	if e != nil {
		return e
	}
	for _, p := range inv.Plugins {
		if _, ok := records.indexes[p.Name]; !ok {
			return errors.New("previous catalog is missing a complete signed index")
		}
	}
	return nil
}

func checkedIndexes(inv inventory, dir, keyPath, indexRoot string) ([]indexSelection, error) {
	if indexRoot == "plugins" {
		if _, e := os.Lstat(filepath.Join(dir, "pending")); e == nil {
			return nil, errors.New("final catalog contains pending indexes")
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	key, e := publicKey(keyPath)
	if e != nil {
		return nil, e
	}
	records, e := authenticatedCatalog(inv, dir, key)
	if e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(filepath.Join(dir, indexRoot))
	if e != nil {
		return nil, e
	}
	if len(entries) != len(inv.Plugins) {
		return nil, errors.New("index inventory differs")
	}
	expected := map[string]plugin{}
	for _, p := range inv.Plugins {
		expected[p.Name] = p
	}
	var selections []indexSelection
	for _, entry := range entries {
		p, ok := expected[entry.Name()]
		if !entry.IsDir() || !ok {
			return nil, errors.New("invalid index directory")
		}
		selected, e := readCatalogIndex(dir, indexRoot, p.Name, key, records.archives)
		if e != nil {
			return nil, e
		}
		index, e := artifact.DecodeReleaseIndex(selected.body)
		if e != nil {
			return nil, e
		}
		for _, platform := range inv.Platforms {
			found := false
			for _, r := range index.Releases {
				if r.Version == p.Version && r.Platform == platform.Platform {
					found = true
				}
			}
			if !found {
				return nil, errors.New("index is missing an expected release")
			}
		}
		selections = append(selections, selected)
	}
	return selections, nil
}

func validCLIPayload(inv inventory, parts []string, target string) bool {
	if len(parts) != 3 || parts[0] != "cli" || !artifact.ValidVersion(parts[1]) || target != assetURL("cli", parts[1], parts[2]) {
		return false
	}
	if parts[2] == "checksums.txt" || parts[2] == "checksums.sig" {
		return true
	}
	for _, p := range inv.Platforms {
		if parts[2] == cliArchiveFilename(parts[1], p.Platform) {
			return true
		}
	}
	return false
}
