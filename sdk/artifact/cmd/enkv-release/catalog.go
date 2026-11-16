package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"enkv.sh/sdk/artifact"
)

type redirect struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

func put(path string, b []byte) error {
	old, e := read(path, artifact.MaxRecordBytes)
	if e == nil {
		if !bytes.Equal(old, b) {
			return errors.New("immutable route already has different bytes")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return writeNew(path, b)
}
func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(destination, rel), 0755)
		}
		if !d.Type().IsRegular() {
			return errors.New("catalog contains a nonregular file")
		}
		b, e := read(path, artifact.MaxRecordBytes)
		if e != nil {
			return e
		}
		return writeNew(filepath.Join(destination, rel), b)
	})
}
func catalog(ctx context.Context, inv inventory, dir, previous, output string) error {
	c, e := checkedCandidate(ctx, inv, dir)
	if e != nil {
		return e
	}
	if output == "" {
		return errors.New("output is required")
	}
	if _, e := os.Lstat(output); !errors.Is(e, os.ErrNotExist) {
		return errors.New("catalog output must not exist")
	}
	if previous != "" {
		if e := checkedPriorCatalog(inv, previous, filepath.Join(dir, "keys/plugin-public.pem")); e != nil {
			return e
		}
	}
	if e := os.Mkdir(output, 0755); e != nil {
		return e
	}

	if previous != "" {
		if e := copyTree(previous, output); e != nil {
			return e
		}
	}
	for _, name := range []string{"cli-public.pem", "plugin-public.pem"} {
		b, e := read(filepath.Join(dir, "keys", name), 4096)
		if e != nil {
			return e
		}
		if e := os.MkdirAll(filepath.Join(output, "keys"), 0755); e != nil {
			return e
		}
		if e := os.WriteFile(filepath.Join(output, "keys", name), b, 0644); e != nil {
			return e
		}
	}
	var redirects []redirect
	if previous != "" {
		if e := decode(filepath.Join(previous, "redirects.json"), &redirects); e != nil {
			return e
		}
	}
	redirectMap := map[string]string{}
	for _, r := range redirects {
		if !validRedirect(r) {
			return errors.New("invalid previous payload redirect")
		}
		if _, ok := redirectMap[r.Path]; ok {
			return errors.New("duplicate previous redirect")
		}
		redirectMap[r.Path] = r.URL
	}
	addRedirect := func(path, url string) error {
		r := redirect{"/releases/" + path, url}
		if !validRedirect(r) {
			return errors.New("payload redirect refused")
		}
		if old, ok := redirectMap[r.Path]; ok && old != url {
			return errors.New("immutable payload redirect differs")
		}
		redirectMap[r.Path] = url
		return nil
	}
	if c.Kind == "cli" {
		for _, f := range c.Files {
			if f.URL != "" {
				if e := addRedirect("cli/"+inv.CLIVersion+"/"+filepath.Base(f.Path), f.URL); e != nil {
					return e
				}
			}
		}

		if e := os.WriteFile(filepath.Join(output, "index.html"), []byte(installationPage(inv)), 0644); e != nil {
			return e
		}
	} else {
		key, e := publicKey(filepath.Join(dir, "keys/plugin-public.pem"))
		if e != nil {
			return e
		}
		for _, p := range inv.Plugins {
			index := artifact.ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: p.Name, Releases: []artifact.Release{}}
			if previous != "" {
				old, e := verifyRecord(filepath.Join(previous, "plugins", p.Name), "index", "plugin-index", key)
				if e == nil {
					index, e = artifact.DecodeReleaseIndex(old)
					if e != nil {
						return e
					}
				} else {
					return e
				}
			}
			for _, platform := range inv.Platforms {
				rel := "plugins/" + p.Name + "/" + p.Version + "/" + strings.ReplaceAll(platform.Platform, "/", "-")
				body, e := read(filepath.Join(dir, rel, "archive.json"), artifact.MaxRecordBytes)
				if e != nil {
					return e
				}
				record, e := artifact.DecodeArchiveRecord(body)
				if e != nil {
					return e
				}
				for _, route := range []string{rel, "artifacts/" + record.Artifact.String()} {
					for _, n := range []string{"archive.json", "archive.sig"} {
						b, e := read(filepath.Join(dir, rel, n), artifact.MaxRecordBytes)
						if e != nil {
							return e
						}
						if e := put(filepath.Join(output, route, n), b); e != nil {
							return e
						}
					}
					if e := addRedirect(route+"/"+record.Archive.Filename, assetURL("plugins", inv.PluginTag, record.Archive.Filename)); e != nil {
						return e
					}
				}
				found := false

				for _, r := range index.Releases {
					if r.Version == record.Version && r.Platform == record.Platform {
						if r.Artifact != record.Artifact {
							return errors.New("release version/platform is immutable")
						}
						found = true
					}
				}
				if !found {
					index.Releases = append(index.Releases, artifact.Release{Version: record.Version, Platform: record.Platform, Artifact: record.Artifact})
				}
			}
			slices.SortFunc(index.Releases, func(a, b artifact.Release) int {
				if c, _ := artifact.CompareVersions(a.Version, b.Version); c != 0 {
					return c
				}
				return strings.Compare(a.Platform, b.Platform)
			})
			body, e := artifact.EncodeReleaseIndex(index)
			if e != nil {
				return e
			}
			if e := writeNew(filepath.Join(output, "pending", p.Name, "index.json"), body); e != nil {
				return e
			}
		}
	}

	redirects = nil
	for path, url := range redirectMap {
		redirects = append(redirects, redirect{path, url})
	}
	slices.SortFunc(redirects, func(a, b redirect) int { return strings.Compare(a.Path, b.Path) })
	bpath := filepath.Join(output, "redirects.json")
	if previous != "" {
		if e := os.Remove(bpath); e != nil {
			return e
		}
	}
	return writeJSON(bpath, redirects)
}
func validRedirect(r redirect) bool {
	if !strings.HasPrefix(r.Path, "/releases/") || filepath.Clean(r.Path) != r.Path || strings.ContainsAny(r.Path, "?%#\\ \r\n") {
		return false
	}
	for _, repo := range []string{"core", "extensions"} {
		prefix := "https://github.com/enkv-sh/" + repo + "/releases/download/"
		if strings.HasPrefix(r.URL, prefix) {
			tail := strings.TrimPrefix(r.URL, prefix)
			parts := strings.Split(tail, "/")
			return len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.ContainsAny(tail, "?%#\\ \r\n") && parts[0] != ".." && parts[1] != ".."
		}
	}
	return false
}

type indexSelection struct {
	name            string
	body, signature []byte
}

func finalize(inv inventory, dir, keyPath string) error {
	selections, e := checkedIndexes(inv, dir, keyPath, "pending")
	if e != nil {
		return e
	}
	for _, s := range selections {
		for n, b := range map[string][]byte{"index.json": s.body, "index.sig": s.signature} {
			if e := os.MkdirAll(filepath.Join(dir, "plugins", s.name), 0755); e != nil {
				return e
			}
			if e := os.WriteFile(filepath.Join(dir, "plugins", s.name, n), b, 0644); e != nil {
				return e
			}
		}
	}
	return os.RemoveAll(filepath.Join(dir, "pending"))
}
func assets(ctx context.Context, inv inventory, dir, output string) error {
	c, e := checkedCandidate(ctx, inv, dir)
	if e != nil {
		return e
	}
	if e := requireCatalog(c, dir); e != nil {
		return e
	}
	if _, e := os.Lstat(output); !errors.Is(e, os.ErrNotExist) {
		return errors.New("asset output must not exist")
	}
	if e := os.Mkdir(output, 0755); e != nil {
		return e
	}
	for _, f := range c.Files {
		if f.URL == "" {
			continue
		}
		name := f.URL[strings.LastIndex(f.URL, "/")+1:]
		b, e := read(filepath.Join(dir, f.Path), artifact.MaxArchiveBytes)
		if e != nil {
			return e
		}
		if e := put(filepath.Join(output, name), b); e != nil {
			return e
		}
	}
	return nil
}

func installationPage(inv inventory) string {
	var page strings.Builder
	page.WriteString("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><style>body{font:17px/1.6 system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1.2rem}a{color:#1855b5}li{margin:.6rem 0}</style><title>Install ENKV</title><h1>Install ENKV beta</h1><p>Download the full CLI for your platform. Extract it into an empty directory, retain its legal files, and put enkv on PATH.</p><ul>")
	for _, platform := range inv.Platforms {
		name := cliArchiveFilename(inv.CLIVersion, platform.Platform)
		label := "Linux · x86_64"
		if platform.Platform == "darwin/arm64" {
			label = "macOS · Apple silicon"
		}
		fmt.Fprintf(&page, "<li><a href=\"%s\">%s</a> — %s</li>", html.EscapeString(assetURL("cli", inv.CLIVersion, name)), label, html.EscapeString(inv.CLIVersion))
	}
	page.WriteString("</ul><p><a href=\"" + assetURL("cli", inv.CLIVersion, "checksums.txt") + "\">Checksums</a> · <a href=\"" + assetURL("cli", inv.CLIVersion, "checksums.sig") + "\">Checksum signature</a> · <a href=\"/keys/cli-public.pem\">CLI public key</a> · <a href=\"/keys/plugin-public.pem\">Plugin public key</a></p><p><a href=\"https://github.com/enkv-sh/core/blob/main/docs/install.md\">Installation and signature verification</a>. macOS requires manual approval for this beta. Application preparation is a separate operation.</p><p><a href=\"https://github.com/enkv-sh/core/blob/main/docs/quickstart-aws.md\">Start with AWS</a> · <a href=\"https://github.com/enkv-sh/core/blob/main/docs/quickstart-gcp.md\">Start with GCP</a> · <a href=\"https://github.com/enkv-sh/core/blob/main/docs/operations.md\">Operator guide</a></p></html>\n")
	return page.String()
}
