// Command enkv-release checks complete release candidates and prepares static catalog files.
// It does not execute payloads, hold signing keys, or publish files.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"enkv.sh/sdk/artifact"
)

type platform struct {
	Platform  string `json:"platform"`
	Runner    string `json:"runner"`
	Container string `json:"container,omitempty"`
}
type plugin struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Directory  string `json:"directory"`
	Command    string `json:"command"`
	Descriptor string `json:"descriptor"`
}
type inventory struct {
	Schema     int        `json:"schema"`
	CLIVersion string     `json:"cli_version"`
	PluginTag  string     `json:"plugin_release_tag"`
	Platforms  []platform `json:"platforms"`
	Plugins    []plugin   `json:"plugins"`
}
type fileFact struct {
	Path   string          `json:"path"`
	SHA256 artifact.Digest `json:"sha256"`
	Length uint64          `json:"length"`
	URL    string          `json:"url"`
}
type candidate struct {
	Schema      int             `json:"schema"`
	Kind        string          `json:"kind"`
	Environment string          `json:"environment"`
	Source      string          `json:"source"`
	Inventory   artifact.Digest `json:"inventory"`
	Files       []fileFact      `json:"files"`
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func read(path string, limit int64) ([]byte, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, errors.New("input is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	err = errors.Join(e, f.Close())
	if int64(len(b)) > limit {
		return nil, errors.New("input exceeds limit")
	}
	return b, err
}
func decode(path string, dst any) error {
	b, err := read(path, artifact.MaxRecordBytes)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(b, '\n'))
}
func writeNew(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	return errors.Join(e, f.Close())
}
func readInventory(path string) (v inventory, err error) {
	if err = decode(path, &v); err != nil {
		return
	}
	if v.Schema != 1 || !artifact.ValidVersion(v.CLIVersion) || !tagPattern.MatchString(v.PluginTag) || len(v.Platforms) != 2 || len(v.Plugins) != 9 {
		return v, errors.New("incomplete release inventory")
	}
	if v.Platforms[0].Platform != "darwin/arm64" || v.Platforms[1].Platform != "linux/amd64" {
		return v, errors.New("unsupported native inventory")
	}
	for i, p := range v.Plugins {
		if !artifact.ValidVersion(p.Version) || !namePattern.MatchString(p.Name) || i > 0 && v.Plugins[i-1].Name >= p.Name || !strings.HasPrefix(p.Directory, "plugins/") || filepath.Clean(p.Directory) != p.Directory || !strings.HasPrefix(p.Command, "./cmd/") || p.Descriptor != strings.TrimPrefix(p.Command, "./")+"/plugin.json" {
			return v, errors.New("invalid plugin inventory")
		}
	}
	return
}
func inventoryID(inv inventory) artifact.Digest { b, _ := json.Marshal(inv); return artifact.Hash(b) }
func publicKey(path string) (ed25519.PublicKey, error) {
	b, e := read(path, 4096)
	if e != nil {
		return nil, e
	}
	return artifact.ParsePublicKeyPEM(b)
}
func verifyRecord(directory, name, purpose string, key ed25519.PublicKey) ([]byte, error) {
	b, e := read(filepath.Join(directory, name+".json"), artifact.MaxRecordBytes)
	if e != nil {
		return nil, e
	}
	s, e := read(filepath.Join(directory, name+".sig"), 64)
	if e != nil {
		return nil, e
	}
	return b, artifact.VerifySignature(purpose, b, s, key)
}
func assetURL(kind, version, name string) string {
	repo := "extensions"
	tag := version
	if kind == "cli" {
		repo = "core"
		tag = "v" + version
	}
	return "https://github.com/enkv-sh/" + repo + "/releases/download/" + tag + "/" + name
}
func fact(path, relative, url string) (fileFact, error) {
	b, e := read(filepath.Join(path, relative), artifact.MaxArchiveBytes)
	return fileFact{relative, artifact.Hash(b), uint64(len(b)), url}, e
}
func inspectCandidate(ctx context.Context, inv inventory, dir, kind, environment string) ([]fileFact, error) {
	if environment != "production" && environment != "development" {
		return nil, errors.New("environment must be production or development")
	}
	cliKey, e := publicKey(filepath.Join(dir, "keys/cli-public.pem"))
	if e != nil {
		return nil, e
	}
	pluginKey, e := publicKey(filepath.Join(dir, "keys/plugin-public.pem"))
	if e != nil {
		return nil, e
	}
	if bytes.Equal(cliKey, pluginKey) {
		return nil, errors.New("CLI and plugin roots must differ")
	}
	var facts []fileFact
	add := func(path, url string) error {
		f, e := fact(dir, path, url)
		if e == nil {
			facts = append(facts, f)
		}
		return e
	}
	for _, p := range []string{"keys/cli-public.pem", "keys/plugin-public.pem"} {
		if e := add(p, ""); e != nil {
			return nil, e
		}
	}
	switch kind {
	case "cli":
		body, e := read(filepath.Join(dir, "cli/checksums.txt"), artifact.MaxRecordBytes)
		if e != nil {
			return nil, e
		}
		sig, e := read(filepath.Join(dir, "cli/checksums.sig"), 64)
		if e != nil {
			return nil, e
		}
		if e := artifact.VerifySignature("cli-checksums", body, sig, cliKey); e != nil {
			return nil, e
		}
		rows, e := artifact.DecodeChecksums(body)
		if e != nil {
			return nil, e
		}
		if len(rows) != len(inv.Platforms) {
			return nil, errors.New("incomplete CLI checksum set")
		}
		expected := map[string]string{}
		for _, p := range inv.Platforms {
			tuple := strings.ReplaceAll(p.Platform, "/", "-")
			n := cliArchiveFilename(inv.CLIVersion, p.Platform)
			expected[n] = "cli/" + tuple + "/" + n
		}
		for _, r := range rows {
			path, ok := expected[r.Name]
			if !ok {
				return nil, errors.New("unexpected CLI archive")
			}
			if e := add(path, assetURL(kind, inv.CLIVersion, r.Name)); e != nil {
				return nil, e
			}
			if facts[len(facts)-1].SHA256 != r.Digest {
				return nil, errors.New("CLI checksum mismatch")
			}
			if e := inspectCLI(filepath.Join(dir, path), strings.ReplaceAll(filepath.Base(filepath.Dir(path)), "-", "/"), cliKey, pluginKey, environment); e != nil {
				return nil, e
			}
			delete(expected, r.Name)
		}
		for _, n := range []string{"checksums.txt", "checksums.sig"} {
			if e := add("cli/"+n, assetURL(kind, inv.CLIVersion, n)); e != nil {
				return nil, e
			}
		}
	case "plugins":
		for _, p := range inv.Plugins {
			for _, platform := range inv.Platforms {
				rel := "plugins/" + p.Name + "/" + p.Version + "/" + strings.ReplaceAll(platform.Platform, "/", "-")
				folder := filepath.Join(dir, rel)
				body, e := verifyRecord(folder, "archive", "plugin-archive", pluginKey)
				if e != nil {
					return nil, fmt.Errorf("%s: %w", rel, e)
				}
				record, e := artifact.DecodeArchiveRecord(body)
				if e != nil {
					return nil, e
				}
				if record.Name != p.Name || record.Version != p.Version || record.Platform != platform.Platform {
					return nil, errors.New("archive identity differs from inventory")
				}
				archive, e := os.Open(filepath.Join(folder, record.Archive.Filename))
				if e != nil {
					return nil, e
				}
				scratch, e := os.MkdirTemp("", "enkv-release-verify-")
				if e != nil {
					return nil, errors.Join(e, archive.Close())
				}
				contents, verifyErr := artifact.ExtractArchiveBytes(ctx, archive, record, scratch, nil)
				e = errors.Join(verifyErr, archive.Close())
				if e == nil {
					var signature []byte
					signature, e = read(filepath.Join(scratch, "metadata.sig"), 64)
					if e == nil {
						e = artifact.VerifySignature("plugin-executable", contents.MetadataBytes, signature, pluginKey)
					}
				}
				if e == nil {
					m := contents.Metadata
					if m.MainModule != "enkv.sh/"+p.Directory || m.Command != "enkv.sh/"+p.Directory+strings.TrimPrefix(p.Command, ".") || m.Toolchain != "go1.27.3" {
						e = errors.New("plugin build facts differ from inventory")
					}
					if environment == "production" {
						for _, dep := range m.Resolved {
							if dep.Path != m.MainModule && (dep.Version == "" || dep.Version == "(devel)" || dep.Replacement != nil && (dep.Replacement.Version == "" || dep.Replacement.Version == "(devel)")) {
								e = errors.New("production requires published dependency versions without replacements")
							}
						}
					}
				}
				e = errors.Join(e, os.RemoveAll(scratch))
				if e != nil {
					return nil, fmt.Errorf("%s: %w", rel, e)
				}
				for _, n := range []string{"archive.json", "archive.sig", record.Archive.Filename} {
					asset := n
					if n == "archive.json" || n == "archive.sig" {
						asset = record.Artifact.String() + "-" + n
					}
					if e := add(rel+"/"+n, assetURL(kind, inv.PluginTag, asset)); e != nil {
						return nil, e
					}
				}
			}
		}
	default:
		return nil, errors.New("kind must be cli or plugins")
	}
	if environment == "production" {
		for _, platform := range inv.Platforms {
			tuple := strings.ReplaceAll(platform.Platform, "/", "-")
			names := []string{tuple}
			if kind == "plugins" {
				names = nil
				for _, p := range inv.Plugins {
					names = append(names, p.Name+"-"+tuple)
				}
			}
			for _, folder := range names {
				for _, name := range []string{"environment.json", "modules.json", "go.mod", "go.sum", "native-environment.txt", "buildinfo.txt"} {
					if _, e := read(filepath.Join(dir, "evidence", folder, name), artifact.MaxRecordBytes); e != nil {
						return nil, fmt.Errorf("required native build evidence %s/%s: %w", folder, name, e)
					}
				}
			}
		}
	}
	if entries, e := os.ReadDir(filepath.Join(dir, "evidence")); e == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !tagPattern.MatchString(entry.Name()) {
				return nil, errors.New("invalid evidence directory")
			}
			for _, name := range []string{"environment.json", "modules.json", "go.mod", "go.sum", "native-environment.txt", "buildinfo.txt"} {
				path := "evidence/" + entry.Name() + "/" + name
				if _, e := os.Stat(filepath.Join(dir, path)); e == nil {
					if e := add(path, ""); e != nil {
						return nil, e
					}
				} else if !errors.Is(e, os.ErrNotExist) {
					return nil, e
				}
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if catalogDir := filepath.Join(dir, "catalog"); kind == "plugins" {
		if _, e := os.Stat(catalogDir); e == nil {
			if _, e := checkedIndexes(inv, catalogDir, filepath.Join(dir, "keys/plugin-public.pem"), "plugins"); e != nil {
				return nil, e
			}
			for _, p := range inv.Plugins {
				for _, platform := range inv.Platforms {
					rel := "plugins/" + p.Name + "/" + p.Version + "/" + strings.ReplaceAll(platform.Platform, "/", "-") + "/archive.json"
					a, e := read(filepath.Join(dir, rel), artifact.MaxRecordBytes)
					if e != nil {
						return nil, e
					}
					b, e := read(filepath.Join(catalogDir, rel), artifact.MaxRecordBytes)
					if e != nil || !bytes.Equal(a, b) {
						return nil, errors.New("catalog current record differs from candidate")
					}
				}
			}

			e := filepath.WalkDir(catalogDir, func(path string, entry fs.DirEntry, e error) error {
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
				url := ""
				for _, p := range inv.Plugins {
					for _, n := range []string{"index.json", "index.sig"} {
						if relative == "catalog/plugins/"+p.Name+"/"+n {
							url = assetURL("plugins", inv.PluginTag, p.Name+"-"+n)
						}
					}
				}
				return add(relative, url)
			})
			if e != nil {
				return nil, e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	slices.SortFunc(facts, func(a, b fileFact) int { return strings.Compare(a.Path, b.Path) })
	return facts, nil
}
func checkedCandidate(ctx context.Context, inv inventory, dir string) (candidate, error) {
	var c candidate
	if e := decode(filepath.Join(dir, "candidate.json"), &c); e != nil {
		return c, e
	}
	if c.Schema != 1 || !commitPattern.MatchString(c.Source) || c.Inventory != inventoryID(inv) {
		return c, errors.New("candidate source or inventory differs")
	}
	facts, e := inspectCandidate(ctx, inv, dir, c.Kind, c.Environment)
	if e != nil {
		return c, e
	}
	a, _ := json.Marshal(facts)
	b, _ := json.Marshal(c.Files)
	if !bytes.Equal(a, b) {
		return c, errors.New("candidate file facts differ")
	}
	return c, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("command required: matrix, candidate, verify, catalog, finalize, assets, floor")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(output)
	inventoryPath := flags.String("inventory", "distribution/release.json", "reviewed release inventory")
	dir := flags.String("directory", "", "candidate or catalog directory")
	kind := flags.String("kind", "", "cli or plugins")
	source := flags.String("source", "", "reviewed 40-hex source commit")
	environment := flags.String("environment", "production", "production or development")
	candidatePath := flags.String("candidate", "", "candidate directory")
	previous := flags.String("previous", "", "previous catalog tree")
	out := flags.String("output", "", "new output directory")
	key := flags.String("plugin-public-key", "", "trusted plugin public key")
	cliKey := flags.String("cli-public-key", "", "trusted CLI public key")
	binary := flags.String("binary", "", "native executable to inspect")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "floor" {
		return checkFloor(*binary, output)
	}
	inv, e := readInventory(*inventoryPath)
	if e != nil {
		return e
	}
	switch args[0] {
	case "finalize":
		return finalize(inv, *dir, *key)
	case "matrix":
		var rows []map[string]string
		for _, p := range inv.Platforms {
			switch *kind {
			case "cli":
				rows = append(rows, map[string]string{"platform": p.Platform, "tuple": strings.ReplaceAll(p.Platform, "/", "-"), "runner": p.Runner, "container": p.Container, "archive": cliArchiveFilename(inv.CLIVersion, p.Platform)})
			case "plugins":
				for _, plugin := range inv.Plugins {
					rows = append(rows, map[string]string{"platform": p.Platform, "tuple": strings.ReplaceAll(p.Platform, "/", "-"), "runner": p.Runner, "container": p.Container, "name": plugin.Name, "directory": plugin.Directory, "command": plugin.Command, "descriptor": plugin.Descriptor})
				}
			default:
				return errors.New("kind must be cli or plugins")
			}
		}
		return json.NewEncoder(output).Encode(map[string]any{"include": rows})
	case "candidate":
		if !commitPattern.MatchString(*source) {
			return errors.New("reviewed source commit required")
		}
		facts, e := inspectCandidate(ctx, inv, *dir, *kind, *environment)
		if e != nil {
			return e
		}
		return writeJSON(filepath.Join(*dir, "candidate.json"), candidate{1, *kind, *environment, *source, inventoryID(inv), facts})
	case "verify":
		if e := trustedRoots(*dir, *cliKey, *key); e != nil {
			return e
		}
		c, e := checkedCandidate(ctx, inv, *dir)
		if e != nil {
			return e
		}
		return requireCatalog(c, *dir)
	case "catalog":
		if e := trustedRoots(*candidatePath, *cliKey, *key); e != nil {
			return e
		}
		return catalog(ctx, inv, *candidatePath, *previous, *out)
	case "assets":
		if e := trustedRoots(*dir, *cliKey, *key); e != nil {
			return e
		}
		return assets(ctx, inv, *dir, *out)
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if e := run(context.Background(), os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func requireCatalog(c candidate, dir string) error {
	if c.Kind == "plugins" && c.Environment == "production" {
		if _, e := os.Stat(filepath.Join(dir, "catalog/plugins")); e != nil {
			return errors.New("production plugin candidate requires its complete signed catalog")
		}
	}
	return nil
}

func cliArchiveFilename(version, platform string) string {
	return "enkv-full-" + strings.ReplaceAll(version, "+", "_") + "-" + strings.ReplaceAll(platform, "/", "-") + ".tar.gz"
}
