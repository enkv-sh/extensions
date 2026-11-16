package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/build"
)

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func testKeys(t *testing.T, dir string) ed25519.PrivateKey {
	t.Helper()
	seed, e := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	for name, k := range map[string]ed25519.PrivateKey{"plugin": key, "cli": ed25519.NewKeyFromSeed(make([]byte, 32))} {
		der, e := x509.MarshalPKIXPublicKey(k.Public())
		if e != nil {
			t.Fatal(e)
		}
		mustWrite(t, filepath.Join(dir, "keys", name+"-public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return key
}
func pluginFixture(t *testing.T, version string) (inventory, string, ed25519.PrivateKey) {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	dir := t.TempDir()
	key := testKeys(t, dir)
	p := plugin{Name: "generic-json", Version: version, Directory: "plugins/manifest-generators/generic-json", Command: "./cmd/plugin", Descriptor: "cmd/plugin/plugin.json"}
	inv := inventory{Schema: 1, CLIVersion: "0.1.0-beta.1", PluginTag: "plugins-v" + version, Platforms: []platform{{Platform: runtime.GOOS + "/" + runtime.GOARCH}}, Plugins: []plugin{p}}
	source := t.TempDir()
	mustWrite(t, filepath.Join(source, "go.mod"), []byte("module enkv.sh/plugins/manifest-generators/generic-json\n\ngo 1.27.0\n"))
	mustWrite(t, filepath.Join(source, "LICENSE"), []byte("test license\n"))
	mustWrite(t, filepath.Join(source, "cmd/plugin/main.go"), []byte("package main\nfunc main(){panic(\"release tooling must never execute payloads\")}\n"))
	body, e := os.ReadFile("../../../../plugins/manifest-generators/generic-json/cmd/enkv-manifest-generic-json/plugin.json")
	if e != nil {
		t.Fatal(e)
	}
	body = []byte(strings.Replace(string(body), "0.1.0", version, 1))
	mustWrite(t, filepath.Join(source, p.Descriptor), body)
	output := filepath.Join(t.TempDir(), "build")
	t.Cleanup(func() {
		err := filepath.Walk(output, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		})
		if err != nil {
			t.Errorf("restore build directory permissions: %v", err)
		}
	})
	cfg := build.Config{Directory: source, Command: p.Command, Descriptor: p.Descriptor, Output: output, Versioned: true}
	if _, e := build.Run(t.Context(), cfg); e != nil {
		t.Fatal(e)
	}
	metadata, e := artifact.VerifyBuild(t.Context(), output)
	if e != nil {
		t.Fatal(e)
	}
	m, e := artifact.EncodeMetadata(metadata)
	if e != nil {
		t.Fatal(e)
	}
	sig := filepath.Join(t.TempDir(), "metadata.sig")
	mustWrite(t, sig, ed25519.Sign(key, m))
	tuple := strings.ReplaceAll(inv.Platforms[0].Platform, "/", "-")
	archiveDir := filepath.Join(dir, "plugins", p.Name, version, tuple)
	if e := os.MkdirAll(filepath.Dir(archiveDir), 0700); e != nil {
		t.Fatal(e)
	}
	record, e := build.Archive(t.Context(), build.ArchiveConfig{Build: output, Directory: source, Command: p.Command, Output: archiveDir, Versioned: true, MetadataSignature: sig})
	if e != nil {
		t.Fatal(e)
	}
	recordBytes, e := artifact.EncodeArchiveRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	mustWrite(t, filepath.Join(archiveDir, "archive.sig"), ed25519.Sign(key, recordBytes))
	facts, e := inspectCandidate(t.Context(), inv, dir, "plugins", "development")
	if e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(dir, "candidate.json"), candidate{1, "plugins", "development", strings.Repeat("1", 40), inventoryID(inv), facts}); e != nil {
		t.Fatal(e)
	}
	return inv, dir, key
}
func signIndexes(t *testing.T, site string, key ed25519.PrivateKey) {
	t.Helper()
	entries, e := os.ReadDir(filepath.Join(site, "pending"))
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		path := filepath.Join(site, "pending", entry.Name(), "index.json")
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		mustWrite(t, filepath.Join(filepath.Dir(path), "index.sig"), ed25519.Sign(key, b))
	}
}

func cliFixture(t *testing.T, inv inventory, tlsRoots string) string {
	t.Helper()
	dir := t.TempDir()
	testKeys(t, dir)
	module := t.TempDir()
	mustWrite(t, filepath.Join(module, "go.mod"), []byte("module enkv.sh/compositions/full\n\ngo 1.27.0\n"))
	names := []string{"installedPluginKeys", "installedCLIVerificationKey", "installedPluginOrigin", "installedPluginRedirectHosts", "installedPluginTLSRoots"}
	var declarations, values, flags []string
	for _, name := range names {
		declarations = append(declarations, "var "+name+" string")
		values = append(values, name)
		value := "https://enkv.sh/releases/"
		switch name {
		case "installedPluginKeys":
			key, e := publicKey(filepath.Join(dir, "keys/plugin-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			value = hex.EncodeToString(key)
		case "installedCLIVerificationKey":
			key, e := publicKey(filepath.Join(dir, "keys/cli-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			value = hex.EncodeToString(key)
		case "installedPluginRedirectHosts":
			value = "github.com,release-assets.githubusercontent.com"
		case "installedPluginTLSRoots":
			value = tlsRoots
		}
		flags = append(flags, "-X=enkv.sh/compositions/full."+name+"="+value)
	}
	mustWrite(t, filepath.Join(module, "full.go"), []byte("package full\n"+strings.Join(declarations, "\n")+"\nfunc Values()string{return "+strings.Join(values, "+")+"}\n"))
	mustWrite(t, filepath.Join(module, "cmd/enkv/main.go"), []byte("package main\nimport (\"fmt\";\"enkv.sh/compositions/full\")\nfunc main(){fmt.Print(full.Values())}\n"))
	binary := filepath.Join(t.TempDir(), "enkv")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-buildvcs=false", "-ldflags="+strings.Join(flags, " "), "-o", binary, "./cmd/enkv")
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("CLI fixture build: %s %v", out, e)
	}
	body, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "enkv"} {
		data := []byte("synthetic legal bytes\n")
		mode := int64(0644)
		if name == "enkv" {
			data = body
			mode = 0755
		}
		if e := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: mode, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	tuple := strings.ReplaceAll(inv.Platforms[0].Platform, "/", "-")
	filename := "enkv-full-" + strings.ReplaceAll(inv.CLIVersion, "+", "_") + "-" + tuple + ".tar.gz"
	mustWrite(t, filepath.Join(dir, "cli", tuple, filename), archive.Bytes())
	checksums := []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(archive.Bytes()), filename))
	mustWrite(t, filepath.Join(dir, "cli/checksums.txt"), checksums)
	mustWrite(t, filepath.Join(dir, "cli/checksums.sig"), ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, 32)), checksums))
	facts, e := inspectCandidate(t.Context(), inv, dir, "cli", "development")
	if e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(dir, "candidate.json"), candidate{1, "cli", "development", strings.Repeat("1", 40), inventoryID(inv), facts}); e != nil {
		t.Fatal(e)
	}
	return dir
}

// full_only: false
func TestSignedCandidateCatalogPreservesRoutesAndRefusesTamper(t *testing.T) {
	inv, dir, key := pluginFixture(t, "0.1.0")
	c, e := checkedCandidate(t.Context(), inv, dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Files) != 5 {
		t.Fatalf("wrong complete candidate inventory: %d", len(c.Files))
	}
	var archive string
	for _, f := range c.Files {
		if strings.HasSuffix(f.Path, ".tar.gz") {
			archive = filepath.Join(dir, f.Path)
			b, e := os.ReadFile(archive)
			if e != nil {
				t.Fatal(e)
			}
			if f.SHA256 != sha256.Sum256(b) || f.Length != uint64(len(b)) {
				t.Fatal("candidate bytes differ")
			}
		}
	}
	site := filepath.Join(t.TempDir(), "site")
	if e := catalog(t.Context(), inv, dir, "", site); e != nil {
		t.Fatal(e)
	}
	if e := finalize(inv, site, filepath.Join(dir, "keys/plugin-public.pem")); e == nil {
		t.Fatal("unsigned selecting index accepted")
	}
	if _, e := os.Stat(filepath.Join(site, "plugins/generic-json/index.json")); !os.IsNotExist(e) {
		t.Fatal("unsigned index selected")
	}
	signIndexes(t, site, key)
	if e := finalize(inv, site, filepath.Join(dir, "keys/plugin-public.pem")); e != nil {
		t.Fatal(e)
	}
	oldIndex, e := os.ReadFile(filepath.Join(site, "plugins/generic-json/index.json"))
	if e != nil {
		t.Fatal(e)
	}
	index, e := artifact.DecodeReleaseIndex(oldIndex)
	if e != nil {
		t.Fatal(e)
	}
	artifactPath := filepath.Join("artifacts", index.Releases[0].Artifact.String(), "archive.json")
	oldRecord, e := os.ReadFile(filepath.Join(site, artifactPath))
	if e != nil {
		t.Fatal(e)
	}
	newer, newDir, newKey := pluginFixture(t, "0.2.0")
	next := filepath.Join(t.TempDir(), "next")
	if e := catalog(t.Context(), newer, newDir, site, next); e != nil {
		t.Fatal(e)
	}
	signIndexes(t, next, newKey)
	originalRedirects, e := os.ReadFile(filepath.Join(next, "redirects.json"))
	if e != nil {
		t.Fatal(e)
	}
	var damaged []redirect
	if e := decode(filepath.Join(next, "redirects.json"), &damaged); e != nil {
		t.Fatal(e)
	}
	for i := range damaged {
		damaged[i].URL = "https://github.com/enkv-sh/core/releases/download/v0.1.0-beta.1/wrong.tar.gz"
	}
	encoded, e := json.Marshal(damaged)
	if e != nil {
		t.Fatal(e)
	}
	mustWrite(t, filepath.Join(next, "redirects.json"), encoded)
	if e := finalize(newer, next, filepath.Join(newDir, "keys/plugin-public.pem")); e == nil {
		t.Fatal("damaged retained payload asset identity accepted")
	}
	mustWrite(t, filepath.Join(next, "redirects.json"), originalRedirects)
	if e := finalize(newer, next, filepath.Join(newDir, "keys/plugin-public.pem")); e != nil {
		t.Fatal(e)
	}
	retained, e := os.ReadFile(filepath.Join(next, artifactPath))
	if e != nil || string(retained) != string(oldRecord) {
		t.Fatal("retained artifact route changed")
	}
	body, e := os.ReadFile(filepath.Join(next, "plugins/generic-json/index.json"))
	if e != nil {
		t.Fatal(e)
	}
	current, e := artifact.DecodeReleaseIndex(body)
	if e != nil || len(current.Releases) != 2 {
		t.Fatal("old release selection lost", e)
	}
	if destination := os.Getenv("ENKV_RELEASE_EXAMPLE"); destination != "" {
		if e := os.CopyFS(filepath.Join(destination, "site"), os.DirFS(next)); e != nil {
			t.Fatal(e)
		}
		if e := os.CopyFS(filepath.Join(destination, "candidate"), os.DirFS(newDir)); e != nil {
			t.Fatal(e)
		}
	}
	if archivePath := os.Getenv("ENKV_RELEASE_REAL_CLI_ARCHIVE"); archivePath != "" {
		t.Run("real-packaged-cli-roots", func(t *testing.T) {
			cliKey, e := publicKey(filepath.Join(dir, "keys/cli-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			pluginKey, e := publicKey(filepath.Join(dir, "keys/plugin-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			if e := inspectCLI(archivePath, runtime.GOOS+"/"+runtime.GOARCH, cliKey, pluginKey, "development"); e != nil {
				t.Fatal(e)
			}
			wrong := append([]byte(nil), cliKey...)
			wrong[0] ^= 1
			if e := inspectCLI(archivePath, runtime.GOOS+"/"+runtime.GOARCH, wrong, pluginKey, "development"); e == nil {
				t.Fatal("wrong embedded CLI root accepted")
			}
		})
	}
	cliDir := cliFixture(t, newer, "")
	combined := filepath.Join(t.TempDir(), "combined")
	if e := catalog(t.Context(), newer, cliDir, next, combined); e != nil {
		t.Fatal(e)
	}
	page, e := os.ReadFile(filepath.Join(combined, "index.html"))
	if e != nil || !strings.Contains(string(page), "Apple silicon") && runtime.GOOS == "darwin" {
		t.Fatal("CLI install page missing", e)
	}
	after, e := os.ReadFile(filepath.Join(combined, "plugins/generic-json/index.json"))
	if e != nil || !bytes.Equal(after, body) {
		t.Fatal("adding CLI changed signed plugin selection")
	}
	if destination := os.Getenv("ENKV_RELEASE_COMBINED_EXAMPLE"); destination != "" {
		if e := os.CopyFS(filepath.Join(destination, "site"), os.DirFS(combined)); e != nil {
			t.Fatal(e)
		}
		if e := os.CopyFS(filepath.Join(destination, "cli-candidate"), os.DirFS(cliDir)); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(archive)
	if e != nil {
		t.Fatal(e)
	}
	b[len(b)/2] ^= 1
	mustWrite(t, archive, b)
	if _, e := checkedCandidate(t.Context(), inv, dir); e == nil {
		t.Fatal("tampered archive accepted")
	}
}

// full_only: false
func TestRedirectPolicy(t *testing.T) {
	for _, url := range []string{"https://evil.test/payload", "http://github.com/enkv-sh/core/releases/download/v1/a", "https://github.com.evil.test/enkv-sh/core/releases/download/v1/a", "https://github.com/enkv-sh/core/releases/download/v1/../a"} {
		if validRedirect(redirect{"/releases/cli/a", url}) {
			t.Fatal("untrusted redirect accepted", url)
		}
	}
}

// full_only: false
func TestProductionCLICandidateRefusesCustomTLSRoots(t *testing.T) {
	inv := inventory{CLIVersion: "0.1.0-beta.1", Platforms: []platform{{Platform: runtime.GOOS + "/" + runtime.GOARCH}}}
	for _, custom := range []string{"", "custom-root"} {
		t.Run(fmt.Sprintf("custom=%t", custom != ""), func(t *testing.T) {
			dir := cliFixture(t, inv, custom)
			cliKey, e := publicKey(filepath.Join(dir, "keys/cli-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			pluginKey, e := publicKey(filepath.Join(dir, "keys/plugin-public.pem"))
			if e != nil {
				t.Fatal(e)
			}
			tuple := strings.ReplaceAll(inv.Platforms[0].Platform, "/", "-")
			path := filepath.Join(dir, "cli", tuple, "enkv-full-"+inv.CLIVersion+"-"+tuple+".tar.gz")
			err := inspectCLI(path, inv.Platforms[0].Platform, cliKey, pluginKey, "production")
			if custom == "" && err != nil {
				t.Fatal(err)
			}
			if custom != "" && err == nil {
				t.Fatal("production candidate accepted custom TLS roots")
			}
		})
	}
}

// full_only: false
func TestPriorCatalogAuthenticatesUnindexedRetainedRoutes(t *testing.T) {
	inv, dir, key := pluginFixture(t, "0.1.0")
	site := filepath.Join(t.TempDir(), "site")
	if e := catalog(t.Context(), inv, dir, "", site); e != nil {
		t.Fatal(e)
	}
	signIndexes(t, site, key)
	if e := finalize(inv, site, filepath.Join(dir, "keys/plugin-public.pem")); e != nil {
		t.Fatal(e)
	}
	old, oldDir, _ := pluginFixture(t, "0.0.9")
	tuple := strings.ReplaceAll(old.Platforms[0].Platform, "/", "-")
	versionRoute := "plugins/generic-json/0.0.9/" + tuple
	raw, e := os.ReadFile(filepath.Join(oldDir, versionRoute, "archive.json"))
	if e != nil {
		t.Fatal(e)
	}
	record, e := artifact.DecodeArchiveRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := os.ReadFile(filepath.Join(oldDir, versionRoute, "archive.sig"))
	if e != nil {
		t.Fatal(e)
	}
	artifactRoute := "artifacts/" + record.Artifact.String()
	for _, condition := range []string{"valid", "standalone-artifact", "version-only", "missing-index-signature", "missing-index", "missing-index-pair", "damaged-artifact-signature", "missing-artifact-signature", "damaged-version-signature", "wrong-artifact-redirect", "wrong-version-redirect"} {
		t.Run(condition, func(t *testing.T) {
			previous := filepath.Join(t.TempDir(), "previous")
			if e := os.CopyFS(previous, os.DirFS(site)); e != nil {
				t.Fatal(e)
			}
			var redirects []redirect
			body, e := os.ReadFile(filepath.Join(previous, "redirects.json"))
			if e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(body, &redirects); e != nil {
				t.Fatal(e)
			}
			routes := []string{artifactRoute}
			if condition == "version-only" {
				routes = nil
			}
			if condition != "standalone-artifact" {
				routes = append(routes, versionRoute)
			}
			for _, route := range routes {
				mustWrite(t, filepath.Join(previous, route, "archive.json"), raw)
				mustWrite(t, filepath.Join(previous, route, "archive.sig"), sig)
				target := assetURL("plugins", old.PluginTag, record.Archive.Filename)
				if condition == "wrong-artifact-redirect" && route == artifactRoute || condition == "wrong-version-redirect" && route == versionRoute {
					target = assetURL("plugins", old.PluginTag, "wrong.tar.gz")
				}
				redirects = append(redirects, redirect{"/releases/" + route + "/" + record.Archive.Filename, target})
			}
			encoded, e := json.Marshal(redirects)
			if e != nil {
				t.Fatal(e)
			}
			mustWrite(t, filepath.Join(previous, "redirects.json"), encoded)
			remove := func(path string) {
				if e := os.Remove(filepath.Join(previous, path)); e != nil {
					t.Fatal(e)
				}
			}
			switch condition {
			case "missing-index-signature":
				remove("plugins/generic-json/index.sig")
			case "missing-index":
				remove("plugins/generic-json/index.json")
			case "missing-index-pair":
				remove("plugins/generic-json/index.sig")
				remove("plugins/generic-json/index.json")
			case "damaged-artifact-signature":
				bad := append([]byte(nil), sig...)
				bad[0] ^= 1
				mustWrite(t, filepath.Join(previous, artifactRoute, "archive.sig"), bad)
			case "missing-artifact-signature":
				remove(artifactRoute + "/archive.sig")
			case "damaged-version-signature":
				bad := append([]byte(nil), sig...)
				bad[0] ^= 1
				mustWrite(t, filepath.Join(previous, versionRoute, "archive.sig"), bad)
			}
			output := filepath.Join(t.TempDir(), "merged")
			err := catalog(t.Context(), inv, dir, previous, output)
			if condition != "valid" && condition != "standalone-artifact" {
				if err == nil {
					t.Fatal("unauthenticated prior catalog accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, route := range routes {
				body, e := os.ReadFile(filepath.Join(output, route, "archive.json"))
				if e != nil || !bytes.Equal(body, raw) {
					t.Fatal("retained record changed", e)
				}
			}
			before, e := os.ReadFile(filepath.Join(previous, "plugins/generic-json/index.json"))
			if e != nil {
				t.Fatal(e)
			}
			after, e := os.ReadFile(filepath.Join(output, "plugins/generic-json/index.json"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("previous selection changed", e)
			}
		})
	}
}

// full_only: false
func TestCLIBuildMetadataUsesCanonicalArchiveFilename(t *testing.T) {
	inv := inventory{CLIVersion: "0.1.0-beta.1+build.7", Platforms: []platform{{Platform: runtime.GOOS + "/" + runtime.GOARCH}}}
	dir := cliFixture(t, inv, "")
	tuple := strings.ReplaceAll(inv.Platforms[0].Platform, "/", "-")
	name := "enkv-full-0.1.0-beta.1_build.7-" + tuple + ".tar.gz"
	if _, e := os.Stat(filepath.Join(dir, "cli", tuple, name)); e != nil {
		t.Fatal(e)
	}
	realInventory, e := readInventory("../../../../distribution/release.json")
	if e != nil {
		t.Fatal(e)
	}
	realInventory.CLIVersion = inv.CLIVersion
	inventoryPath := filepath.Join(t.TempDir(), "release.json")
	if e := writeJSON(inventoryPath, realInventory); e != nil {
		t.Fatal(e)
	}
	var matrix bytes.Buffer
	if e := run(t.Context(), []string{"matrix", "-inventory", inventoryPath, "-kind", "cli"}, &matrix); e != nil {
		t.Fatal(e)
	}
	var result struct {
		Include []struct {
			Archive string `json:"archive"`
			Tuple   string `json:"tuple"`
		} `json:"include"`
	}
	if e := json.Unmarshal(matrix.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	for _, row := range result.Include {
		if row.Archive != "enkv-full-0.1.0-beta.1_build.7-"+row.Tuple+".tar.gz" {
			t.Fatal("matrix archive filename differs", row.Archive)
		}
	}
	page := installationPage(inv)
	if !strings.Contains(page, "https://github.com/enkv-sh/core/releases/download/v0.1.0-beta.1+build.7/"+name) {
		t.Fatal("installation link does not use the canonical archive name")
	}
}
