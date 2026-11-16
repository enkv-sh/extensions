package build

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

func archiveBuildFixture(t *testing.T, name, version string) (Config, artifact.Metadata, string, ed25519.PublicKey) {
	t.Helper()
	root, unused := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal/helper"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(root, "go.mod"):                    "module example.test/main\n\ngo 1.27.0\n",
		filepath.Join(root, "main.go"):                   "package main\nimport \"example.test/main/internal/helper\"\nfunc main(){panic(helper.Value)}\n",
		filepath.Join(root, "LICENSE"):                   "exact author license\n",
		filepath.Join(root, "NOTICE"):                    "Required Notice: Copyright fixture author\n",
		filepath.Join(root, "internal/helper/LICENSE"):   "nested helper license\n",
		filepath.Join(root, "internal/helper/helper.go"): "// Copyright helper author\n\npackage helper\nconst Value = \"packaging must not execute the plugin\"\n",
		filepath.Join(unused, "go.mod"):                  "module example.test/unused\n\ngo 1.27.0\n",
		filepath.Join(unused, "LICENSE"):                 "unused resolved license\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root, unused})
	role := "manifest-generator"
	switch name {
	case "cloudflare-account-token":
		role = "generator"
	case "aws-secrets-manager":
		role = "output"
	}
	config.Descriptor = writeBuildDescriptor(t, root, name, role, version)
	if _, err := Run(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	metadata, err := artifact.VerifyBuild(t.Context(), config.Output)
	if err != nil {
		t.Fatal(err)
	}
	signature, public := archiveMetadataSignature(t, metadata)
	return config, metadata, signature, public
}

func archiveMetadataSignature(t *testing.T, metadata artifact.Metadata) (string, ed25519.PublicKey) {
	t.Helper()
	// RFC 8032 section 7.1 test key; never a release signing key.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	body, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(t.TempDir(), "metadata.sig")
	if err := os.WriteFile(signature, ed25519.Sign(key, body), 0600); err != nil {
		t.Fatal(err)
	}
	return signature, key.Public().(ed25519.PublicKey)
}

func archiveConfig(t *testing.T, config Config, signature string) ArchiveConfig {
	t.Helper()
	return ArchiveConfig{Build: config.Output, Directory: config.Directory, Command: config.Command, Output: filepath.Join(t.TempDir(), "archive"), Workspace: config.Workspace, MetadataSignature: signature}
}

// full_only: false
func TestArchivePackagesVerifiedBuildWithExternalMetadataSignature(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, test := range []struct{ name, version string }{
		{"cloudflare-account-token", "1.2.3"},
		{"aws-secrets-manager", "1.2.3"},
		{"generic-json", "1.2.3+fixture.1"},
	} {
		name, version := test.name, test.version
		t.Run(name, func(t *testing.T) {
			config, metadata, signature, public := archiveBuildFixture(t, name, version)
			if metadata.Toolchain != "go1.27.3" {
				t.Fatal("archive fixture did not use the exact supported compiler", metadata.Toolchain)
			}
			packaging := archiveConfig(t, config, signature)
			record, err := Archive(t.Context(), packaging)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(packaging.Output, record.Archive.Filename))
			if err != nil {
				t.Fatal(err)
			}
			if record.Archive.SHA256 != sha256.Sum256(body) || record.Archive.Length != uint64(len(body)) {
				t.Fatal("archive differs from exact independently measured bytes")
			}
			metadataDigest := sha256.Sum256(metadataBytesForArchive(t, config.Output))
			filename := "enkv-plugin-" + hex.EncodeToString(metadataDigest[:]) + ".tar.gz"
			if record.Version != version || record.Archive.Filename != filename {
				t.Fatal("archive changed the exact version or produced an unsafe filename", record.Version, record.Archive.Filename)
			}
			recordBytes, err := os.ReadFile(filepath.Join(packaging.Output, "archive.json"))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := artifact.DecodeArchiveRecord(recordBytes)
			if err != nil || !reflect.DeepEqual(record, decoded) {
				t.Fatal("archive.json is not the canonical returned record", err)
			}
			extracted := t.TempDir()
			if err := artifact.ExtractArchive(t.Context(), bytes.NewReader(body), record, extracted); err != nil {
				t.Fatal("existing extractor refused the produced archive", err)
			}
			if err := artifact.VerifyPackage(t.Context(), extracted, record); err != nil {
				t.Fatal(err)
			}
			expect := []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "dependencies.bin", "metadata.json", "metadata.sig", "plugin"}
			var got []string
			for _, member := range record.Members {
				got = append(got, member.Name)
			}
			if !slices.Equal(got, expect) {
				t.Fatal("family archive member set differs", got, expect)
			}
			metadataBytes, err := os.ReadFile(filepath.Join(extracted, "metadata.json"))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := os.ReadFile(filepath.Join(extracted, "metadata.sig"))
			if err != nil || !ed25519.Verify(public, metadataBytes, sig) {
				t.Fatal("external metadata signature was changed", err)
			}
			license, err := os.ReadFile(filepath.Join(extracted, "LICENSE"))
			if err != nil || string(license) != "exact author license\n" {
				t.Fatal("author license changed", err)
			}
			notices, err := os.ReadFile(filepath.Join(extracted, "THIRD_PARTY_NOTICES.md"))
			if err != nil || !bytes.Contains(notices, []byte("Go toolchain\nSource file: LICENSE\n\n")) || bytes.Contains(notices, []byte("unused resolved license")) || bytes.Contains(notices, []byte("example.test/unused")) {
				t.Fatal("legal material lost Go or included an uncompiled owner", err)
			}
			for _, want := range []string{"nested helper license\n", "// Copyright helper author\n", "Required Notice: Copyright fixture author\n"} {
				if !bytes.Contains(notices, []byte(want)) {
					t.Fatalf("archive omitted legal material: %q", want)
				}
			}
			notice, err := os.ReadFile(filepath.Join(extracted, "NOTICE"))
			if err != nil || !bytes.Contains(notice, []byte("Required Notice: Copyright fixture author\n")) {
				t.Fatal("archive omitted main notice", err)
			}
			after, err := artifact.VerifyBuild(t.Context(), config.Output)
			if err != nil || !reflect.DeepEqual(after, metadata) {
				t.Fatal("packaging changed the immutable local build", err)
			}
			if name == "generic-json" {
				packaging.Output = filepath.Join(t.TempDir(), "repeat")
				again, err := Archive(t.Context(), packaging)
				if err != nil || !reflect.DeepEqual(record, again) {
					t.Fatal("repeated packaging changed archive identity", err)
				}
			}
		})
	}
}

// full_only: false
func TestArchiveRefusesUnsupportedCompiler(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	config, metadata, signature, _ := archiveBuildFixture(t, "generic-json", "1.2.3")
	for _, test := range []struct{ name, executing, recorded string }{
		{"executing_1.27.0", "go1.27.0", "go1.27.3"},
		{"executing_1.27.2", "go1.27.2", "go1.27.3"},
		{"executing_devel", "devel go1.27.3", "go1.27.3"},
		{"recorded_1.27.0", "go1.27.3", "go1.27.0"},
		{"recorded_1.27.2", "go1.27.3", "go1.27.2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			packaging := archiveConfig(t, config, signature)
			if test.recorded != metadata.Toolchain {
				executable := publicBuildChangedCompiler(t, config, metadata, test.recorded)
				changed := metadata
				changed.Toolchain = test.recorded
				var err error
				changed.Executable, err = artifact.ExecutableIdentity(t.Context(), executable)
				if err != nil {
					t.Fatal(err)
				}
				changedConfig := publicBuildFixtureConfig(t, config.Directory, nil)
				changed, dependency := bindBuildMetadataFixture(t, changed)
				if _, err := artifact.PublishBuild(t.Context(), changedConfig.Output, changed, executable, dependency); err != nil {
					t.Fatal("self-consistent unsupported build fixture refused", err)
				}
				packaging.Build = changedConfig.Output
				packaging.MetadataSignature, _ = archiveMetadataSignature(t, changed)
			}
			publicBuildGoCommand(t, test.executing, "")
			record, err := Archive(t.Context(), packaging)
			if err == nil || err.Error() != "go 1.27.3 is required" || !reflect.DeepEqual(record, artifact.ArchiveRecord{}) {
				t.Fatal("unsupported archive compiler did not refuse at its policy gate", record, err)
			}
			if _, err := os.Lstat(packaging.Output); !os.IsNotExist(err) {
				t.Fatal("unsupported archive compiler published output", err)
			}
		})
	}
}

// full_only: false
func TestArchiveRefusesChangedSourceOrBuildBytes(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	config, metadata, signature, _ := archiveBuildFixture(t, "generic-json", "1.2.3")
	identity, err := metadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"source", "license", "nested license", "plugin", "short signature", "missing signature", "wrong command"} {
		t.Run(damage, func(t *testing.T) {
			packaging := archiveConfig(t, config, signature)
			var path string
			switch damage {
			case "source":
				path = filepath.Join(config.Directory, "main.go")
			case "license":
				path = filepath.Join(config.Directory, "LICENSE")
			case "nested license":
				path = filepath.Join(config.Directory, "internal/helper/LICENSE")
			case "plugin":
				path = filepath.Join(config.Output, "builds", identity.String(), "plugin")
			case "short signature":
				packaging.MetadataSignature = filepath.Join(t.TempDir(), "short.sig")
				if err := os.WriteFile(packaging.MetadataSignature, make([]byte, 63), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing signature":
				packaging.MetadataSignature = filepath.Join(t.TempDir(), "missing.sig")
			case "wrong command":
				packaging.Command = "./missing"
			}
			if path != "" {
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(path, before, 0700); err != nil {
						t.Error(err)
					}
					if err := os.Chmod(path, info.Mode().Perm()); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(path, append(bytes.Clone(before), '\n'), 0700); err != nil {
					t.Fatal(err)
				}
			}
			record, err := Archive(t.Context(), packaging)
			if err == nil || !reflect.DeepEqual(record, artifact.ArchiveRecord{}) {
				t.Fatal("invalid archive inputs produced complete facts", record, err)
			}
			if _, err := os.Lstat(packaging.Output); !os.IsNotExist(err) {
				t.Fatal("invalid archive input published output", err)
			}
		})
	}
	packaging := archiveConfig(t, config, signature)
	if err := os.Mkdir(packaging.Output, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(packaging.Output, "keep")
	if err := os.WriteFile(keep, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Archive(t.Context(), packaging); err == nil {
		t.Fatal("existing archive output was reused")
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "unchanged" {
		t.Fatal("existing archive output changed", err)
	}
}

// full_only: false
func TestArchiveRejectsMissingArgumentsBeforeGoExecution(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := Archive(ctx, ArchiveConfig{}); err == nil || !strings.Contains(err.Error(), "metadata signature") {
		t.Fatal("missing archive arguments did not refuse before Go execution", err)
	}
}

// full_only: false
func TestArchiveRefusesOutputInsideBuild(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	for _, test := range []struct {
		name         string
		alias, older bool
	}{
		{"direct_parent", false, false},
		{"symlink_parent", true, false},
		{"older_direct_parent", false, true},
		{"older_symlink_parent", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, metadata, signature, _ := archiveBuildFixture(t, "generic-json", "1.2.3")
			targetMetadata := metadata
			identity, err := metadata.Identity()
			if err != nil {
				t.Fatal(err)
			}
			immutable := filepath.Join(config.Output, "builds", identity.String())
			if test.older {
				config.Descriptor = writeBuildDescriptor(t, config.Directory, "generic-json", "manifest-generator", "1.2.4")
				if _, err := Run(t.Context(), config); err != nil {
					t.Fatal(err)
				}
				metadata, err = artifact.VerifyBuild(t.Context(), config.Output)
				if err != nil {
					t.Fatal(err)
				}
				current, err := metadata.Identity()
				if err != nil || current == identity {
					t.Fatal("new version did not select a separate current build", err)
				}
				signature, _ = archiveMetadataSignature(t, metadata)
			}
			info, err := os.Stat(immutable)
			if err != nil {
				t.Fatal(err)
			}
			// A writable directory remains a valid verified build. Refusal must
			// follow the output relationship, not incidental filesystem modes.
			if err := os.Chmod(immutable, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(immutable, info.Mode().Perm()); err != nil {
					t.Error(err)
				}
			})
			if _, err := artifact.VerifyBuild(t.Context(), config.Output); err != nil {
				t.Fatal("writable fixture is not a verified build", err)
			}
			if err := artifact.VerifyExecutable(t.Context(), filepath.Join(immutable, "plugin"), targetMetadata); err != nil {
				t.Fatal("target build executable is invalid", err)
			}
			entries, err := os.ReadDir(immutable)
			if err != nil {
				t.Fatal(err)
			}
			var beforeNames []string
			beforeBytes := make(map[string][]byte)
			for _, entry := range entries {
				beforeNames = append(beforeNames, entry.Name())
				path := filepath.Join(immutable, entry.Name())
				beforeBytes[path], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(config.Output, "build.json")
			beforeBytes[marker], err = os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			packaging := archiveConfig(t, config, signature)
			parent := immutable
			if test.alias {
				parent = filepath.Join(t.TempDir(), "immutable-alias")
				if err := os.Symlink(immutable, parent); err != nil {
					t.Fatal(err)
				}
			}
			packaging.Output = filepath.Join(parent, "archive")
			record, err := Archive(t.Context(), packaging)
			if err == nil || !reflect.DeepEqual(record, artifact.ArchiveRecord{}) {
				t.Errorf("archive output inside the build was not refused: record=%#v err=%v", record, err)
			}
			if _, err := os.Lstat(filepath.Join(immutable, "archive")); !os.IsNotExist(err) {
				t.Errorf("archive creation added an entry to the immutable build: %v", err)
			}
			after, err := artifact.VerifyBuild(t.Context(), config.Output)
			if err != nil || !reflect.DeepEqual(after, metadata) {
				t.Errorf("archive refusal did not preserve the verified build: %v", err)
			}
			entries, err = os.ReadDir(immutable)
			if err != nil {
				t.Fatal(err)
			}
			var afterNames []string
			for _, entry := range entries {
				afterNames = append(afterNames, entry.Name())
			}
			if !slices.Equal(beforeNames, afterNames) {
				t.Errorf("immutable build member set changed: before=%v after=%v", beforeNames, afterNames)
			}
			for path, expected := range beforeBytes {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Errorf("original build bytes changed at %s: %v", path, err)
				}
			}
			if err := artifact.VerifyExecutable(t.Context(), filepath.Join(immutable, "plugin"), targetMetadata); err != nil {
				t.Errorf("archive refusal did not preserve the target build executable: %v", err)
			}
		})
	}
}

// full_only: false
func TestArchiveOutputParentStaysBoundAfterSymlinkReplacement(t *testing.T) {
	build, original, replacement := t.TempDir(), t.TempDir(), t.TempDir()
	identity := artifact.Hash([]byte("selected fixture"))
	if err := os.MkdirAll(filepath.Join(build, "builds", identity.String()), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(original, alias); err != nil {
		t.Fatal(err)
	}
	parent, err := openArchiveOutputParent(build, filepath.Join(alias, "archive"), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := parent.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, alias); err != nil {
		t.Fatal(err)
	}
	if err := parent.Mkdir("archive", 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := parent.OpenRoot("archive")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveRecord(directory, []byte("held-parent fixture")); err != nil {
		t.Error(err)
	}
	if err := directory.Close(); err != nil {
		t.Error(err)
	}
	body, err := os.ReadFile(filepath.Join(original, "archive", "archive.json"))
	if err != nil || string(body) != "held-parent fixture" {
		t.Fatal("output did not remain in the held parent", err)
	}
	if _, err := os.Lstat(filepath.Join(replacement, "archive")); !os.IsNotExist(err) {
		t.Fatal("parent symlink replacement redirected archive output", err)
	}
}

func metadataBytesForArchive(t *testing.T, output string) []byte {
	t.Helper()
	marker, err := os.ReadFile(filepath.Join(output, "build.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selected struct {
		Directory string `json:"directory"`
	}
	if err := json.Unmarshal(marker, &selected); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(selected.Directory), "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestArchivePackagesMaximumIdentityWithBoundedFilename(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	name, version := strings.Repeat("n", 255), "1.2.3+"+strings.Repeat("b", 122)
	if len(version) != 128 {
		t.Fatal("maximum version fixture differs")
	}
	config, metadata, signature, public := archiveBuildFixture(t, name, version)
	packaging := archiveConfig(t, config, signature)
	record, err := Archive(t.Context(), packaging)
	if err != nil {
		t.Fatal(err)
	}
	exactMetadata := metadataBytesForArchive(t, config.Output)
	digest := sha256.Sum256(exactMetadata)
	wantFilename := "enkv-plugin-" + hex.EncodeToString(digest[:]) + ".tar.gz"
	if record.Name != name || record.Version != version || record.Platform != runtime.GOOS+"/"+runtime.GOARCH || record.Archive.Filename != wantFilename || len(record.Archive.Filename) != 83 {
		t.Fatalf("maximum identity changed: %#v", record)
	}
	raw, err := os.ReadFile(filepath.Join(packaging.Output, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := artifact.DecodeArchiveRecord(raw)
	if err != nil || !reflect.DeepEqual(decoded, record) {
		t.Fatalf("exact archive record differs: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(packaging.Output, wantFilename))
	if err != nil {
		t.Fatal(err)
	}
	extracted := t.TempDir()
	if err := artifact.ExtractArchive(t.Context(), bytes.NewReader(body), record, extracted); err != nil {
		t.Fatal(err)
	}
	captured, err := os.ReadFile(filepath.Join(extracted, "metadata.json"))
	if err != nil || !bytes.Equal(captured, exactMetadata) {
		t.Fatalf("signed metadata changed: %v", err)
	}
	sig, err := os.ReadFile(filepath.Join(extracted, "metadata.sig"))
	if err != nil || !ed25519.Verify(public, captured, sig) {
		t.Fatalf("maximum identity signature changed: %v", err)
	}
	got, err := artifact.DecodeMetadata(captured)
	if err != nil || !reflect.DeepEqual(got, metadata) {
		t.Fatalf("maximum metadata identity changed: %v", err)
	}
}
