package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestRunHelpShowsBuildAndVerifyOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("help emitted a result record")
	}
	for _, option := range []string{"-descriptor", "-workspace", "-versioned", "-verify", "-archive", "-metadata-signature"} {
		if !strings.Contains(stderr.String(), option) {
			t.Fatal("help omitted option", option)
		}
	}
}

// full_only: false
func TestRunArchiveRequiresMetadataSignatureBeforeGoExecution(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	output := filepath.Join(root, "archive-output")
	var stdout, stderr bytes.Buffer
	args := []string{"-archive", filepath.Join(root, "build-output"), "-output", output}
	if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
		t.Fatalf("missing metadata signature exit code %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires -metadata-signature") {
		t.Fatalf("missing metadata signature did not refuse before Go: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("missing metadata signature created archive output: %v", err)
	}
}

// full_only: false
func TestRunArchiveRefusesConflictingFlags(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{"verify", []string{"-verify", "build", "-archive", "build"}, "verify cannot be combined"},
		{"descriptor", []string{"-archive", "build", "-metadata-signature", "metadata.sig", "-output", "archive", "-descriptor", "enkv-plugin.json"}, "existing build descriptor"},
		{"signature_without_archive", []string{"-metadata-signature", "metadata.sig"}, "metadata-signature requires -archive"},
		{"output", []string{"-archive", "build", "-metadata-signature", "metadata.sig"}, "archive requires -output"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), test.args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("invalid archive arguments: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

// full_only: false
func TestRunArchiveProducesCanonicalRecord(t *testing.T) {
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	author, build := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(build, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	workspace := filepath.Join(t.TempDir(), "go.work")
	for path, body := range map[string]string{
		filepath.Join(author, "go.mod"):  "module example.test/author\n\ngo 1.27.0\n",
		filepath.Join(author, "main.go"): "package main\nfunc main(){panic(\"archive creation must not execute this plugin\")}\n",
		filepath.Join(author, "LICENSE"): "author license\n",
		workspace:                        fmt.Sprintf("go 1.27.0\n\nuse %q\n", filepath.ToSlash(author)),
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	descriptor := cliDescriptorFile(t, author)
	args := []string{"-descriptor", descriptor, "-directory", author, "-workspace", workspace, "-output", build}
	if code := run(ctx, args, &stdout, &stderr); code != 0 {
		t.Fatalf("build exit code %d: %s", code, stderr.String())
	}
	var marker artifact.BuildMarker
	if err := json.Unmarshal(stdout.Bytes(), &marker); err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(build, filepath.FromSlash(marker.Directory), "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8032 section 7.1 fixture key, independent of production signing roots.
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(t.TempDir(), "metadata.sig")
	if err := os.WriteFile(signature, ed25519.Sign(ed25519.NewKeyFromSeed(seed), metadata), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "archive")
	stdout.Reset()
	stderr.Reset()
	args = []string{"-archive", build, "-metadata-signature", signature, "-directory", author, "-workspace", workspace, "-output", archive}
	if code := run(ctx, args, &stdout, &stderr); code != 0 {
		t.Fatalf("archive exit code %d: %s", code, stderr.String())
	}
	var record artifact.ArchiveRecord
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(archive, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := artifact.DecodeArchiveRecord(body)
	digest := sha256.Sum256(metadata)
	if err != nil || decoded.Artifact != marker.Artifact || decoded.Archive != record.Archive || decoded.Archive.Filename != "enkv-plugin-"+hex.EncodeToString(digest[:])+".tar.gz" {
		t.Fatal("archive command did not emit its canonical record", err)
	}
	if _, err := artifact.VerifyBuild(ctx, build); err != nil {
		t.Fatal("archive command changed the local build", err)
	}
	var verified bytes.Buffer
	unusedDiagnostic := &cliDeliveryFailureWriter{failure: errors.New("unused diagnostic stream")}
	if code := run(ctx, []string{"-verify", build}, &verified, unusedDiagnostic); code != 0 || unusedDiagnostic.calls != 0 {
		t.Fatal("successful verification used the diagnostic stream", code, unusedDiagnostic.calls)
	}
	if verified.String() != string(metadata)+"\n" {
		t.Fatal("verification result differs from exact metadata and newline")
	}
	for _, mode := range []string{"error-after-prefix", "nil-error-short"} {
		t.Run("verify-result-"+mode, func(t *testing.T) {
			output := &cliDeliveryFailureWriter{}
			wantDiagnostic := "short write"
			if mode == "error-after-prefix" {
				output.failure = errors.New("controlled result delivery failure")
				wantDiagnostic = output.failure.Error()
			}
			var diagnostic bytes.Buffer
			code := run(ctx, []string{"-verify", build}, output, &diagnostic)
			if output.calls == 0 || output.attempted <= 7 || output.body.String() != `{"schem` {
				t.Fatalf("result delivery did not reach its strict JSON prefix: body=%q calls=%d attempted=%d", output.body.String(), output.calls, output.attempted)
			}
			if _, err := artifact.VerifyBuild(ctx, build); err != nil {
				t.Fatal("failed result delivery changed the local build", err)
			}
			if code != 1 || !strings.Contains(diagnostic.String(), wantDiagnostic) {
				t.Fatalf("failed result delivery: code=%d diagnostic=%q", code, diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestRunRejectsUnknownFlagsAndPositionalArguments(t *testing.T) {
	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{"unknown_flag", []string{"-unknown"}, "flag provided but not defined"},
		{"positional_argument", []string{"unexpected"}, "unexpected positional arguments"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), test.args, &stdout, &stderr); code != 2 {
				t.Fatalf("usage exit code %d: %s", code, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("unexpected error output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// full_only: false
func TestRunRequiresBuildFlagsBeforeGoExecution(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{"descriptor", []string{"-descriptor", "", "-output", t.TempDir()}, "plugin build: descriptor: required"},
		{"output", []string{"-descriptor", "descriptor.json"}, "plugin build: output: required"},
		{"directory", []string{"-directory", "", "-output", t.TempDir()}, "plugin build: directory: required"},
		{"command", []string{"-command", "", "-output", t.TempDir()}, "plugin build: command: required"},
		{"command-pattern", []string{"-command", "./...", "-output", t.TempDir()}, "plugin build: command: exact package required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), test.args, &stdout, &stderr); code != 1 {
				t.Fatalf("missing build flag exit code %d: %s", code, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("missing flag did not refuse before Go: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// full_only: false
func TestRunRefusesInvalidWorkspaceBeforeGoExecution(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	var stdout, stderr bytes.Buffer
	descriptor := cliDescriptorFile(t, t.TempDir())
	args := []string{"-descriptor", descriptor, "-output", t.TempDir(), "-workspace", "relative/go.work"}
	if code := run(context.Background(), args, &stdout, &stderr); code != 1 {
		t.Fatalf("workspace exit code %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "explicit absolute workspace file") {
		t.Fatalf("invalid workspace did not refuse before Go: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// full_only: false
func TestRunVerifyRefusesMissingAndIncompleteBuilds(t *testing.T) {
	root := t.TempDir()
	incomplete := filepath.Join(root, "incomplete")
	if err := os.Mkdir(incomplete, 0700); err != nil {
		t.Fatal(err)
	}
	digest := artifact.Hash([]byte("incomplete build"))
	body, err := artifact.EncodeBuildMarker(artifact.BuildMarker{Schema: "enkv/plugin-build/v1", Artifact: digest, Directory: "builds/" + digest.String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, "build.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, directory string }{{"missing", filepath.Join(root, "missing")}, {"incomplete", incomplete}} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), []string{"-verify", test.directory}, &stdout, &stderr); code != 1 {
				t.Fatalf("verify exit code %d: %s", code, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("verify failure output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// full_only: false
func TestRunVerifyRefusesBuildFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-verify", t.TempDir(), "-descriptor", "enkv-plugin.json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("mixed verify exit code %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "verify cannot be combined with build flags") {
		t.Fatalf("mixed verify failure output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func cliDescriptorFile(t *testing.T, directory string) string {
	t.Helper()
	descriptor := artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "generic-json", Role: "manifest-generator", Version: "1.2.3", Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest{1}.String(), Version: 9}, Manifest: &artifact.ManifestDeclaration{ConfigContractID: "private-settings/v1", FormatContractID: "private-format/v1"}}
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "enkv-plugin.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
