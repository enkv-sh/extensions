package build

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestRunBuildsUnlistedAuthorWithoutSDKOrProviderCatalog(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	root := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":  "module private.example/team/inventory\n\ngo 1.27.0\n",
		"LICENSE": "private author license\n",
		"main.go": "package main\nfunc main(){panic(\"build must not execute the plugin\")}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root})
	config.Descriptor = writeBuildDescriptor(t, root, "private-inventory-plugin", "manifest-generator", "2.3.4")
	marker, err := Run(t.Context(), config)
	if err != nil {
		t.Fatal("unlisted author refused", err)
	}
	metadata, err := artifact.VerifyBuild(t.Context(), config.Output)
	if err != nil || metadata.Name != "private-inventory-plugin" || metadata.MainModule != "private.example/team/inventory" || metadata.Command != "private.example/team/inventory" || metadata.Version != "2.3.4" || metadata.Family == nil || metadata.Family.Schema != artifact.FamilySchema {
		t.Fatal("measured independent author facts changed", err)
	}
	descriptor, err := metadata.Descriptor()
	if err != nil || descriptor.Name != metadata.Name || descriptor.Wire.Version != 9 {
		t.Fatal("author declaration changed", err)
	}
	identity, err := metadata.Identity()
	if err != nil || identity != marker.Artifact {
		t.Fatal("complete metadata does not bind the build", err)
	}
	dependency, err := os.ReadFile(filepath.Join(config.Output, marker.Directory, "dependencies.bin"))
	if err != nil {
		t.Fatal("manifest dependency body missing", err)
	}
	facts, err := artifact.DecodeDependency(dependency)
	if err != nil || len(facts.Compiled) != 1 || facts.Compiled[0].Path != "private.example/team/inventory" {
		t.Fatal("actual dependency closure changed", err)
	}
}

// full_only: false
func TestRunBindsEmbeddedAuthorDescriptorBytes(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	root := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":  "module private.example/embedded\n\ngo 1.27.0\n",
		"LICENSE": "private author license\n",
		"main.go": "package main\nimport _ \"embed\"\n//go:embed enkv-plugin.json\nvar descriptor []byte\nfunc main(){println(len(descriptor))}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root})
	first, err := Run(t.Context(), config)
	if err != nil {
		t.Fatal("embedded descriptor refused", err)
	}
	before, err := artifact.VerifyBuild(t.Context(), config.Output)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(config.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	// Formatting leaves the declared identity unchanged but changes compiler
	// input and therefore must remain in the source and executable capture.
	if err := os.WriteFile(config.Descriptor, append(bytes.Clone(original), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := Run(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	after, err := artifact.VerifyBuild(t.Context(), config.Output)
	if err != nil || before.Sources[0].Digest == after.Sources[0].Digest || first.Artifact == second.Artifact {
		t.Fatal("embedded author bytes omitted", err)
	}
	a, _ := before.Descriptor()
	b, _ := after.Descriptor()
	aID, _ := a.Identity()
	bID, _ := b.Identity()
	if aID != bID {
		t.Fatal("author formatting changed descriptor semantics")
	}
}

// full_only: false
func TestRunRefusesDescriptorChangedDuringBuild(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	root := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":  "module private.example/changing\n\ngo 1.27.0\n",
		"LICENSE": "private author license\n",
		"main.go": "package main\nfunc main(){}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := publicBuildFixtureConfig(t, root, []string{root})
	publicBuildGoCommand(t, "go1.27.3", "")
	t.Setenv("ENKV_TEST_DESCRIPTOR_CHANGE", config.Descriptor)
	marker, err := Run(t.Context(), config)
	if err == nil || err.Error() != "author descriptor changed during build" || marker != (artifact.BuildMarker{}) {
		t.Fatal("changed descriptor did not refuse before publication", marker, err)
	}
	if _, err := os.Lstat(filepath.Join(config.Output, "build.json")); !os.IsNotExist(err) {
		t.Fatal("changed descriptor published a build marker", err)
	}
}

// full_only: false
func TestRunPreservesLogicalAuthorDirectoryForWorkspace(t *testing.T) {
	cleanPublicBuildEnvironment(t)
	real := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":  "module private.example/logical\n\ngo 1.27.0\n",
		"LICENSE": "private author license\n",
		"main.go": "package main\nfunc main(){}\n",
	} {
		if err := os.WriteFile(filepath.Join(real, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	logical := filepath.Join(t.TempDir(), "author")
	if err := os.Symlink(real, logical); err != nil {
		t.Fatal(err)
	}
	config := publicBuildFixtureConfig(t, logical, []string{logical})
	// Explicit child environments must not carry this parent's directory into
	// the nested Go command or resolve the alias to a different workspace path.
	t.Setenv("PWD", t.TempDir())
	marker, err := Run(t.Context(), config)
	if err != nil || marker.Artifact.IsZero() {
		t.Fatal("logical author directory failed workspace selection", err)
	}
	metadata, err := artifact.VerifyBuild(t.Context(), config.Output)
	if err != nil || metadata.MainModule != "private.example/logical" {
		t.Fatal("logical author directory changed measured module", err)
	}
}
