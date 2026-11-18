package artifact

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// full_only: false
func TestVerifyBuildRefusesIncompleteAndEscapingMembers(t *testing.T) {
	root := t.TempDir()
	id := Hash([]byte("absent build"))
	marker, err := EncodeBuildMarker(BuildMarker{Schema: "enkv/plugin-build/v1", Artifact: id, Directory: "builds/" + id.String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBuild(context.Background(), root); err == nil {
		t.Fatal("incomplete build accepted")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "builds")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBuild(context.Background(), root); err == nil {
		t.Fatal("symlink build owner accepted")
	}
}

// full_only: false
func TestPublishBuildKeepsCompleteMarkerAndRefusesCorruptCollision(t *testing.T) {
	first, firstExecutable := publicationFixture(t, "first selected helper")
	second, secondExecutable := publicationFixture(t, "second selected helper")
	if first.Executable == second.Executable {
		t.Fatal("helper byte variants did not produce distinct executables")
	}
	ctx := t.Context()
	t.Run("complete_idempotent_and_corrupt_collision", func(t *testing.T) {
		root := publicationOutput(t)
		marker, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBuild(ctx, root); err != nil {
			t.Fatal(err)
		}
		before := publicationMarker(t, root)
		if _, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first)); err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := PublishBuild(canceled, root, first, firstExecutable, fixtureDependency(first)); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
		plugin := filepath.Join(root, filepath.FromSlash(marker.Directory), "plugin")
		if err := os.Chmod(plugin, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(plugin, []byte("damaged executable"), 0500); err != nil {
			t.Fatal(err)
		}
		if _, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first)); err == nil {
			t.Fatal("corrupt existing immutable folder was replaced")
		}
		if !bytes.Equal(before, publicationMarker(t, root)) {
			t.Fatal("failed publication changed prior marker")
		}
	})
	t.Run("external_executable_modes", func(t *testing.T) {
		for _, mode := range []os.FileMode{0755, 0775, 0777} {
			t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
				before, err := os.Stat(firstExecutable)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(firstExecutable, before.Mode().Perm()); err != nil {
						t.Error(err)
					}
				})
				if err := os.Chmod(firstExecutable, mode); err != nil {
					t.Fatal(err)
				}
				root := publicationOutput(t)
				_, publishErr := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first))
				if mode == 0755 && publishErr != nil || mode != 0755 && publishErr == nil {
					t.Fatal("external executable permission admission differs", mode, publishErr)
				}
				if mode != 0755 && publishErr.Error() != "executable type, mode or size refused" {
					t.Fatal("unsafe external mode did not refuse at executable admission", publishErr)
				}
				after, err := os.Stat(firstExecutable)
				if err != nil || after.Mode().Perm() != mode {
					t.Fatal("publication changed the external executable mode", err)
				}
				if mode != 0755 {
					if _, err := os.Lstat(filepath.Join(root, "build.json")); !os.IsNotExist(err) {
						t.Fatal("refused external executable published a marker", err)
					}
				}
			})
		}
	})
	t.Run("reuse_preserves_private_directory_permissions", func(t *testing.T) {
		root := publicationOutput(t)
		marker, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first))
		if err != nil {
			t.Fatal(err)
		}
		folder := filepath.Join(root, filepath.FromSlash(marker.Directory))
		if err := os.Chmod(folder, 0500); err != nil {
			t.Fatal(err)
		}
		if _, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first)); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(folder)
		if err != nil || info.Mode().Perm() != 0500 {
			t.Fatalf("reuse changed private permissions: %v %v", info, err)
		}
	})
	for _, distinct := range []bool{false, true} {
		name := "same_identity_concurrent"
		if distinct {
			name = "distinct_helper_bytes_concurrent"
		}
		t.Run(name, func(t *testing.T) {
			root := publicationOutput(t)
			metadata := []Metadata{first, first}
			executables := []string{firstExecutable, firstExecutable}
			if distinct {
				metadata[1] = second
				executables[1] = secondExecutable
			}
			type result struct {
				marker BuildMarker
				err    error
				index  int
			}
			start := make(chan struct{})
			results := make(chan result, 2)
			var workers sync.WaitGroup
			workers.Add(2)
			for index := range metadata {
				go func(index int) {
					defer workers.Done()
					<-start
					marker, err := PublishBuild(ctx, root, metadata[index], executables[index], fixtureDependency(metadata[index]))
					results <- result{marker, err, index}
				}(index)
			}
			close(start)
			completed := []result{<-results, <-results}
			workers.Wait()
			successes := 0
			for _, result := range completed {
				if result.err == nil {
					successes++
					expected, identityErr := metadata[result.index].Identity()
					if identityErr != nil {
						t.Fatal(identityErr)
					}
					if result.marker.Artifact != expected {
						t.Fatal("concurrent publisher returned another build identity")
					}
					if _, err := verifyBuildFolder(ctx, filepath.Join(root, filepath.FromSlash(result.marker.Directory)), result.marker.Artifact); err != nil {
						t.Fatal("successful concurrent publication is incomplete", err)
					}
				}
			}
			if successes == 0 {
				t.Fatal("concurrent publishers produced no complete build", completed[0].err, completed[1].err)
			}
			selected, err := VerifyBuild(ctx, root)
			if err != nil {
				t.Fatal("concurrent marker selected incomplete bytes", err)
			}
			identity, err := selected.Identity()
			if err != nil {
				t.Fatal(err)
			}
			firstID, err := first.Identity()
			if err != nil {
				t.Fatal(err)
			}
			secondID, err := second.Identity()
			if err != nil {
				t.Fatal(err)
			}
			if identity != firstID && (!distinct || identity != secondID) {
				t.Fatal("concurrent marker selected an unbound identity")
			}
		})
	}
	t.Run("foreign_empty_collision", func(t *testing.T) {
		root := publicationOutput(t)
		if _, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first)); err != nil {
			t.Fatal(err)
		}
		before := publicationMarker(t, root)
		secondID, err := second.Identity()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "builds", secondID.String())
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		ownedElsewhere, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PublishBuild(ctx, root, second, secondExecutable, fixtureDependency(second)); err == nil {
			t.Fatal("foreign empty target was replaced")
		}
		after, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(target)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(ownedElsewhere, after) || len(entries) != 0 || after.Mode() != ownedElsewhere.Mode() {
			t.Fatal("foreign empty collision was modified")
		}
		if !bytes.Equal(before, publicationMarker(t, root)) {
			t.Fatal("foreign collision changed prior marker")
		}
		if _, err := VerifyBuild(ctx, root); err != nil {
			t.Fatal("foreign collision damaged previous complete build", err)
		}
	})
	t.Run("cancel_private_build_before_publication", func(t *testing.T) {
		root := publicationOutput(t)
		if _, err := PublishBuild(ctx, root, first, firstExecutable, fixtureDependency(first)); err != nil {
			t.Fatal(err)
		}
		before := publicationMarker(t, root)
		secondID, err := second.Identity()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "builds", secondID.String())
		canceled, cancel := context.WithCancel(ctx)
		defer cancel()
		partial := &cancelOnBuildMember{Context: canceled, cancel: cancel, directory: filepath.Join(root, "builds")}
		if _, err := PublishBuild(partial, root, second, secondExecutable, fixtureDependency(second)); !errors.Is(err, context.Canceled) {
			t.Fatalf("private build cancellation: %v", err)
		}
		if !bytes.Equal(before, publicationMarker(t, root)) {
			t.Fatal("partial publication changed prior marker")
		}
		if _, err := VerifyBuild(ctx, root); err != nil {
			t.Fatal("partial publication damaged previous complete build", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned partial target was not removed", err)
		}
	})
}

type cancelOnBuildMember struct {
	context.Context
	cancel    context.CancelFunc
	directory string
}

func (c *cancelOnBuildMember) Err() error {
	entries, err := os.ReadDir(c.directory)
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".build-") {
				if members, err := os.ReadDir(filepath.Join(c.directory, entry.Name())); err == nil && len(members) > 0 {
					c.cancel()
					break
				}
			}
		}
	}
	return c.Context.Err()
}
func publicationMarker(t *testing.T, root string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, "build.json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func publicationOutput(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	return root
}
func publicationFixture(t *testing.T, value string) (Metadata, string) {
	t.Helper()
	source := t.TempDir()
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/author\n\ngo 1.27.0\n", "main.go": "package main\nfunc main(){println(message())}\n", "helper.go": "package main\nfunc message()string{return " + fmt.Sprintf("%q", value) + "}\n"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(t.TempDir(), "plugin")
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", executable, ".")
	command.Dir = source
	fixed := map[string]string{"GOWORK": "off", "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "", "CGO_ENABLED": "0", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0"}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := fixed[key]; !ok {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range fixed {
		command.Env = append(command.Env, key+"="+value)
	}
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, body)
	}
	if err := os.Chmod(executable, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	options, err := CaptureBuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	module := SourceModule{Path: info.Main.Path, Dir: source, Main: true}
	sources, err := CaptureSources(t.Context(), "manifest-generator", []SourcePackage{{Dir: source, Module: &module, GoFiles: []string{"main.go", "helper.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompiledDependencies(info, sources)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ExecutableIdentity(t.Context(), executable)
	if err != nil {
		t.Fatal(err)
	}
	m := Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: "generic-json", Role: "manifest-generator", Version: "1.2.3", MainModule: info.Main.Path, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Contracts: []Contract{}, Executable: identity, Sources: sources, Resolved: []Dependency{{Path: info.Main.Path}}, Compiled: compiled}
	descriptor := authorDescriptor("manifest-generator")
	descriptor.Name, descriptor.Version = m.Name, m.Version
	return fixtureBoundMetadata(m, descriptor), executable
}

// full_only: false
func TestBuildDirectoryCleanupPreservesForeignEntries(t *testing.T) {
	for _, condition := range []string{"replaced_file", "extra_file", "replaced_directory"} {
		t.Run(condition, func(t *testing.T) {
			root := t.TempDir()
			parent, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := parent.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := parent.Mkdir("partial", 0700); err != nil {
				t.Fatal(err)
			}
			directory, err := openBuildDirectory(parent, "partial", openBuildDirectoryFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := directory.write(t.Context(), "metadata.json", []byte("owned"), 0444); err != nil {
				t.Fatal(errors.Join(err, directory.finish(true)))
			}
			target := filepath.Join(root, "partial")
			switch condition {
			case "replaced_file":
				if err := os.Rename(filepath.Join(target, "metadata.json"), filepath.Join(root, "moved-owned-file")); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
				if err := os.WriteFile(filepath.Join(target, "metadata.json"), []byte("foreign"), 0600); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
			case "extra_file":
				if err := os.WriteFile(filepath.Join(target, "foreign"), []byte("foreign"), 0600); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
			case "replaced_directory":
				if err := os.Rename(target, filepath.Join(root, "moved-owned-directory")); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
				if err := os.WriteFile(filepath.Join(target, "foreign"), []byte("foreign"), 0600); err != nil {
					t.Fatal(errors.Join(err, directory.finish(true)))
				}
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(errors.Join(err, directory.finish(true)))
			}
			if err := directory.finish(true); err == nil {
				t.Fatal("incomplete ownership cleanup reported success")
			}
			after, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("foreign target directory was removed or replaced")
			}
			name := "foreign"
			if condition == "replaced_file" {
				name = "metadata.json"
			}
			body, err := os.ReadFile(filepath.Join(target, name))
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "foreign" {
				t.Fatal("foreign entry was changed")
			}
		})
	}
}

// full_only: false
func TestPublishBuildCreatorFailurePreservesAdoptedBuild(t *testing.T) {
	metadata, executable := publicationFixture(t, "adopted immutable bytes")
	root := publicationOutput(t)
	identity, err := metadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "builds", identity.String())
	canceled, cancel := context.WithCancel(t.Context())
	defer cancel()
	var adopted BuildMarker
	var adoptErr error
	var expected map[string][]byte
	observer := &observeCompleteBuild{Context: canceled, directory: target}
	observer.observe = func() {
		expected = make(map[string][]byte)
		for _, name := range []string{"dependencies.bin", "metadata.json", "plugin"} {
			body, err := os.ReadFile(filepath.Join(target, name))
			if err != nil {
				adoptErr = err
				cancel()
				return
			}
			expected[name] = body
		}
		adopted, adoptErr = PublishBuild(t.Context(), root, metadata, executable, fixtureDependency(metadata))
		cancel()
	}
	marker, err := PublishBuild(observer, root, metadata, executable, fixtureDependency(metadata))
	if !observer.observed || adoptErr != nil {
		t.Fatalf("adopter did not complete: observed=%v error=%v", observer.observed, adoptErr)
	}
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(marker, BuildMarker{}) {
		t.Fatalf("creator failure: marker=%#v error=%v", marker, err)
	}
	if adopted.Artifact != identity || adopted.Directory != "builds/"+identity.String() {
		t.Fatalf("adopter marker differs: %#v", adopted)
	}
	selected, err := VerifyBuild(t.Context(), root)
	if err != nil || !reflect.DeepEqual(selected, metadata) {
		t.Errorf("successful adopter lost complete build: %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != len(expected) {
		t.Errorf("adopted member set differs: %v %v", entries, err)
	}
	for name, want := range expected {
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("adopted bytes changed for %s: %v", name, err)
		}
	}
	entries, err = os.ReadDir(filepath.Join(root, "builds"))
	if err != nil || len(entries) != 1 || entries[0].Name() != identity.String() {
		t.Errorf("private stage not disposed: %v %v", entries, err)
	}
}

type observeCompleteBuild struct {
	context.Context
	directory string
	observed  bool
	observe   func()
}

func (c *observeCompleteBuild) Err() error {
	if !c.observed {
		if entries, err := os.ReadDir(c.directory); err == nil && len(entries) == 3 {
			c.observed = true
			c.observe()
		}
	}
	return c.Context.Err()
}

type failingBuildDirectory struct {
	*os.File
	condition string
	fail      func() error
}

func (d *failingBuildDirectory) Chmod(mode os.FileMode) error {
	if d.condition == "chmod stage" && mode == 0755 {
		return d.fail()
	}
	if d.condition == "chmod" && mode == 0555 {
		return d.fail()
	}
	return d.File.Chmod(mode)
}
func (d *failingBuildDirectory) Sync() error {
	if d.condition == "sync stage" && strings.HasPrefix(filepath.Base(filepath.Clean(d.Name())), ".build-") {
		return d.fail()
	}
	if d.condition == "sync immutable" {
		info, err := d.Stat()
		if err != nil {
			return err
		}
		if info.Mode().Perm() == 0555 {
			return d.fail()
		}
	}
	if d.condition == "sync parent" && filepath.Base(filepath.Clean(d.Name())) == "builds" {
		return d.fail()
	}
	return d.File.Sync()
}

// full_only: false
func TestPublishBuildDirectoryFailurePreservesPriorOrAdoptedBuild(t *testing.T) {
	previous, previousExecutable := publicationFixture(t, "prior immutable bytes")
	metadata, executable := publicationFixture(t, "new immutable bytes")
	identity, err := metadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"chmod stage", "sync stage", "chmod", "sync immutable", "sync parent"} {
		t.Run(condition, func(t *testing.T) {
			root := publicationOutput(t)
			if _, err := PublishBuild(t.Context(), root, previous, previousExecutable, fixtureDependency(previous)); err != nil {
				t.Fatal(err)
			}
			before := publicationMarker(t, root)
			target := filepath.Join(root, "builds", identity.String())
			failure := errors.New("directory operation failed")
			failed, adopted := false, false
			var adoptErr error
			fail := func() error {
				if failed {
					return nil
				}
				failed = true
				if _, err := verifyBuildFolder(t.Context(), target, identity); err == nil {
					adopted = true
					_, adoptErr = PublishBuild(t.Context(), root, metadata, executable, fixtureDependency(metadata))
				}
				return failure
			}
			opener := func(root *os.Root) (buildDirectoryFile, error) {
				file, err := root.Open(".")
				if err != nil {
					return nil, err
				}
				return &failingBuildDirectory{File: file, condition: condition, fail: fail}, nil
			}
			marker, err := publishBuild(t.Context(), root, metadata, executable, fixtureDependency(metadata), opener)
			if !failed || !errors.Is(err, failure) || !reflect.DeepEqual(marker, BuildMarker{}) {
				t.Errorf("directory failure result differs: called=%v marker=%#v error=%v", failed, marker, err)
			}
			if adoptErr != nil {
				t.Errorf("complete visible build could not be adopted: %v", adoptErr)
			}
			if adopted != (condition != "chmod stage" && condition != "sync stage") {
				t.Errorf("build visibility at %s: adopted=%v", condition, adopted)
			}
			selected, verifyErr := VerifyBuild(t.Context(), root)
			want := previous
			if adopted {
				want = metadata
			}
			if verifyErr != nil || !reflect.DeepEqual(selected, want) {
				t.Errorf("failure damaged prior or adopted build: adopted=%v error=%v", adopted, verifyErr)
			}
			if !adopted && !bytes.Equal(before, publicationMarker(t, root)) {
				t.Error("private failure changed prior marker")
			}
			if !adopted {
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("private failure exposed target: %v", err)
				}
			} else {
				for name, want := range map[string][]byte{"metadata.json": mustPublicationMetadata(t, metadata), "dependencies.bin": fixtureDependency(metadata)} {
					got, err := os.ReadFile(filepath.Join(target, name))
					if err != nil || !bytes.Equal(got, want) {
						t.Errorf("adopted member %s changed: %v", name, err)
					}
				}
				wantExecutable, err := os.ReadFile(executable)
				if err != nil {
					t.Fatal(err)
				}
				gotExecutable, err := os.ReadFile(filepath.Join(target, "plugin"))
				if err != nil || !bytes.Equal(gotExecutable, wantExecutable) {
					t.Errorf("adopted executable changed: %v", err)
				}
				members, err := os.ReadDir(target)
				if err != nil || len(members) != 3 {
					t.Errorf("adopted member set differs: %v %v", members, err)
				}
			}
			entries, err := os.ReadDir(filepath.Join(root, "builds"))
			expectedCount := 1
			if adopted {
				expectedCount++
			}
			if err != nil || len(entries) != expectedCount {
				t.Errorf("private stage not disposed: %v %v", entries, err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".build-") {
					t.Error("private stage survived failure")
				}
			}
		})
	}
	t.Run("retry after chmod failure", func(t *testing.T) {
		root := publicationOutput(t)
		if _, err := PublishBuild(t.Context(), root, previous, previousExecutable, fixtureDependency(previous)); err != nil {
			t.Fatal(err)
		}
		before := publicationMarker(t, root)
		failure := errors.New("cannot seal directory")
		opener := func(root *os.Root) (buildDirectoryFile, error) {
			file, err := root.Open(".")
			if err != nil {
				return nil, err
			}
			return &failingBuildDirectory{File: file, condition: "chmod", fail: func() error { return failure }}, nil
		}
		if _, err := publishBuild(t.Context(), root, metadata, executable, fixtureDependency(metadata), opener); !errors.Is(err, failure) {
			t.Fatalf("seal failure: %v", err)
		}
		if !bytes.Equal(before, publicationMarker(t, root)) {
			t.Fatal("seal failure changed the previous selection")
		}
		target := filepath.Join(root, "builds", identity.String())
		unsealed, err := os.Stat(target)
		if err != nil || unsealed.Mode().Perm() != 0755 {
			t.Fatalf("expected a complete owner-writable directory at its final name: %v %v", unsealed, err)
		}
		marker, err := PublishBuild(t.Context(), root, metadata, executable, fixtureDependency(metadata))
		if err != nil || marker.Artifact != identity {
			t.Fatalf("retry returned marker %v and error %v", marker, err)
		}
		sealed, err := os.Stat(target)
		if err != nil || !os.SameFile(unsealed, sealed) || sealed.Mode().Perm() != 0555 {
			t.Fatalf("retry did not seal the same directory: %v %v", sealed, err)
		}
		if selected, err := VerifyBuild(t.Context(), root); err != nil || !reflect.DeepEqual(selected, metadata) {
			t.Fatalf("retry did not select the complete build: %v", err)
		}
	})
}
func mustPublicationMetadata(t *testing.T, metadata Metadata) []byte {
	t.Helper()
	body, err := EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
