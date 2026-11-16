package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestCollectLegalFilesUsesCompiledSourceOwners(t *testing.T) {
	main, replaced, goRoot := t.TempDir(), t.TempDir(), t.TempDir()
	for path, body := range map[string]string{filepath.Join(main, "LICENSE"): "author license", filepath.Join(replaced, "LICENSE.txt"): "replacement license", filepath.Join(replaced, "NOTICE.txt"): "replacement notice", filepath.Join(goRoot, "LICENSE"): "Go license"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := &SourceModule{Path: "example.test/main", Dir: main, Main: true}
	helper := &SourceModule{Path: "example.test/helper", Dir: filepath.Join(main, "unused-original"), Version: "v1.2.3", Replace: &SourceModule{Path: "example.test/replacement", Version: "v2.3.4", Dir: replaced}}
	packages := []SourcePackage{{Dir: replaced, Module: helper}, {Dir: main, Module: owner}, {Standard: true}, {Dir: replaced, Module: helper}}
	files, err := CollectLegalFiles(t.Context(), packages, owner.Path, goRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := "Module: example.test/helper\nVersion: v1.2.3\nReplacement: example.test/replacement\nReplacement version: v2.3.4\nSource file: LICENSE.txt\n\nreplacement license\n\n" +
		"Module: example.test/helper\nVersion: v1.2.3\nReplacement: example.test/replacement\nReplacement version: v2.3.4\nSource file: NOTICE.txt\n\nreplacement notice\n\n" +
		"Module: example.test/main\nVersion: \nSource file: LICENSE\n\nauthor license\n\n" +
		"Go toolchain\nSource file: LICENSE\n\nGo license\n\n"
	if len(files) != 2 || string(files["LICENSE"]) != "author license" || string(files["THIRD_PARTY_NOTICES.md"]) != want {
		t.Fatalf("legal owner set or exact bytes differ: %#v", files)
	}
	slices.Reverse(packages)
	again, err := CollectLegalFiles(t.Context(), packages, owner.Path, goRoot)
	if err != nil || !reflect.DeepEqual(files, again) {
		t.Fatal("package order changed legal material", err)
	}
}

// full_only: false
func TestCollectLegalFilesPreservesAliasesAndGoLicense(t *testing.T) {
	main, goRoot := t.TempDir(), t.TempDir()
	names := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(main, name), []byte("exact "+name+" bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(goRoot, "LICENSE"), []byte("exact Go bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	packages := []SourcePackage{{Dir: main, Module: &SourceModule{Path: "example.test/main", Dir: main}}}
	files, err := CollectLegalFiles(t.Context(), packages, "example.test/main", goRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 || string(files["LICENSE"]) != "exact LICENSE bytes" {
		t.Fatal("main license was changed or fixed legal members are missing", files)
	}
	for _, name := range names {
		section := []byte("Source file: " + name + "\n\nexact " + name + " bytes\n\n")
		if bytes.Count(files["THIRD_PARTY_NOTICES.md"], section) != 1 {
			t.Fatal("co-present legal alias omitted or duplicated", name)
		}
	}
	if !strings.Contains(string(files["NOTICE"]), "\n\nexact NOTICE bytes\n\n") || !strings.Contains(string(files["NOTICE"]), "\n\nexact NOTICE.txt bytes\n\n") || !bytes.HasSuffix(files["THIRD_PARTY_NOTICES.md"], []byte("exact Go bytes\n\n")) {
		t.Fatal("notice aliases or Go license were omitted")
	}
	if err := os.Remove(filepath.Join(main, "LICENSE.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(main, "LICENSE"), filepath.Join(main, "LICENSE.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectLegalFiles(t.Context(), packages, "example.test/main", goRoot); err == nil {
		t.Fatal("invalid co-present alias was ignored")
	}
	if err := os.Remove(filepath.Join(main, "LICENSE.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(goRoot, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectLegalFiles(t.Context(), packages, "example.test/main", goRoot); err == nil {
		t.Fatal("missing Go license was ignored")
	}
}

// full_only: false
func TestLegalMaterialFollowsSelectedInputs(t *testing.T) {
	root, goRoot := t.TempDir(), t.TempDir()
	const preamble = "// Copyright First Author\r\n// SPDX-License-Identifier: Apache-2.0\r\n\r\n/* Copyright Second Author. BSD terms apply. */\r\n\r\n"
	inputs := map[string]string{
		"LICENSE": "main license", "NOTICE": "main notice", "AUTHORS": "authors", "PATENTS": "patent grant",
		"internal/NOTICE.md": "ancestor notice", "internal/nested/LICENSE": "nested BSD license",
		"internal/nested/helper.go": preamble + "package helper\n", "internal/nested/data/COPYING": "embedded data license",
		"internal/nested/data/value.txt": "embedded value", "internal/unused/LICENSE": "unselected sibling license",
	}
	for name, body := range inputs {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(goRoot, "LICENSE"), []byte("Go license"), 0600); err != nil {
		t.Fatal(err)
	}
	owner := &SourceModule{Path: "example.test/main", Replace: &SourceModule{Path: "example.test/replacement", Dir: root}}
	pkg := SourcePackage{Dir: filepath.Join(root, "internal/nested"), Module: owner, GoFiles: []string{"helper.go"}, EmbedFiles: []string{"data/value.txt"}}
	packages := []SourcePackage{pkg, pkg}
	files, err := CollectLegalFiles(t.Context(), packages, owner.Path, goRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"LICENSE": "main license", "NOTICE": "main notice", "AUTHORS": "authors", "PATENTS": "patent grant", "internal/NOTICE.md": "ancestor notice", "internal/nested/LICENSE": "nested BSD license", "internal/nested/data/COPYING": "embedded data license", "internal/nested/helper.go (leading comments)": preamble}
	for name, body := range want {
		section := []byte("Source file: " + name + "\n\n" + body + "\n\n")
		if bytes.Count(files["THIRD_PARTY_NOTICES.md"], section) != 1 {
			t.Errorf("missing or duplicated exact legal bytes: %s", name)
		}
	}
	if bytes.Contains(files["THIRD_PARTY_NOTICES.md"], []byte("unselected sibling")) || bytes.Contains(files["THIRD_PARTY_NOTICES.md"], []byte("package helper")) {
		t.Fatal("unselected legal material or code was included")
	}
	if string(files["LICENSE"]) != "main license" || !bytes.Contains(files["NOTICE"], []byte("main notice")) {
		t.Fatal("root legal members changed")
	}
	first, err := CaptureSources(t.Context(), "output", packages)
	if err != nil {
		t.Fatal(err)
	}
	// Independently framed with Python struct/hashlib from the nine literal inputs.
	if len(first) != 1 || first[0].Digest.String() != "cffbe253e41cefae11fa75aeb3c1f273bb6d5d180bb8831e66a2c67b02a63639" {
		t.Fatalf("legal source inventory differs: %+v", first)
	}
	for _, name := range []string{"internal/NOTICE.md", "internal/nested/LICENSE", "internal/nested/data/COPYING", "AUTHORS", "PATENTS"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			if err := os.WriteFile(path, []byte(inputs[name]+" changed"), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := CaptureSources(t.Context(), "output", packages)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(first, changed) {
				t.Error("legal bytes missing from source digest")
			}
			if err := os.WriteFile(path, []byte(inputs[name]), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(root, "internal/unused/LICENSE"), []byte("changed unused license"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := CaptureSources(t.Context(), "output", packages)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("unselected sibling changed source digest", err)
	}
	if err := os.Remove(filepath.Join(root, "internal/nested/LICENSE")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "LICENSE"), filepath.Join(root, "internal/nested/LICENSE")); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectLegalFiles(t.Context(), packages, owner.Path, goRoot); err == nil {
		t.Fatal("symlink legal file accepted")
	}
	if _, err := CaptureSources(t.Context(), "output", packages); err == nil {
		t.Fatal("symlink legal file captured")
	}
	pkg.Dir = t.TempDir()
	if _, err := CollectLegalFiles(t.Context(), []SourcePackage{pkg}, owner.Path, goRoot); err == nil {
		t.Fatal("package outside owner accepted")
	}
}

// full_only: false
func TestCollectLegalFilesRequiresCompleteSelectedOwners(t *testing.T) {
	main, helper, goRoot := t.TempDir(), t.TempDir(), t.TempDir()
	for path, body := range map[string]string{filepath.Join(main, "LICENSE"): "main license", filepath.Join(goRoot, "LICENSE"): "Go license"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	owner := &SourceModule{Path: "example.test/main", Dir: main}
	for _, packages := range [][]SourcePackage{
		{{Dir: main, Module: owner}, {Dir: helper, Module: &SourceModule{Path: "example.test/helper", Dir: helper}}},
		{{Dir: main, Module: owner}, {}},
		{{Dir: main, Module: owner}, {Dir: helper, Module: &SourceModule{Path: owner.Path, Dir: helper}}},
		{{Standard: true}},
	} {
		if files, err := CollectLegalFiles(t.Context(), packages, owner.Path, goRoot); err == nil || files != nil {
			t.Fatal("incomplete or inconsistent selected legal owners were accepted", files, err)
		}
	}
}

// full_only: false
func TestLeadingSourceCommentsPreserveBytes(t *testing.T) {
	for _, test := range []struct{ name, source, want string }{
		{"line_at_eof", "// notice", "// notice"},
		{"blocks_and_build_tag", "//go:build linux\n\n/* first */\n\n// second\n\npackage x", "//go:build linux\n\n/* first */\n\n// second\n\n"},
		{"bom", "\xef\xbb\xbf// notice\npackage x", "\xef\xbb\xbf// notice\n"},
		{"code_first", "package x\n// ordinary code comment\n", ""},
		{"whitespace", "\t\r\n", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := leadingSourceComments([]byte(test.source))
			if err != nil || string(got) != test.want {
				t.Fatalf("comments %q, want %q: %v", got, test.want, err)
			}
		})
	}
	if _, err := leadingSourceComments([]byte("/* unfinished")); err == nil {
		t.Fatal("malformed comment ignored")
	}
}

// full_only: false
func TestCollectLegalFilesPreservesLaterGoCommentsAndSourceSymlinks(t *testing.T) {
	for _, link := range []bool{false, true} {
		name := "regular"
		if link {
			name = "confined_symlink"
		}
		t.Run(name, func(t *testing.T) {
			root, goRoot := t.TempDir(), t.TempDir()
			const source = "package helper\r\n// Copyright later line\r\nvar value = \"// not a comment\"\r\n/* Later notice\r\nexact bytes */\r\n"
			for path, body := range map[string]string{filepath.Join(root, "LICENSE"): "main license", filepath.Join(root, "actual.go"): source, filepath.Join(goRoot, "LICENSE"): "Go license"} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			file := "actual.go"
			if link {
				file = "linked.go"
				if err := os.Symlink(filepath.Join(root, "actual.go"), filepath.Join(root, file)); err != nil {
					t.Fatal(err)
				}
			}
			pkg := SourcePackage{Dir: root, Module: &SourceModule{Path: "example.test/main", Dir: root}, GoFiles: []string{file}}
			files, err := CollectLegalFiles(t.Context(), []SourcePackage{pkg}, pkg.Module.Path, goRoot)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"Source file: " + file + ":2 (comment)\n\n// Copyright later line\r\n\n", "Source file: " + file + ":4 (comment)\n\n/* Later notice\r\nexact bytes */\n\n"} {
				if !bytes.Contains(files["THIRD_PARTY_NOTICES.md"], []byte(want)) {
					t.Errorf("missing exact source comment %q", want)
				}
			}
			if bytes.Contains(files["THIRD_PARTY_NOTICES.md"], []byte("not a comment")) {
				t.Fatal("string literal treated as comment")
			}
			if link {
				if err := os.Remove(filepath.Join(root, file)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(goRoot, "LICENSE"), filepath.Join(root, file)); err != nil {
					t.Fatal(err)
				}
				if _, err := CollectLegalFiles(t.Context(), []SourcePackage{pkg}, pkg.Module.Path, goRoot); err == nil {
					t.Fatal("escaping source symlink accepted")
				}
			}
		})
	}
}

// full_only: false
func TestLegalSourceAncestorsStayWithinOwner(t *testing.T) {
	root, outside, goRoot := t.TempDir(), t.TempDir(), t.TempDir()
	for path, body := range map[string]string{
		filepath.Join(root, "LICENSE"): "main license", filepath.Join(root, "data"): "selected data",
		filepath.Join(outside, "NOTICE"): "outside notice", filepath.Join(goRoot, "LICENSE"): "Go license",
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "bridge")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(outside, "back")); err != nil {
		t.Fatal(err)
	}
	pkg := SourcePackage{Dir: root, Module: &SourceModule{Path: "example.test/main", Dir: root}, EmbedFiles: []string{"bridge/back/data"}}
	if _, err := CollectLegalFiles(t.Context(), []SourcePackage{pkg}, pkg.Module.Path, goRoot); err == nil {
		t.Fatal("outside ancestor accepted because final input returned inside owner")
	}
	if _, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg}); err == nil {
		t.Fatal("outside ancestor captured")
	}
}
