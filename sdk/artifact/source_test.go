package artifact

import (
	"context"
	"crypto/sha256"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestSourceCaptureTracksSelectedBytesAndOwner(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/helper\n", "helper.go": "package helper\n", "data.bin": "a", "helper.s": "#include \"local.h\"\n", "local.h": "// header\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	module := SourceModule{Path: "example.test/helper", Dir: root, Version: "v1.2.3"}
	pkg := SourcePackage{Dir: root, Module: &module, GoFiles: []string{"helper.go"}, SFiles: []string{"helper.s"}, HFiles: []string{"local.h"}, EmbedFiles: []string{"data.bin"}}
	first, err := CaptureSources(context.Background(), "output", []SourcePackage{pkg})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Module != module.Path || first[0].Digest.IsZero() {
		t.Fatalf("sources: %#v", first)
	}
	if err := os.WriteFile(filepath.Join(root, "data.bin"), []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := CaptureSources(context.Background(), "output", []SourcePackage{pkg})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Digest == second[0].Digest {
		t.Fatal("selected embedded change did not change digest")
	}
	module.Version = ""
	if _, err := CaptureSources(context.Background(), "output", []SourcePackage{pkg}); err == nil {
		t.Fatal("local assembly input accepted")
	}
	module.Version = "v1.2.3"
	if err := os.WriteFile(filepath.Join(root, "helper.s"), []byte("#include \"../foreign.h\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureSources(context.Background(), "output", []SourcePackage{pkg}); err == nil {
		t.Fatal("external assembler include accepted")
	}
}

// full_only: false
func TestSourceCaptureRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/author\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(other, "foreign.go"), []byte("package foreign\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "foreign.go"), filepath.Join(root, "main.go")); err != nil {
		t.Fatal(err)
	}
	module := SourceModule{Path: "example.test/author", Dir: root, Main: true}
	if _, err := CaptureSources(context.Background(), "manifest-generator", []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"main.go"}}}); err == nil {
		t.Fatal("source escaped module owner")
	}
}

// full_only: false
func TestSourceDigestUsesExactFramingAndRoleDomain(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module x\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	module := SourceModule{Path: "x", Dir: root, Main: true}
	sources, err := CaptureSources(context.Background(), "manifest-generator", []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"a.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	// The literal is domain+NUL, B("x"), count 3, followed by the sorted
	// LICENSE="L", a.go="package a\n", and go.mod="module x\n" framed pairs.
	expected := Digest(sha256.Sum256([]byte("ENKV/MANIFEST/v1/source-set\x00\x00\x00\x00\x01x\x00\x00\x00\x03\x00\x00\x00\x07LICENSE\x00\x00\x00\x01L\x00\x00\x00\x04a.go\x00\x00\x00\x0apackage a\n\x00\x00\x00\x06go.mod\x00\x00\x00\x09module x\n")))
	if sources[0].Digest != expected {
		t.Fatalf("digest %s, want %s", sources[0].Digest, expected)
	}
	other, err := CaptureSources(context.Background(), "generator", []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"a.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].Digest == other[0].Digest {
		t.Fatal("source role domains were merged")
	}
}

// full_only: false
func TestSourceCaptureBindsEveryPresentLegalFilename(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"go.mod": "module example.test/helper\n", "helper.go": "package helper\n", "LICENSE": "license", "LICENSE.txt": "text license", "LICENSE.md": "markdown license", "NOTICE": "notice", "NOTICE.txt": "text notice", "THIRD_PARTY_NOTICES.md": "third party notices"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	module := SourceModule{Path: "example.test/helper", Dir: root, Main: true}
	packages := []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"helper.go"}}}
	first, err := CaptureSources(t.Context(), "output", packages)
	if err != nil {
		t.Fatal(err)
	}
	// Independently framed from the eight literal files with Python struct/hashlib.
	const expected = "4ff88a263e52fae4a6b99268fa952c2e148c1089ce6eecba843a3065685a506f"
	if len(first) != 1 || first[0].Module != module.Path || first[0].Digest.String() != expected {
		t.Errorf("complete legal source set differs: %+v, want %s", first, expected)
	}
	for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md"} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, name), []byte(files[name]+" changed"), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := CaptureSources(t.Context(), "output", packages)
			if err != nil {
				t.Fatal(err)
			}
			if first[0].Digest == changed[0].Digest {
				t.Error("present legal file bytes were omitted", name)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte(files[name]), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestSourceCaptureBindsLegalFilenameAndRefusesInvalidPresentAliases(t *testing.T) {
	t.Run("same_bytes_different_name", func(t *testing.T) {
		root := t.TempDir()
		for name, body := range map[string]string{"go.mod": "module example.test/helper\n", "helper.go": "package helper\n", "LICENSE.txt": "same license bytes"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		module := SourceModule{Path: "example.test/helper", Dir: root, Main: true}
		packages := []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"helper.go"}}}
		first, err := CaptureSources(t.Context(), "output", packages)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(root, "LICENSE.txt"), filepath.Join(root, "LICENSE.md")); err != nil {
			t.Fatal(err)
		}
		second, err := CaptureSources(t.Context(), "output", packages)
		if err != nil {
			t.Fatal(err)
		}
		if first[0].Digest == second[0].Digest {
			t.Fatal("legal filename was omitted from the source binding")
		}
	})
	for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md"} {
		t.Run("nonregular/"+name, func(t *testing.T) {
			root := t.TempDir()
			validLicense := "LICENSE"
			if name == validLicense {
				validLicense = "LICENSE.md"
			}
			for path, body := range map[string]string{"go.mod": "module example.test/helper\n", "helper.go": "package helper\n", validLicense: "valid license"} {
				if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
				t.Fatal(err)
			}
			module := SourceModule{Path: "example.test/helper", Dir: root, Main: true}
			if _, err := CaptureSources(t.Context(), "output", []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"helper.go"}}}); err == nil {
				t.Fatal("nonregular present legal file was omitted", name)
			}
		})
	}
}

// full_only: false
func TestUnusedLocalReplacementBindsModuleFilesAndLaterSelectedGoFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/main\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helper := t.TempDir()
	for _, owner := range []string{root, helper} {
		if err := os.WriteFile(filepath.Join(owner, "LICENSE"), []byte("test license\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main(){}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "go.mod"), []byte("module example.test/helper\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "helper.go"), []byte("package helper\nconst Value=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	main := SourceModule{Path: "example.test/main", Dir: root, Main: true}
	local := SourceModule{Path: "example.test/helper", Version: "v1.0.0", Replace: &SourceModule{Path: "../helper", Dir: helper}}
	packages := []SourcePackage{{Dir: root, Module: &main, GoFiles: []string{"main.go"}}}
	first, err := CaptureSourcesForModules(context.Background(), "generator", packages, []SourceModule{main, local})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].Module != local.Path || first[1].Module != main.Path {
		t.Fatalf("bound owner set: %+v", first)
	}
	if err := os.WriteFile(filepath.Join(helper, "go.mod"), []byte("module example.test/helper\ngo 1.27.0\n// changed module facts\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := CaptureSourcesForModules(context.Background(), "generator", packages, []SourceModule{main, local})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Digest == second[0].Digest {
		t.Fatal("unused replacement module-file change was omitted")
	}
	packages = append(packages, SourcePackage{Dir: helper, Module: &local, GoFiles: []string{"helper.go"}})
	imported, err := CaptureSourcesForModules(context.Background(), "generator", packages, []SourceModule{main, local})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helper, "helper.go"), []byte("package helper\nconst Value=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := CaptureSourcesForModules(context.Background(), "generator", packages, []SourceModule{main, local})
	if err != nil {
		t.Fatal(err)
	}
	if imported[0].Digest == changed[0].Digest {
		t.Fatal("selected replacement Go-file change was omitted")
	}
}

// full_only: false
func TestUnusedWorkspaceOwnerBindsOnlyActualModuleFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("L"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/unused\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unused.go"), []byte("package unused\n"), 0600); err != nil {
		t.Fatal(err)
	}
	module := SourceModule{Path: "example.test/unused", Dir: root, Main: true}
	first, err := CaptureSourcesForModules(context.Background(), "output", nil, []SourceModule{module})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Module != module.Path || first[0].Digest.IsZero() {
		t.Fatalf("workspace owner source: %+v", first)
	}
	if err := os.WriteFile(filepath.Join(root, "unused.go"), []byte("package unused\n// not selected\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := CaptureSourcesForModules(context.Background(), "output", nil, []SourceModule{module})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Digest != second[0].Digest {
		t.Fatal("unselected compiler input entered source digest")
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/unused\ngo 1.27.0\n// changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	third, err := CaptureSourcesForModules(context.Background(), "output", nil, []SourceModule{module})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Digest == third[0].Digest {
		t.Fatal("unused workspace module facts were omitted")
	}
}

// full_only: false
func TestSourceCaptureRejectsCommentHiddenAssemblerIncludes(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"comment_before_directive", "/* c */ #include \"../foreign.h\"\n"},
		{"comment_after_hash", "# /* c */ include \"../foreign.h\"\n"},
		{"multiline_comment_prefix", "/* first line\nsecond line */ #include \"../foreign.h\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "module")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string]string{filepath.Join(root, "LICENSE"): "L", filepath.Join(root, "go.mod"): "module example.test/helper\n", filepath.Join(parent, "foreign.h"): "#define FOREIGN 1\n", filepath.Join(root, "helper.go"): "package helper\n", filepath.Join(root, "helper.s"): test.source} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			module := SourceModule{Path: "example.test/helper", Dir: root, Version: "v1.2.3"}
			packages := []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"helper.go"}, SFiles: []string{"helper.s"}}}
			if _, err := CaptureSources(context.Background(), "output", packages); err == nil {
				t.Fatal("comment-hidden include escaped the selected module input set")
			}
		})
	}
}

// full_only: false
func TestSourceCaptureAcceptsClosedIncludesWithCommentsAndQuotedMarkers(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"comment_before_stock", "/* c */ #include \"textflag.h\"\n"},
		{"comment_after_hash_stock", "# /* c */ include \"textflag.h\"\n"},
		{"multiline_comment_before_local", "/* first\nsecond */ #include \"local.h\"\n"},
		{"quoted_comment_markers", "DATA ·text(SB)/8, $\"/* #include \\\"../foreign.h\\\" */\"\nDATA ·char(SB)/1, $'#'\n#include \"local.h\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/helper\n", "helper.go": "package helper\n", "helper.s": test.source, "local.h": "/* c */ #include \"textflag.h\"\n"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			module := SourceModule{Path: "example.test/helper", Dir: root, Version: "v1.2.3"}
			packages := []SourcePackage{{Dir: root, Module: &module, GoFiles: []string{"helper.go"}, SFiles: []string{"helper.s"}, HFiles: []string{"local.h"}}}
			if _, err := CaptureSources(context.Background(), "output", packages); err != nil {
				t.Fatal("closed selected assembler inputs refused", err)
			}
		})
	}
}

// full_only: false
func TestSourceCaptureBindsMultiChunkEmbedBytes(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, 256*513+3)
	for i := range 256 * 513 {
		data[i] = byte(i)
	}
	copy(data[256*513:], "end")
	for name, body := range map[string][]byte{"LICENSE": []byte("L"), "go.mod": []byte("module example.test/helper\n"), "helper.go": []byte("package helper\n"), "data.bin": data} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	module := SourceModule{Path: "example.test/helper", Dir: root, Version: "v1.2.3"}
	pkg := SourcePackage{Dir: root, Module: &module, GoFiles: []string{"helper.go"}, EmbedFiles: []string{"data.bin"}}
	got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
	if err != nil || len(got) != 1 || got[0].Module != module.Path || got[0].Digest.String() != "9322dbe33cc15f5a4fc69685f34dc025d684012c98c02f588534390fca44e022" {
		t.Fatalf("multi-chunk source framing differs: %v, %v", got, err)
	}
}

const sourceMacroDirective = "#define X(a,b) # a b\nX(include, \"../external.h\")\n"
const sourceDisabledBacktickDirective = "#ifdef ENKV_NEVER_DEFINED\n`\n#endif\n#include \"../external.h\"\n#ifdef ENKV_NEVER_DEFINED\n`\n#endif\n"
const sourceOrdinaryAssemblyMacro = "#define RETURN RET\n#define RETURN_AFTER(insn) \\\ninsn; \\\nRETURN\nTEXT ·probe(SB),$0-0\nRETURN_AFTER(NOP)\n"

// full_only: false
func TestSourceCaptureRejectsMacroConstructedAssemblerDirectives(t *testing.T) {
	for _, test := range []struct {
		name, body string
		selected   bool
	}{
		{"replacement", sourceMacroDirective, false},
		{"argument", "#define X(a,b,c) a b c\nX(#, include, \"../external.h\")\n", false},
		{"continued_replacement", "#define X(a,b) \\\n# a b\nX(include, \"../external.h\")\n", false},
		{"unsupported_newline_argument", "#define X(a,b,c) a b c\nX(\n#, include, \"../external.h\")\n", false},
		{"selected_header_replacement", "#define X # include \"local.h\"\nX\n", true},
		{"selected_header_continued_replacement", "#define X \\\n# include \"local.h\"\nX\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, pkg := sourceCaptureFixture(t, test.body)
			header := filepath.Join(filepath.Dir(root), "external.h")
			if test.selected {
				pkg.HFiles = []string{"local.h"}
				header = filepath.Join(root, "local.h")
			}
			for _, symbol := range []string{"before", "after"} {
				if err := os.WriteFile(header, []byte("TEXT ·"+symbol+"(SB),$0-0\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
				got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
				if err == nil || len(got) != 0 {
					t.Errorf("macro-constructed directive accepted %s header change: %v, %v", symbol, got, err)
				}
			}
		})
	}
}

// full_only: false
func TestSourceCaptureRejectsDisabledBranchBacktickIncludes(t *testing.T) {
	root, pkg := sourceCaptureFixture(t, sourceDisabledBacktickDirective)
	for _, symbol := range []string{"before", "after"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(root), "external.h"), []byte("TEXT ·"+symbol+"(SB),$0-0\nRET\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
		if err == nil || len(got) != 0 {
			t.Errorf("disabled-branch backticks hid an include %s external-header change: %v, %v", symbol, got, err)
		}
	}
}

// full_only: false
func TestSourceCaptureKeepsOrdinaryAssemblerMacrosAndSelectedHeaders(t *testing.T) {
	root, pkg := sourceCaptureFixture(t, "#include \"outer.h\"\n"+sourceOrdinaryAssemblyMacro)
	pkg.HFiles = []string{"outer.h", "inner.h", "textflag.h"}
	for name, body := range map[string]string{"outer.h": "#include \"inner.h\"\n", "inner.h": "#include \"textflag.h\"\n", "textflag.h": "#define NOSPLIT 4\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
	if err != nil || len(first) != 1 || first[0].Digest.String() != "fe99d7d1a3a218ed966cf436fb65233728b8d76775dee77250617858fe0261bd" {
		t.Fatal("ordinary macros or recursively selected headers refused", first, err)
	}
	if err := os.WriteFile(filepath.Join(root, "textflag.h"), []byte("#define NOSPLIT 8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
	if err != nil || len(second) != 1 || second[0].Digest.String() != "36c28b37ee773f9dc36769f7be1e30f3f0f25cfd997276ea4c9a25e7466d5481" {
		t.Fatal("selected local textflag bytes did not change source identity", second, err)
	}
	pkg.HFiles = []string{"outer.h", "inner.h"}
	if got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg}); err == nil || len(got) != 0 {
		t.Fatal("unselected local textflag shadow was treated as stock", got, err)
	}
}

// full_only: false
func TestSourceCaptureAdmitsOnlyBoundedRegularInputs(t *testing.T) {
	for _, input := range []struct{ name, path, body, digest string }{
		{"compiler", "helper.go", "package helper\n", "7d30218492ddd7de84dcfae99e7c4997f73b1df29e48811c0e41deaa048ecd26"},
		{"metadata", "NOTICE", "notice", "ce02ddd27b0a5b26729db8417944bc69e8a5022cbaeaebf677bd31bfdd125d51"},
	} {
		t.Run(input.name, func(t *testing.T) {
			for _, kind := range []string{"regular", "alias", "directory", "oversized", "escaping_alias"} {
				t.Run(kind, func(t *testing.T) {
					root, pkg := sourceCaptureFixture(t, "")
					path := filepath.Join(root, input.path)
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					switch kind {
					case "regular":
						if err := os.WriteFile(path, []byte(input.body), 0600); err != nil {
							t.Fatal(err)
						}
					case "alias", "escaping_alias":
						target := filepath.Join(root, "resolved-input")
						if kind == "escaping_alias" {
							target = filepath.Join(filepath.Dir(root), "external-input")
						}
						if err := os.WriteFile(target, []byte(input.body), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(target, path); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
					case "oversized":
						if err := os.WriteFile(path, nil, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Truncate(path, int64(math.MaxUint32)+1); err != nil {
							t.Fatal(err)
						}
					}
					got, err := CaptureSources(t.Context(), "output", []SourcePackage{pkg})
					if kind == "regular" || kind == "alias" {
						if err != nil || len(got) != 1 || got[0].Module != pkg.Module.Path || got[0].Digest.String() != input.digest {
							t.Fatal("bounded regular source differs from independently framed bytes", got, err)
						}
					} else if err == nil || len(got) != 0 {
						t.Fatal("invalid present source input accepted", got, err)
					}
				})
			}
		})
	}
}

func sourceCaptureFixture(t *testing.T, assembly string) (string, SourcePackage) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "module")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"LICENSE": "L", "go.mod": "module example.test/helper\n", "helper.go": "package helper\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	module := &SourceModule{Path: "example.test/helper", Dir: root, Version: "v1.2.3"}
	pkg := SourcePackage{Dir: root, Module: module, GoFiles: []string{"helper.go"}}
	if assembly != "" {
		if err := os.WriteFile(filepath.Join(root, "helper.s"), []byte(assembly), 0600); err != nil {
			t.Fatal(err)
		}
		pkg.SFiles = []string{"helper.s"}
	}
	return root, pkg
}
