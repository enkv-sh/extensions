//go:build unix

package artifact

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestSourceCaptureRefusesFIFOWithoutOpening(t *testing.T) {
	for _, input := range []struct{ name, path string }{{"compiler", "helper.go"}, {"metadata", "NOTICE"}} {
		t.Run(input.name, func(t *testing.T) {
			root, pkg := sourceCaptureFixture(t, "")
			path := filepath.Join(root, input.path)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var got []Source
			err, blocked := joinedArtifactInputCall(t, path, func() error {
				var err error
				got, err = CaptureSources(ctx, "output", []SourcePackage{pkg})
				return err
			})
			if blocked {
				t.Error("source capture blocked until a FIFO writer was supplied")
			}
			if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
				t.Fatal("nonregular source did not return an ordinary input refusal", got, err)
			}
		})
	}
}

// full_only: false
func TestNativeAssemblerCompilesDirectiveClosureFixtures(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("admitted Go executable unavailable", err)
	}
	goPath, err = filepath.EvalSymlinks(goPath)
	if err != nil {
		t.Fatal("resolve admitted Go executable", err)
	}
	info, err := buildinfo.ReadFile(goPath)
	if err != nil || info.GoVersion != "go1.27.3" {
		t.Fatal("native fixture requires the pinned Go executable", info, err)
	}
	goRoot := filepath.Dir(filepath.Dir(goPath))
	assembler := filepath.Join(goRoot, "pkg", "tool", runtime.GOOS+"_"+runtime.GOARCH, "asm")
	for _, test := range []struct{ name, source string }{
		{"macro", sourceMacroDirective},
		{"disabled_backticks", sourceDisabledBacktickDirective},
		{"ordinary_macro", sourceOrdinaryAssemblyMacro},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _ := sourceCaptureFixture(t, test.source)
			output := filepath.Join(root, "helper.o")
			var before []byte
			for _, symbol := range []string{"before", "after"} {
				if err := os.WriteFile(filepath.Join(filepath.Dir(root), "external.h"), []byte("TEXT ·"+symbol+"(SB),$0-0\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				command := exec.CommandContext(ctx, assembler, "-p", "example.test/helper", "-o", output, "helper.s")
				command.Dir = root
				command.Env = append(os.Environ(), "GOROOT="+goRoot, "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
				command.WaitDelay = time.Second
				diagnostic, err := command.CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("native assembler fixture failed: %v: %.2048s", err, diagnostic)
				}
				object, err := os.ReadFile(output)
				if err != nil || len(object) == 0 {
					t.Fatal("native assembler produced no object", err)
				}
				if symbol == "before" {
					before = object
				} else if bytes.Equal(before, object) != (test.name == "ordinary_macro") {
					t.Fatal("native assembler external-header dependency differs from the fixture")
				}
			}
		})
	}
}
