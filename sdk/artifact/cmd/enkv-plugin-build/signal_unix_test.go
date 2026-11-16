//go:build (darwin && arm64) || (linux && amd64)

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestCommandTerminationSettlesCompilerGroup(t *testing.T) {
	if mode := os.Getenv("ENKV_BUILD_SIGNAL_MODE"); mode != "" {
		terminationChild(t, mode)
		return
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "enkv-plugin-build")
	build := exec.CommandContext(t.Context(), realGo, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, ".")
	if body, err := build.CombinedOutput(); err != nil {
		t.Fatalf("command build failed: %v: %.4096s", err, body)
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(signal.String(), func(t *testing.T) {
			author := t.TempDir()
			for path, body := range map[string]string{
				"go.mod":  "module example.test/author\n\ngo 1.27.0\n",
				"LICENSE": "fixture license\n",
				"main.go": "package main\nfunc main() {}\n",
			} {
				if err := os.WriteFile(filepath.Join(author, path), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			scratch := t.TempDir()
			fixture := newTerminationFixture(t)
			script := "#!/bin/sh\nif [ \"$1\" != build ]; then exec \"$ENKV_BUILD_SIGNAL_REAL_GO\" \"$@\"; fi\nexec \"$ENKV_BUILD_SIGNAL_BINARY\" -test.run '^TestCommandTerminationSettlesCompilerGroup$' -test.count=1 -- \"$@\"\n"
			if err := os.WriteFile(filepath.Join(fixture.directory, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ENKV_BUILD_SIGNAL_REAL_GO", realGo)
			t.Setenv("TMPDIR", scratch)
			command := exec.Command(tool, "-directory", author, "-descriptor", cliDescriptorFile(t, author), "-versioned", "-output", filepath.Join(author, "output"))
			command.Env = append(os.Environ(), "GOFLAGS=")
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			commandJoined := false
			t.Cleanup(func() {
				if !commandJoined {
					if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						t.Error("command cleanup signal failed", err)
					}
					select {
					case <-done:
						commandJoined = true
					case <-time.After(8 * time.Second):
						t.Error("command cleanup did not join")
					}
				}
				stages, stageErr := filepath.Glob(filepath.Join(scratch, "enkv-plugin-build-*"))
				driverMarker, driverErr := os.ReadFile(fixture.ready + ".driver")
				compilerMarker, compilerErr := os.ReadFile(fixture.ready + ".compiler")
				t.Logf("command setup/cleanup: command=%d joined=%t driver_marker=%.128q driver_marker_error=%v compiler_marker=%.128q compiler_marker_error=%v scratch=%v scratch_error=%v", command.Process.Pid, commandJoined, driverMarker, driverErr, compilerMarker, compilerErr, stages, stageErr)
				if commandJoined {
					t.Logf("command terminal: exit=%d stdout=%.4096q stderr=%.4096q", command.ProcessState.ExitCode(), stdout.String(), stderr.String())
				}
			})
			fixture.waitReady(t)
			before, err := filepath.Glob(filepath.Join(scratch, "enkv-plugin-build-*"))
			if err != nil || len(before) != 1 {
				t.Fatal("build did not own exactly one scratch directory", before, err)
			}
			t.Logf("termination ready: command=%d driver=%d group=%d compiler=%d compiler_group=%d scratch=%s signal=%d", command.Process.Pid, fixture.driver, fixture.driverGroup, fixture.compiler, fixture.compilerGroup, before[0], signal)
			if err := command.Process.Signal(signal); err != nil {
				t.Fatal("termination signal failed", err)
			}
			var waitErr error
			select {
			case waitErr = <-done:
				commandJoined = true
			case <-time.After(8 * time.Second):
				t.Fatal("termination did not join command and captured pipes")
			}
			driverGone := errors.Is(syscall.Kill(fixture.driver, 0), syscall.ESRCH)
			compilerGone := errors.Is(syscall.Kill(fixture.compiler, 0), syscall.ESRCH)
			groupGone := errors.Is(syscall.Kill(-fixture.driver, 0), syscall.ESRCH)
			_, scratchErr := os.Stat(before[0])
			t.Logf("termination terminal: command_joined=%t exit=%d driver_gone=%t compiler_gone=%t group_gone=%t scratch_removed=%t stdout_bytes=%d stderr_bytes=%d", commandJoined, command.ProcessState.ExitCode(), driverGone, compilerGone, groupGone, errors.Is(scratchErr, os.ErrNotExist), stdout.Len(), stderr.Len())
			// Cleanup releases and positively settles known children before removing
			// scratch, including when the signal handler is absent.
			if waitErr == nil || command.ProcessState.ExitCode() != 1 || !strings.Contains(stderr.String(), "context canceled") || stdout.Len() != 0 {
				t.Errorf("termination did not return the cancelled command result: exit=%d stdout_bytes=%d stderr=%.4096q", command.ProcessState.ExitCode(), stdout.Len(), stderr.String())
			}
			if !driverGone || !compilerGone || !groupGone || !errors.Is(scratchErr, os.ErrNotExist) {
				t.Error("command returned before its compiler group settled and scratch was removed")
			}
		})
	}
}

type terminationFixture struct {
	directory, ready, release                    string
	driver, driverGroup, compiler, compilerGroup int
}

func newTerminationFixture(t *testing.T) *terminationFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := &terminationFixture{directory: directory, ready: filepath.Join(directory, "ready"), release: filepath.Join(directory, "release")}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_BUILD_SIGNAL_BINARY", binary)
	t.Setenv("ENKV_BUILD_SIGNAL_MODE", "driver")
	t.Setenv("ENKV_BUILD_SIGNAL_READY", fixture.ready)
	t.Setenv("ENKV_BUILD_SIGNAL_RELEASE", fixture.release)
	t.Cleanup(func() {
		for _, row := range []struct {
			suffix     string
			pid, group *int
		}{{".driver", &fixture.driver, &fixture.driverGroup}, {".compiler", &fixture.compiler, &fixture.compilerGroup}} {
			body, err := os.ReadFile(fixture.ready + row.suffix)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			fields := strings.Fields(string(body))
			if err != nil || len(fields) < 2 {
				t.Error("compiler cleanup identity unavailable", row.suffix, err)
				continue
			}
			pid, pidErr := strconv.Atoi(fields[0])
			group, groupErr := strconv.Atoi(fields[1])
			if pidErr != nil || groupErr != nil || pid <= 0 || group <= 0 {
				t.Error("compiler cleanup identity invalid", row.suffix)
				continue
			}
			*row.pid, *row.group = pid, group
		}
		if err := os.WriteFile(fixture.release, nil, 0600); err != nil {
			t.Error("compiler cleanup release failed", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			driverGone := fixture.driver == 0 || errors.Is(syscall.Kill(fixture.driver, 0), syscall.ESRCH)
			compilerGone := fixture.compiler == 0 || errors.Is(syscall.Kill(fixture.compiler, 0), syscall.ESRCH)
			groupGone := fixture.driver == 0 || errors.Is(syscall.Kill(-fixture.driver, 0), syscall.ESRCH)
			if driverGone && compilerGone && groupGone {
				t.Logf("compiler fixture cleanup settled: driver=%d compiler=%d group=%d", fixture.driver, fixture.compiler, fixture.driverGroup)
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("compiler cleanup did not settle: driver=%d group=%d compiler=%d driver_gone=%t compiler_gone=%t group_gone=%t", fixture.driver, fixture.driverGroup, fixture.compiler, driverGone, compilerGone, groupGone)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return fixture
}

func (fixture *terminationFixture) waitReady(t *testing.T) {
	t.Helper()
	values := terminationReadIdentity(t, fixture.ready, 5)
	fixture.driver, fixture.driverGroup, fixture.compiler, fixture.compilerGroup = values[0], values[1], values[2], values[3]
	if fixture.driver != fixture.driverGroup || fixture.driverGroup != fixture.compilerGroup || values[4] != fixture.driver {
		t.Fatal("compiler does not belong to the driver group and parent", values)
	}
}

func terminationReadIdentity(t *testing.T, path string, count int) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(body))
			if len(fields) != count {
				t.Fatal("compiler identity shape differs")
			}
			values := make([]int, count)
			for i, field := range fields {
				values[i], err = strconv.Atoi(field)
				if err != nil || values[i] <= 0 {
					t.Fatal("compiler identity is invalid")
				}
			}
			return values
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("compiler readiness unavailable", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("compiler readiness timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func terminationMarker(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func terminationChild(t *testing.T, mode string) {
	t.Helper()
	ready, release := os.Getenv("ENKV_BUILD_SIGNAL_READY"), os.Getenv("ENKV_BUILD_SIGNAL_RELEASE")
	group, err := syscall.Getpgid(0)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "compiler" {
		terminationMarker(t, ready+".compiler", fmt.Sprintf("%d %d %d", os.Getpid(), group, os.Getppid()))
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(release); err == nil {
				os.Exit(0)
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(0)
	}
	if mode != "driver" {
		t.Fatal("compiler mode is invalid")
	}
	terminationMarker(t, ready+".driver", fmt.Sprintf("%d %d", os.Getpid(), group))
	child := exec.Command(os.Args[0], "-test.run=^TestCommandTerminationSettlesCompilerGroup$", "-test.count=1")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ENKV_BUILD_SIGNAL_MODE=") {
			child.Env = append(child.Env, entry)
		}
	}
	child.Env = append(child.Env, "ENKV_BUILD_SIGNAL_MODE=compiler")
	child.Stdout = os.Stdout
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error("compiler cleanup signal failed", err)
			}
			if err := child.Wait(); child.ProcessState == nil {
				t.Error("compiler cleanup did not join", err)
			}
		}
	}()
	values := terminationReadIdentity(t, ready+".compiler", 3)
	if values[0] != child.Process.Pid || values[2] != os.Getpid() {
		t.Fatal("compiler readiness changed identity or parent")
	}
	terminationMarker(t, ready, fmt.Sprintf("%d %d %d %d %d", os.Getpid(), group, values[0], values[1], values[2]))
	err = child.Wait()
	joined = child.ProcessState != nil
	if err != nil {
		t.Fatal("compiler wait failed", err)
	}
	os.Exit(0)
}
