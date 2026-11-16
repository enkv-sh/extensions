//go:build (darwin && arm64) || (linux && amd64)

package build

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const commandProcessMode = "ENKV_BUILD_COMMAND_TEST_MODE"

// full_only: false
func TestGoCommandWaitInfoMatchesNativeLayout(t *testing.T) {
	var info goCommandWaitInfo
	wantSize, wantPID := uintptr(104), uintptr(12)
	if runtime.GOOS == "linux" {
		wantSize, wantPID = 128, 16
	}
	if unsafe.Sizeof(info) != wantSize || unsafe.Offsetof(info.signal) != 0 || unsafe.Offsetof(info.code) != 8 || unsafe.Offsetof(info.pid) != wantPID {
		t.Fatal("native wait result layout differs from platform headers", unsafe.Sizeof(info), unsafe.Offsetof(info.signal), unsafe.Offsetof(info.code), unsafe.Offsetof(info.pid))
	}
}

type commandProcessFixture struct {
	directory, ready, release      string
	driver, compiler               int
	driverGroup, compilerGroup     int
	compilerParent                 int
	cancel                         context.CancelFunc
	done                           <-chan error
	joined                         bool
	readyObserved                  bool
	delayedReap                    bool
	linker, linkerGroup            int
	linkerParent, linkerSession    int
	driverSession, compilerSession int
}

// full_only: false
func TestGoCommandCancellationSettlesCompilerGroup(t *testing.T) {
	if mode := os.Getenv(commandProcessMode); mode != "" {
		commandProcessChild(t, mode)
		return
	}
	t.Run("pre-start", func(t *testing.T) {
		fixture := newCommandProcessFixture(t, "driver", "stdout")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := invokeCommandProcess(ctx, fixture.directory, io.Discard)
		if !errors.Is(err, context.Canceled) {
			t.Error("pre-start cancellation lost its cause", err)
		}
		if _, err := os.Stat(fixture.ready + ".driver"); !errors.Is(err, os.ErrNotExist) {
			t.Error("pre-start cancellation launched a driver")
		}
	})
	t.Run("complete", func(t *testing.T) {
		fixture := newCommandProcessFixture(t, "complete", "stdout")
		var diagnostic bytes.Buffer
		body, err := invokeCommandProcess(t.Context(), fixture.directory, &diagnostic)
		if err != nil || string(body) != "compiler output" || diagnostic.String() != "" {
			t.Error("ordinary command changed its output or diagnostics", err, len(body), diagnostic.Len())
		}
	})
	t.Run("unsettled-group", func(t *testing.T) {
		fixture := newCommandProcessFixture(t, "driver-unsettled", "stdout")
		ctx, cancel := context.WithCancel(t.Context())
		fixture.cancel = cancel
		done := make(chan error, 1)
		fixture.done, fixture.joined = done, false
		var body []byte
		go func() {
			var err error
			body, err = invokeCommandProcess(ctx, fixture.directory, io.Discard)
			done <- err
		}()
		fixture.waitReady(t)
		if fixture.driverGroup != fixture.driver || fixture.driverSession != fixture.driver || fixture.compilerGroup != fixture.compiler || fixture.compilerSession != fixture.compiler || fixture.compilerParent != fixture.driver || fixture.linkerGroup != fixture.driverGroup || fixture.linkerSession != fixture.driverSession || fixture.linkerParent != fixture.compiler {
			t.Fatal("delayed-reaping fixture relationships differ", fixture.driver, fixture.driverGroup, fixture.driverSession, fixture.compiler, fixture.compilerGroup, fixture.compilerSession, fixture.compilerParent, fixture.linker, fixture.linkerGroup, fixture.linkerSession, fixture.linkerParent)
		}
		cancel()
		select {
		case err := <-done:
			fixture.joined = true
			if !errors.Is(err, errGoCommandUnsettled) || !errors.Is(err, context.Canceled) || body != nil {
				t.Error("unsettled group produced trusted output or lost its failure", err, len(body))
			}
		case <-time.After(7 * time.Second):
			t.Fatal("unsettled group did not return its bounded failure")
		}
		if errors.Is(syscall.Kill(-fixture.driver, 0), syscall.ESRCH) || errors.Is(syscall.Kill(fixture.linker, 0), syscall.ESRCH) {
			t.Fatal("delayed-reaping group premise disappeared before release")
		}
		if state := commandProcessState(t, fixture.linker, t.Context()); !strings.HasPrefix(state, "Z") {
			t.Fatal("linker was not an unreaped zombie", state)
		}
	})
	for _, condition := range []struct {
		name, mode, stream string
		cancel, stopped    bool
	}{
		{"stdout", "driver", "stdout", true, false},
		{"stderr", "driver", "stderr", true, false},
		{"natural-exit", "driver-exit", "stdout", false, false},
		{"stopped-driver", "driver-stop", "stdout", true, true},
	} {
		t.Run(condition.name, func(t *testing.T) {
			fixture := newCommandProcessFixture(t, condition.mode, condition.stream)
			ctx, cancel := context.WithCancel(t.Context())
			fixture.cancel = cancel
			done := make(chan error, 1)
			fixture.done, fixture.joined = done, false
			go func() {
				_, err := invokeCommandProcess(ctx, fixture.directory, io.Discard)
				done <- err
			}()
			fixture.waitReady(t)
			if fixture.driverGroup != fixture.compilerGroup || fixture.compilerParent != fixture.driver {
				t.Fatal("fixture compiler was not a same-group child", fixture.driver, fixture.driverGroup, fixture.compiler, fixture.compilerGroup, fixture.compilerParent)
			}
			if condition.stopped {
				fixture.waitStopped(t)
				select {
				case err := <-done:
					fixture.joined = true
					t.Fatal("stopped Go driver was treated as completed before cancellation", err)
				case <-time.After(100 * time.Millisecond):
				}
			}
			if condition.cancel {
				cancel()
			}
			var result error
			select {
			case result = <-done:
				fixture.joined = true
			case <-time.After(7 * time.Second):
				t.Error("command waited for the test to release inherited compiler output")
				fixture.releaseCompiler(t)
				select {
				case result = <-done:
					fixture.joined = true
				case <-time.After(8 * time.Second):
					t.Fatal("released compiler command did not join")
				}
			}
			if condition.cancel && !errors.Is(result, context.Canceled) {
				t.Error("compiler cancellation lost the caller cause", result)
			}
			if !condition.cancel && result != nil {
				t.Error("completed Go driver lost its normal result", result)
			}
			if fixture.driverGroup != fixture.driver {
				t.Error("Go driver did not own its group", fixture.driver, fixture.driverGroup)
			}
			driverGone := errors.Is(syscall.Kill(fixture.driver, 0), syscall.ESRCH)
			compilerGone := errors.Is(syscall.Kill(fixture.compiler, 0), syscall.ESRCH)
			groupGone := errors.Is(syscall.Kill(-fixture.driver, 0), syscall.ESRCH)
			if !driverGone || !compilerGone || !groupGone {
				t.Error("command returned before its driver, compiler or group settled", driverGone, compilerGone, groupGone)
			}
		})
	}
}

func newCommandProcessFixture(t *testing.T, mode, stream string) *commandProcessFixture {
	t.Helper()
	directory, err := os.MkdirTemp("", "enkv-go-command-process-")
	if err != nil {
		t.Fatal("compiler fixture directory unavailable", err)
	}
	fixture := &commandProcessFixture{directory: directory, ready: filepath.Join(directory, "ready"), release: filepath.Join(directory, "release"), joined: true, delayedReap: mode == "driver-unsettled"}
	t.Cleanup(func() { fixture.cleanup(t) })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("compiler fixture executable unavailable", err)
	}
	script := "#!/bin/sh\nexec \"$ENKV_BUILD_COMMAND_TEST_BINARY\" -test.run '^TestGoCommandCancellationSettlesCompilerGroup$' -test.count=1 -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(commandProcessMode, mode)
	t.Setenv("ENKV_BUILD_COMMAND_TEST_BINARY", binary)
	t.Setenv("ENKV_BUILD_COMMAND_TEST_READY", fixture.ready)
	t.Setenv("ENKV_BUILD_COMMAND_TEST_RELEASE", fixture.release)
	t.Setenv("ENKV_BUILD_COMMAND_TEST_STREAM", stream)
	return fixture
}

func (fixture *commandProcessFixture) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		body, err := os.ReadFile(fixture.ready)
		if err == nil {
			count := 5
			if fixture.delayedReap {
				count = 11
			}
			values := commandProcessNumbers(t, body, count)
			fixture.driver, fixture.driverGroup, fixture.compiler, fixture.compilerGroup, fixture.compilerParent = values[0], values[1], values[2], values[3], values[4]
			if fixture.delayedReap {
				fixture.driverSession, fixture.compilerSession = values[5], values[6]
				fixture.linker, fixture.linkerGroup, fixture.linkerParent, fixture.linkerSession = values[7], values[8], values[9], values[10]
			}
			fixture.readyObserved = true
			if fixture.driver == fixture.compiler {
				t.Fatal("driver and compiler identities coincide")
			}
			t.Logf("compiler process ownership: driver=%d driver_group=%d compiler=%d compiler_group=%d compiler_parent=%d", fixture.driver, fixture.driverGroup, fixture.compiler, fixture.compilerGroup, fixture.compilerParent)
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("compiler readiness unavailable", err)
		}
		select {
		case <-deadline.C:
			t.Fatal("Go driver did not report compiler readiness")
		case <-tick.C:
		}
	}
}

func (fixture *commandProcessFixture) waitStopped(t *testing.T) {
	t.Helper()
	observation, stopObservation := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopObservation()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if strings.HasPrefix(commandProcessState(t, fixture.driver, observation), "T") {
			return
		}
		select {
		case err := <-fixture.done:
			fixture.joined = true
			t.Fatal("Go driver ended before its stopped state was observed", err)
		case <-observation.Done():
			t.Fatal("Go driver did not enter stopped state")
		case <-tick.C:
		}
	}
}

func (fixture *commandProcessFixture) releaseCompiler(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(fixture.release, nil, 0600); err != nil {
		t.Error("compiler cleanup release failed", err)
	}
}

func (fixture *commandProcessFixture) cleanup(t *testing.T) {
	t.Helper()
	if fixture.cancel != nil {
		fixture.cancel()
	}
	fixture.releaseCompiler(t)
	if !fixture.joined && fixture.done != nil {
		select {
		case <-fixture.done:
			fixture.joined = true
		case <-time.After(8 * time.Second):
			t.Error("compiler command cleanup did not join")
		}
	}
	for _, row := range []struct {
		suffix string
		pid    *int
		count  int
	}{{".driver", &fixture.driver, 2}, {".compiler", &fixture.compiler, 4}, {".linker", &fixture.linker, 4}} {
		body, err := os.ReadFile(fixture.ready + row.suffix)
		if err == nil {
			*row.pid = commandProcessNumbers(t, body, row.count)[0]
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Error("compiler cleanup identity unavailable", err)
			fixture.joined = false
		}
	}
	if fixture.driver != 0 && fixture.done != nil && !fixture.readyObserved {
		t.Errorf("compiler fixture retained after incomplete readiness: directory=%s driver=%d compiler=%d", fixture.directory, fixture.driver, fixture.compiler)
		return
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		driverGone := fixture.driver == 0 || errors.Is(syscall.Kill(fixture.driver, 0), syscall.ESRCH)
		compilerGone := fixture.compiler == 0 || errors.Is(syscall.Kill(fixture.compiler, 0), syscall.ESRCH)
		linkerGone := fixture.linker == 0 || errors.Is(syscall.Kill(fixture.linker, 0), syscall.ESRCH)
		groupGone := fixture.driver == 0 || fixture.driverGroup != fixture.driver || errors.Is(syscall.Kill(-fixture.driver, 0), syscall.ESRCH)
		if fixture.joined && driverGone && compilerGone && linkerGone && groupGone {
			if fixture.delayedReap {
				body, err := os.ReadFile(fixture.ready + ".reaped")
				if err != nil || string(body) != "linker-killed-and-reaped" {
					t.Error("delayed linker recovery did not record its actual killed/reaped result", err)
				}
			}
			if err := os.RemoveAll(fixture.directory); err != nil {
				t.Error("settled compiler fixture cleanup failed", err)
			}
			return
		}
		select {
		case <-deadline.C:
			t.Errorf("compiler fixture retained after incomplete settlement: directory=%s driver=%d compiler=%d linker=%d command_joined=%t", fixture.directory, fixture.driver, fixture.compiler, fixture.linker, fixture.joined)
			return
		case <-tick.C:
		}
	}
}

func commandProcessNumbers(t *testing.T, body []byte, count int) []int {
	t.Helper()
	fields := strings.Fields(string(body))
	if len(fields) != count {
		t.Fatal("compiler process identity shape differs")
	}
	values := make([]int, count)
	for i, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil || value <= 0 {
			t.Fatal("compiler process identity is invalid")
		}
		values[i] = value
	}
	return values
}

func commandProcessMarker(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", []byte(body), 0600); err != nil {
		t.Fatal("compiler process marker unavailable", err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal("compiler process marker publication failed", err)
	}
}

func commandProcessState(t *testing.T, pid int, ctx context.Context) string {
	t.Helper()
	state, err := commandProcessNativeState(ctx, pid)
	if err != nil {
		t.Fatal("selected process state unavailable", pid, err)
	}
	return state
}

func commandProcessSession(t *testing.T, pid int) int {
	t.Helper()
	session, _, errno := syscall.Syscall(syscall.SYS_GETSID, uintptr(pid), 0, 0)
	if errno != 0 || session == 0 {
		t.Fatal("compiler session unavailable", pid, errno)
	}
	return int(session)
}

func commandProcessReadIdentity(t *testing.T, path string, count int) []int {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			return commandProcessNumbers(t, body, count)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("compiler entry marker unavailable", err)
		}
		select {
		case <-timer.C:
			t.Fatal("compiler fixture did not enter")
		case <-tick.C:
		}
	}
}

func commandProcessAwaitRelease(t *testing.T, release string) {
	t.Helper()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(release); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("compiler release unavailable", err)
		}
		select {
		case <-timer.C:
			return
		case <-tick.C:
		}
	}
}

func commandProcessChild(t *testing.T, mode string) {
	t.Helper()
	ready, release := os.Getenv("ENKV_BUILD_COMMAND_TEST_READY"), os.Getenv("ENKV_BUILD_COMMAND_TEST_RELEASE")
	group, err := syscall.Getpgid(0)
	if err != nil {
		t.Fatal("compiler group unavailable", err)
	}
	session := commandProcessSession(t, 0)
	if mode == "compiler" || mode == "linker" {
		commandProcessMarker(t, ready+"."+mode, fmt.Sprintf("%d %d %d %d", os.Getpid(), group, os.Getppid(), session))
		commandProcessAwaitRelease(t, release)
		os.Exit(0)
	}
	if mode == "complete" {
		commandProcessMarker(t, ready+".driver", fmt.Sprintf("%d %d", os.Getpid(), group))
		if _, err := io.WriteString(os.Stdout, "compiler output"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(os.Stderr, "compiler diagnostic"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	if mode != "driver" && mode != "driver-exit" && mode != "driver-stop" && mode != "driver-unsettled" && mode != "compiler-unsettled" {
		t.Fatal("invalid compiler process mode")
	}
	childMode := "compiler"
	if mode == "driver-unsettled" {
		childMode = "compiler-unsettled"
	}
	if mode == "compiler-unsettled" {
		childMode = "linker"
	} else {
		commandProcessMarker(t, ready+".driver", fmt.Sprintf("%d %d", os.Getpid(), group))
	}
	child := exec.Command(os.Args[0], "-test.run=^TestGoCommandCancellationSettlesCompilerGroup$", "-test.count=1")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, commandProcessMode+"=") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, commandProcessMode+"="+childMode)
	if os.Getenv("ENKV_BUILD_COMMAND_TEST_STREAM") == "stdout" {
		child.Stdout = os.Stdout
	} else {
		child.Stderr = os.Stderr
	}
	if err := child.Start(); err != nil {
		t.Fatal("compiler fixture did not start", err)
	}
	childJoined := false
	defer func() {
		if !childJoined {
			if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error("compiler fixture cleanup signal failed", err)
			}
			err := child.Wait()
			if child.ProcessState == nil {
				t.Error("compiler fixture cleanup did not join", err)
			}
		}
	}()
	identitySuffix := ".compiler"
	if mode == "compiler-unsettled" {
		identitySuffix = ".linker"
	}
	values := commandProcessReadIdentity(t, ready+identitySuffix, 4)
	if values[0] != child.Process.Pid || values[2] != os.Getpid() {
		t.Fatal("compiler readiness changed identity or parent")
	}
	if mode == "compiler-unsettled" {
		if values[1] != group || values[3] != session {
			t.Fatal("linker did not inherit the original compiler group and session")
		}
		newSession, err := syscall.Setsid()
		if err != nil || newSession != os.Getpid() {
			t.Fatal("delayed-reaping compiler did not establish its private session", err)
		}
		newGroup, err := syscall.Getpgid(0)
		newSession = commandProcessSession(t, 0)
		if err != nil || newGroup != os.Getpid() || newSession != os.Getpid() {
			t.Fatal("delayed-reaping compiler session differs", err)
		}
		commandProcessMarker(t, ready+".compiler", fmt.Sprintf("%d %d %d %d", os.Getpid(), newGroup, os.Getppid(), newSession))
		commandProcessAwaitRelease(t, release)
		err = child.Wait()
		childJoined = child.ProcessState != nil
		if !childJoined {
			t.Fatal("delayed linker wait did not join", err)
		}
		status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("delayed linker did not record the actual group kill", err)
		}
		commandProcessMarker(t, ready+".reaped", "linker-killed-and-reaped")
		os.Exit(0)
	}
	body := fmt.Sprintf("%d %d %d %d %d", os.Getpid(), group, child.Process.Pid, values[1], values[2])
	if mode == "driver-unsettled" {
		linker := commandProcessReadIdentity(t, ready+".linker", 4)
		body += fmt.Sprintf(" %d %d %d %d %d %d", session, values[3], linker[0], linker[1], linker[2], linker[3])
	}
	commandProcessMarker(t, ready, body)
	if mode == "driver-exit" {
		os.Exit(0)
	}
	if mode == "driver-stop" {
		if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
			t.Fatal("compiler fixture stop failed", err)
		}
	}
	err = child.Wait()
	childJoined = child.ProcessState != nil
	if err != nil {
		t.Fatal("compiler fixture wait failed", err)
	}
	os.Exit(0)
}

func invokeCommandProcess(ctx context.Context, directory string, diagnostic io.Writer) ([]byte, error) {
	return goCommand(ctx, directory, os.Environ(), "version")
}
