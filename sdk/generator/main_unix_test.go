//go:build darwin || linux

package generator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestNativeMainOwnsDescriptorsAndRefusesInvalidEntry(t *testing.T) {
	for _, mode := range []string{"valid", "arguments", "environment", "direction", "type", "standard stream", "non-null character", "extra descriptor", "close failure", "ordinary exec"} {
		t.Run(mode, func(t *testing.T) {
			implementation := processImplementation()
			issued := processCommand(t, implementation)
			control, environment, _ := processInput(t, implementation, issued)
			controlRead, controlWrite := testPipe(t)
			environmentRead, environmentWrite := testPipe(t)
			resultRead, resultWrite := testPipe(t)
			statusRead, statusWrite := testPipe(t)
			if _, err := controlWrite.Write(control.Bytes()); err != nil {
				t.Fatal(err)
			}
			if _, err := environmentWrite.Write(environment.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(controlWrite.Close(), environmentWrite.Close()); err != nil {
				t.Fatal(err)
			}
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestFile(t, null) })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeMainHelper$", "--", mode)
			command.Env = []string{}
			command.Stdin, command.Stdout, command.Stderr = null, null, null
			command.ExtraFiles = []*os.File{controlRead, environmentRead, resultWrite, statusWrite}
			switch mode {
			case "direction":
				command.ExtraFiles[0] = resultWrite
			case "type":
				command.ExtraFiles[0] = null
			case "standard stream":
				command.Stdout = statusWrite
			case "non-null character":
				zero, err := os.OpenFile("/dev/zero", os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { closeTestFile(t, zero) })
				command.Stdout = zero
			case "extra descriptor":
				command.ExtraFiles = append(command.ExtraFiles, null)
			}
			err = command.Run()
			if ctx.Err() != nil {
				t.Fatal("native child exceeded finite supervisor deadline")
			}
			if closeErr := errors.Join(resultWrite.Close(), statusWrite.Close()); closeErr != nil {
				t.Fatal(closeErr)
			}
			want := 20
			if mode == "valid" || mode == "ordinary exec" {
				want = 0
			}
			if mode == "close failure" {
				want = 33
			}
			got := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				got = exit.ExitCode()
			}
			if got != want {
				t.Fatal("native terminal differs", got, want)
			}
			result, resultErr := io.ReadAll(resultRead)
			status, statusErr := io.ReadAll(statusRead)
			if errors.Join(resultErr, statusErr) != nil {
				t.Fatal("joined child output unavailable")
			}
			if mode == "valid" || mode == "close failure" || mode == "ordinary exec" {
				if !bytes.Contains(result, processValue) || bytes.Contains(status, processValue) || bytes.Contains(status, []byte(processToken)) {
					t.Fatal("native private output used public stream")
				}
			} else if len(result) != 0 || len(status) != 0 {
				t.Fatal("invalid process entry emitted wire output")
			}
			clear(result)
		})
	}
}
func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestFile(t, read); closeTestFile(t, write) })
	return read, write
}
func closeTestFile(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error(err)
	}
}

// full_only: false
func TestNativeMainHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	os.Args = []string{os.Args[0], "generator-wire-v5"}
	os.Clearenv()
	if mode == "arguments" {
		os.Args = append(os.Args, "extra")
	}
	if mode == "environment" {
		if os.Setenv("UNEXPECTED", "present") != nil {
			os.Exit(90)
		}
	}
	implementation := processImplementation()
	implementation.Create = func(_ context.Context, inv Invocation) (protocol.SafeFacts, []byte, error) {
		if os.Getenv("PRIVATE_TOKEN") != processToken {
			os.Exit(93)
		}
		if mode == "ordinary exec" {
			check := exec.Command(os.Args[0], "-test.run=^TestNativeOrdinaryExecHelper$", "--", "channels")
			check.Env = []string{}
			if err := check.Run(); err != nil {
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					os.Exit(exit.ExitCode())
				}
				os.Exit(95)
			}
		}
		if mode == "close failure" {
			if syscall.Close(3) != nil {
				os.Exit(91)
			}
		}
		return completeFacts(inv.Command), bytes.Clone(processValue), nil
	}
	code := Main(implementation)
	if _, present := os.LookupEnv("PRIVATE_TOKEN"); present {
		os.Exit(94)
	}
	for fd := 3; fd <= 6; fd++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
		if errno != syscall.EBADF {
			os.Exit(92)
		}
	}
	os.Exit(code)
}

// full_only: false
func TestNativeOrdinaryExecHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" || os.Args[len(os.Args)-1] != "channels" {
		return
	}
	for fd := 3; fd <= 6; fd++ {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF && (errno != 0 || flags&syscall.FD_CLOEXEC == 0) {
			os.Exit(96)
		}
	}
	os.Exit(0)
}
