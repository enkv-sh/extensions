//go:build darwin || linux

package output

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

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestNativeMainModesAndDescriptorOwnership(t *testing.T) {
	for _, passive := range []bool{false, true} {
		t.Run(map[bool]string{false: "action", true: "passive"}[passive], func(t *testing.T) {
			for _, condition := range []string{"complete", "ordinary exec", "arguments", "mode", "environment", "direction", "credential direction", "payload direction", "result direction", "type", "standard stream", "non-null character", "extra descriptor", "high descriptor", "close failure", "passive private descriptors"} {
				if passive && (condition == "credential direction" || condition == "payload direction") {
					continue
				}
				if !passive && condition == "passive private descriptors" {
					continue
				}
				t.Run(condition, func(t *testing.T) {
					e, _ := fixture(t, passive, protocol.ActionCreateWithValue, []byte("payload"))
					controlRead, controlWrite := testPipe(t)
					credentialRead, credentialWrite := testPipe(t)
					payloadRead, payloadWrite := testPipe(t)
					resultRead, resultWrite := testPipe(t)
					for _, row := range []struct {
						write *os.File
						read  io.Reader
					}{{controlWrite, e.Control}, {credentialWrite, e.Credential}, {payloadWrite, e.Payload}} {
						if _, err := io.Copy(row.write, row.read); err != nil {
							t.Fatal(err)
						}
						if err := row.write.Close(); err != nil {
							t.Fatal(err)
						}
					}
					null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { closeFile(t, null) })
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					mode := "output-wire-v6"
					if passive {
						mode = "output-public-v3"
					}
					command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeMainHelper$", "--", mode, condition)
					command.Env = []string{}
					command.Stdin, command.Stdout, command.Stderr = null, null, null
					command.ExtraFiles = []*os.File{controlRead, credentialRead, payloadRead, resultWrite}
					if passive {
						command.ExtraFiles = []*os.File{controlRead, resultWrite}
					}
					switch condition {
					case "direction":
						command.ExtraFiles[0] = resultWrite
					case "credential direction":
						command.ExtraFiles[1] = resultWrite
					case "payload direction":
						command.ExtraFiles[2] = resultWrite
					case "result direction":
						command.ExtraFiles[len(command.ExtraFiles)-1] = controlRead
					case "type":
						command.ExtraFiles[0] = null
					case "standard stream":
						command.Stdout = resultWrite
					case "non-null character":
						zero, err := os.OpenFile("/dev/zero", os.O_WRONLY, 0)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { closeFile(t, zero) })
						command.Stdout = zero
					case "extra descriptor":
						command.ExtraFiles = append(command.ExtraFiles, null)
					}
					err = command.Run()
					if ctx.Err() != nil {
						t.Fatal("native child did not join within deadline")
					}
					if err := resultWrite.Close(); err != nil {
						t.Fatal(err)
					}
					got := 0
					if err != nil {
						var exit *exec.ExitError
						if !errors.As(err, &exit) {
							t.Fatal(err)
						}
						got = exit.ExitCode()
					}
					want := 2
					switch condition {
					case "complete", "ordinary exec", "passive private descriptors":
						want = 0
					case "close failure":
						want = 1
					}
					if got != want {
						t.Fatalf("status=%d want=%d", got, want)
					}
					b, err := io.ReadAll(resultRead)
					if err != nil {
						t.Fatal(err)
					}
					if want == 2 && len(b) != 0 {
						t.Fatal("invalid native shape produced wire output")
					}
					if want != 2 {
						expected, _ := fixture(t, passive, protocol.ActionCreateWithValue, []byte("payload"))
						p := new(implementation)
						if passive {
							if RunPublic(context.Background(), publicEndpoints(expected), p) != 0 {
								t.Fatal("expected profile exchange failed")
							}
						} else if Run(context.Background(), expected, p) != 0 {
							t.Fatal("expected action exchange failed")
						}
						if !bytes.Equal(b, expected.Result.(*bytes.Buffer).Bytes()) {
							t.Fatal("native exchange differs from shared serving path")
						}
					}
				})
			}
		})
	}
}
func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeFile(t, r); closeFile(t, w) })
	return r, w
}
func closeFile(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error(err)
	}
}

// full_only: false
func TestNativeMainHelper(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--" {
		return
	}
	mode, condition := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	os.Args = []string{os.Args[0], mode}
	os.Clearenv()
	last := 6
	if mode == "output-public-v3" {
		last = 4
	}
	extraDescriptor := -1
	switch condition {
	case "arguments":
		os.Args = append(os.Args, "extra")
	case "mode":
		os.Args[1] = "output-wire-v2"
	case "environment":
		if os.Setenv("UNEXPECTED", "present") != nil {
			os.Exit(90)
		}
	case "high descriptor":
		fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 3, syscall.F_DUPFD, 512)
		if errno != 0 {
			os.Exit(91)
		}
		extraDescriptor = int(fd)
	case "passive private descriptors":
		if err := syscall.Dup2(3, 5); err != nil {
			os.Exit(92)
		}
		syscall.CloseOnExec(5)
		extraDescriptor = 5
	}
	p := new(implementation)
	p.expectNativeEnvironment = last == 6
	if condition == "ordinary exec" {
		check := func() {
			command := exec.Command(os.Args[0], "-test.run=^TestNativeOrdinaryExecHelper$", "--", "channels")
			command.Env = []string{}
			if err := command.Run(); err != nil {
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					os.Exit(exit.ExitCode())
				}
				os.Exit(98)
			}
		}
		p.onPublic, p.onPrepare, p.onExecute = check, check, check
	}
	if condition == "close failure" {
		closeControl := func() {
			if syscall.Close(3) != nil {
				os.Exit(93)
			}
		}
		if last == 4 {
			p.onPublic = closeControl
		} else {
			p.onExecute = closeControl
		}
	}
	code := Main(p)
	if _, found := os.LookupEnv("TOKEN"); found {
		os.Exit(97)
	}
	if condition != "mode" {
		for fd := 3; fd <= last; fd++ {
			_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if errno != syscall.EBADF {
				os.Exit(94)
			}
		}
	}
	if condition == "passive private descriptors" {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 5, syscall.F_GETFD, 0)
		if errno != 0 {
			os.Exit(95)
		}
	}
	if extraDescriptor >= 0 {
		if err := syscall.Close(extraDescriptor); err != nil {
			os.Exit(96)
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
			os.Exit(99)
		}
	}
	os.Exit(0)
}
