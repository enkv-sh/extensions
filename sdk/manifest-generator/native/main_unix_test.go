//go:build darwin || linux

package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
)

// full_only: false
func TestNativeMainShapeAndDescriptorOwnership(t *testing.T) {
	for _, condition := range []string{
		"complete", "arguments", "missing argument", "mode", "environment", "nil renderer", "nil settings validator",
		"request direction", "artifact direction", "status direction",
		"request type", "artifact type", "status type",
		"stdin", "stdout", "stderr", "non-null character",
		"extra descriptor", "high descriptor", "runtime descriptor", "request close failure",
	} {
		t.Run(condition, func(t *testing.T) {
			requestRead, requestWrite := nativeMainPipe(t)
			artifactRead, artifactWrite := nativeMainPipe(t)
			statusRead, statusWrite := nativeMainPipe(t)
			request := nativeMainRequestLiteral()
			if n, err := requestWrite.Write(request); err != nil || n != len(request) {
				t.Fatalf("write request: n=%d err=%v", n, err)
			}
			nativeMainClose(t, requestWrite)
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { nativeMainClose(t, null) })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeMainHelper$", "--", condition)
			command.Env = []string{}
			command.Stdin, command.Stdout, command.Stderr = null, null, null
			command.ExtraFiles = []*os.File{requestRead, artifactWrite, statusWrite}
			switch condition {
			case "request direction":
				command.ExtraFiles[0] = artifactWrite
			case "artifact direction":
				command.ExtraFiles[1] = requestRead
			case "status direction":
				command.ExtraFiles[2] = requestRead
			case "request type":
				command.ExtraFiles[0] = null
			case "artifact type":
				command.ExtraFiles[1] = null
			case "status type":
				command.ExtraFiles[2] = null
			case "stdin":
				command.Stdin = requestRead
			case "stdout":
				command.Stdout = artifactWrite
			case "stderr":
				command.Stderr = artifactWrite
			case "non-null character":
				zero, err := os.OpenFile("/dev/zero", os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { nativeMainClose(t, zero) })
				command.Stdout = zero
			case "extra descriptor":
				command.ExtraFiles = append(command.ExtraFiles, null)
			}
			err = command.Run()
			// Run waits for the child, including after deadline cancellation. The
			// fixed request, status and artifact all fit in their separate pipes.
			nativeMainClose(t, artifactWrite)
			nativeMainClose(t, statusWrite)
			if ctx.Err() != nil {
				t.Fatal("native child did not join within deadline")
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
			case "complete", "runtime descriptor":
				want = 0
			case "request close failure":
				want = 1
			}
			if got != want {
				t.Fatalf("exit=%d want=%d", got, want)
			}
			status := nativeMainRead(t, statusRead)
			artifact := nativeMainRead(t, artifactRead)
			if want == 2 {
				if len(status) != 0 || len(artifact) != 0 {
					t.Fatal("native refusal produced output")
				}
				return
			}
			// The status is magic, success tag zero, and the u64 artifact length.
			wantStatus := append([]byte("ENKV/MANIFEST/v2\x00"), append(append([]byte{8}, make([]byte, 31)...), 0, 0, 0, 0, 0, 0, 0, 0, 2)...)
			if !bytes.Equal(status, wantStatus) || !bytes.Equal(artifact, []byte("{}")) {
				t.Fatalf("exchange differs: status=%x artifact=%q", status, artifact)
			}
		})
	}
}

// This literal follows the specified field order and does not use the codec.
func nativeMainRequestLiteral() []byte {
	b := []byte("ENKV/MANIFEST/v2\x00")
	b = append(b, 2)
	for _, first := range []byte{8, 9} {
		b = append(b, first)
		b = append(b, make([]byte, 31)...)
	}
	for _, text := range []string{"ENKV/CONSUMPTION-PROJECTION/v1", "private/ini/v1", "private/ini-settings/v1", "{}"} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(text)))
		b = append(b, text...)
	}
	b = append(b, 2, 2, 0)
	for _, first := range []byte{1, 2, 3, 4} {
		b = append(b, first)
		b = append(b, make([]byte, 31)...)
	}
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 1, 'a', 5)
	b = append(b, make([]byte, 31)...)
	b = append(b, 1, 0, 0, 0, 2, 0, 255, 0, 0, 0, 0)
	return b
}

func nativeMainPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nativeMainClose(t, r); nativeMainClose(t, w) })
	return r, w
}

func nativeMainClose(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error(err)
	}
}

func nativeMainRead(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil || len(b) > 4096 {
		t.Fatalf("read native output: length=%d err=%v", len(b), err)
	}
	return b
}

// full_only: false
func TestNativeMainHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	condition := os.Args[len(os.Args)-1]
	os.Args = []string{os.Args[0], "manifest-wire-v2"}
	os.Clearenv()
	extra := -1
	switch condition {
	case "arguments":
		os.Args = append(os.Args, "extra")
	case "missing argument":
		os.Args = os.Args[:1]
	case "mode":
		os.Args[1] = "manifest-wire-v3"
	case "environment":
		if os.Setenv("UNEXPECTED", "present") != nil {
			os.Exit(90)
		}
	case "extra descriptor":
		extra = 6
	case "high descriptor", "runtime descriptor":
		fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 3, syscall.F_DUPFD, 512)
		if errno != 0 {
			os.Exit(91)
		}
		extra = int(fd)
		if condition == "runtime descriptor" {
			syscall.CloseOnExec(extra)
		}
	}
	calls := 0
	render := manifest.Renderer(func(ctx context.Context, v manifest.View) manifest.Result {
		calls++
		e, ok := v.Entry(0)
		var plain [2]byte
		n, failure := e.CopyPlain(0, plain[:])
		if ctx == nil || v.EntryCount() != 1 || !ok || e.Metadata().Name != "a" || n != 2 || failure != "" || plain != [2]byte{0, 255} || v.Header().TargetRecipientID != (manifest.ID{4}) {
			os.Exit(92)
		}
		if condition == "request close failure" && syscall.Close(3) != nil {
			os.Exit(93)
		}
		return manifest.Result{Artifact: []byte("{}")}
	})
	if condition == "nil renderer" {
		render = nil
	}
	implementation := Implementation{identity: manifest.Identity{ProtocolID: protocol.ProtocolID(), DescriptorID: manifest.ID{9}}, Implementation: manifest.Implementation{ValidateFormatSettings: func(context.Context, manifest.SettingsRequest) manifest.SettingsResult {
		return manifest.SettingsResult{Settings: []byte("{}")}
	}, Render: render}}
	if condition == "nil settings validator" {
		implementation.ValidateFormatSettings = nil
	}
	code := Main(implementation)
	for fd := 3; fd <= 5; fd++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF {
			os.Exit(94)
		}
	}
	if extra >= 0 {
		// Main has no ownership of unexpected or runtime descriptors.
		if err := syscall.Close(extra); err != nil {
			os.Exit(95)
		}
	}
	if code == 2 && calls != 0 || code != 2 && calls != 1 {
		os.Exit(96)
	}
	os.Exit(code)
}
