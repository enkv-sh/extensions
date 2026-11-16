//go:build darwin || linux

package output

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

// full_only: false
func TestExtraDescriptorCheckIncludesHighNumbersAndModeBoundary(t *testing.T) {
	r, _ := testPipe(t)
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, r.Fd(), syscall.F_DUPFD, 512)
	if errno != 0 {
		t.Fatal(errno)
	}
	t.Cleanup(func() {
		if err := syscall.Close(int(fd)); err != nil {
			t.Error(err)
		}
	})
	names := []string{strconv.Itoa(int(fd))}
	if extraDescriptorsAbsent(names, 7) || extraDescriptorsAbsent(names, 5) {
		t.Fatal("inheritable high descriptor accepted")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
		t.Fatal(errno)
	}
	if !extraDescriptorsAbsent(names, 7) || !extraDescriptorsAbsent(names, 5) {
		t.Fatal("runtime descriptor rejected")
	}
	if !extraDescriptorsAbsent([]string{"0", "1", "2", "3", "4", "not-an-fd"}, 5) {
		t.Fatal("assigned descriptors rejected")
	}
}

// full_only: false
func TestAssignedDescriptorCloseOnExecRetainsFlagsAndRefusesFailure(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	fd := reader.Fd()
	access, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFL), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_SETFD), 0); errno != 0 {
		t.Fatal(errno)
	}
	if !setDescriptorCloseOnExec(fd) {
		t.Fatal("assigned descriptor close-on-exec setup failed")
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFD), 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("actual assigned descriptor remains inheritable", errno)
	}
	after, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFL), 0)
	if errno != 0 || access != after {
		t.Fatal("close-on-exec changed descriptor access flags", errno)
	}
	if setDescriptorCloseOnExec(^uintptr(0)) {
		t.Fatal("invalid descriptor flag failure was accepted")
	}
}
