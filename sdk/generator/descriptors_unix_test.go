//go:build darwin || linux

package generator

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

// full_only: false
func TestExtraDescriptorCheckCoversDescriptorsAbove255(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := read.Close(); err != nil {
			t.Error(err)
		}
		if err := write.Close(); err != nil {
			t.Error(err)
		}
	})
	duplicated, _, errno := syscall.Syscall(syscall.SYS_FCNTL, read.Fd(), uintptr(syscall.F_DUPFD), 512)
	if errno != 0 {
		t.Fatal(errno)
	}
	t.Cleanup(func() {
		if err := syscall.Close(int(duplicated)); err != nil {
			t.Error(err)
		}
	})
	if extraDescriptorsAbsent([]string{strconv.Itoa(int(duplicated))}) {
		t.Fatalf("inherited descriptor %d was not detected", duplicated)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, duplicated, uintptr(syscall.F_SETFD), uintptr(syscall.FD_CLOEXEC)); errno != 0 {
		t.Fatal(errno)
	}
	if !extraDescriptorsAbsent([]string{strconv.Itoa(int(duplicated))}) {
		t.Fatalf("process-owned close-on-exec descriptor %d was rejected", duplicated)
	}
	if !extraDescriptorsAbsent([]string{"0", "1", "2", "3", "4", "5", "6", "not-an-fd"}) {
		t.Fatal("fixed descriptor set was rejected")
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
