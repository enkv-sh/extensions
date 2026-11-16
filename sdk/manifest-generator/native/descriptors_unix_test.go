//go:build darwin || linux

package native

import (
	"strconv"
	"syscall"
	"testing"
)

// full_only: false
func TestExtraDescriptorsRejectInheritableAndAllowRuntimeDescriptors(t *testing.T) {
	r, _ := nativeMainPipe(t)
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, r.Fd(), syscall.F_DUPFD, 512)
	if errno != 0 {
		t.Fatal(errno)
	}
	open := true
	t.Cleanup(func() {
		if open {
			if err := syscall.Close(int(fd)); err != nil {
				t.Error(err)
			}
		}
	})
	names := []string{strconv.Itoa(int(fd))}
	if extraDescriptorsAbsent(names, 6) || extraDescriptorsAbsent(names, int(fd)) {
		t.Fatal("inheritable high descriptor accepted")
	}
	if !extraDescriptorsAbsent(names, int(fd)+1) {
		t.Fatal("descriptor below the boundary rejected")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
		t.Fatal(errno)
	}
	if !extraDescriptorsAbsent(names, 6) {
		t.Fatal("close-on-exec runtime descriptor rejected")
	}
	if err := syscall.Close(int(fd)); err != nil {
		t.Fatal(err)
	}
	open = false
	if !extraDescriptorsAbsent(names, 6) {
		t.Fatal("closed descriptor rejected")
	}
	if !extraDescriptorsAbsent([]string{"0", "1", "2", "3", "4", "5", "not-an-fd"}, 6) {
		t.Fatal("assigned descriptors or directory text rejected")
	}
}
