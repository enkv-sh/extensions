//go:build linux && amd64

package build

import (
	"syscall"
	"unsafe"
)

// Linux's 64-bit SIGCHLD siginfo prefix includes a word before the child PID;
// the complete native result occupies 128 bytes.
type goCommandWaitInfo struct {
	signal, errno, code, alignment int32
	pid                            int32
	uid                            uint32
	status                         int32
	padding                        [100]byte
}

func goCommandChildExited(pid int) (bool, error) {
	var info goCommandWaitInfo
	_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(pid), uintptr(unsafe.Pointer(&info)), syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG, 0, 0)
	if errno == syscall.EINTR {
		return false, nil
	}
	if errno != 0 {
		return false, errno
	}
	return goCommandTerminalEvent(pid, info.signal, info.pid, info.code)
}
