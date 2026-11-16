//go:build darwin && arm64

package build

import (
	"syscall"
	"unsafe"
)

// The native 64-bit Darwin siginfo_t layout comes from sys/signal.h.
// waitid with WNOWAIT reports status without releasing the child's PID.
type goCommandWaitInfo struct {
	signal, errno, code, pid int32
	uid                      uint32
	status                   int32
	address, value           uint64
	band                     int64
	padding                  [7]uint64
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
