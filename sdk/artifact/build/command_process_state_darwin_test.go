//go:build darwin && arm64

package build

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// proc_bsdshortinfo has sixteen 32-bit words in the native platform header.
// Its process status comes from proc_info, independently of waitid.
type commandProcessBSDInfo struct {
	pid, parent, group, state uint32
	name                      [16]byte
	remaining                 [8]uint32
}

func commandProcessNativeState(ctx context.Context, pid int) (string, error) {
	if ctx == nil || pid <= 0 {
		return "", errors.New("selected process context and positive identity are required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var info commandProcessBSDInfo
	// PROC_INFO_CALL_PIDINFO=2, PROC_PIDT_SHORTBSDINFO=13. Nonzero arg
	// includes an unreaped zombie; this query does not acquire or reap it.
	count, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, 2, uintptr(pid), 13, 1, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if errno != 0 || ctx.Err() != nil {
		var observationErr error
		if errno != 0 {
			observationErr = errno
		}
		return "", errors.Join(observationErr, ctx.Err())
	}
	if count != 64 || unsafe.Sizeof(info) != 64 || unsafe.Offsetof(info.state) != 12 || uint64(info.pid) != uint64(pid) {
		return "", fmt.Errorf("selected process state result differs: pid=%d observed=%d bytes=%d", pid, info.pid, count)
	}
	switch info.state {
	case 1:
		return "I", nil
	case 2:
		return "R", nil
	case 3:
		return "S", nil
	case 4:
		return "T", nil
	case 5:
		return "Z", nil
	default:
		return "", fmt.Errorf("selected process state is invalid: pid=%d state=%d", pid, info.state)
	}
}
