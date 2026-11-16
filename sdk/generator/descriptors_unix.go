//go:build darwin || linux

package generator

import (
	"os"
	"strconv"
	"syscall"

	protocol "enkv.sh/sdk/protocols/generator"
)

func fixedDescriptors() bool {
	var null syscall.Stat_t
	if syscall.Stat("/dev/null", &null) != nil {
		return false
	}
	for fd := 0; fd <= 2; fd++ {
		var info syscall.Stat_t
		if syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFCHR || info.Rdev != null.Rdev {
			return false
		}
	}
	for fd, want := range map[int]int{protocol.ControlDescriptor: syscall.O_RDONLY, protocol.EnvironmentDescriptor: syscall.O_RDONLY, protocol.SecretResultDescriptor: syscall.O_WRONLY, protocol.StatusDescriptor: syscall.O_WRONLY} {
		var info syscall.Stat_t
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFL), 0)
		if syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFIFO || errno != 0 || int(flags)&syscall.O_ACCMODE != want {
			return false
		}
		if !setDescriptorCloseOnExec(uintptr(fd)) {
			return false
		}
	}
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return false
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	return readErr == nil && closeErr == nil && extraDescriptorsAbsent(names)
}

func extraDescriptorsAbsent(names []string) bool {
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < protocol.FirstUnassignedDescriptor {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
		if errno == 0 && flags&syscall.FD_CLOEXEC == 0 || errno != 0 && errno != syscall.EBADF {
			return false
		}
	}
	return true
}

func setDescriptorCloseOnExec(fd uintptr) bool {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		return false
	}
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_SETFD), flags|uintptr(syscall.FD_CLOEXEC))
	return errno == 0
}
