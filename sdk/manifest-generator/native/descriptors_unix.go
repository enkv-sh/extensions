//go:build darwin || linux

package native

import (
	"os"
	"strconv"
	"syscall"
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
	last := 5
	for fd := 3; fd <= last; fd++ {
		want := syscall.O_RDONLY
		if fd >= 4 {
			want = syscall.O_WRONLY
		}
		var info syscall.Stat_t
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFIFO || errno != 0 || int(flags)&syscall.O_ACCMODE != want {
			return false
		}
	}
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return false
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	return readErr == nil && closeErr == nil && extraDescriptorsAbsent(names, last+1)
}
func extraDescriptorsAbsent(names []string, first int) bool {
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < first {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		// Runtime-owned close-on-exec descriptors do not extend the inherited
		// plugin interface. A vanished /dev/fd entry is also harmless.
		if errno == 0 && flags&syscall.FD_CLOEXEC == 0 || errno != 0 && errno != syscall.EBADF {
			return false
		}
	}
	return true
}
