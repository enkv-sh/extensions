package artifact

import (
	"errors"
	"os"
	"syscall"
)

// openObservedFile rejects last-component symlinks and opens nonblocking before
// checking the observed identity. A substituted FIFO must not block the caller
// before the regular-file/identity checks can reject it.
func openObservedFile(path string, before os.FileInfo) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameObservedFile(before, opened) {
		return nil, errors.Join(ErrRecord, statErr, file.Close())
	}
	return file, nil
}

func sameObservedFile(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size()
}

func checkObservedPath(path string, before os.FileInfo) error {
	after, err := os.Lstat(path)
	if err != nil || !sameObservedFile(before, after) {
		return errors.Join(ErrRecord, err)
	}
	return nil
}
