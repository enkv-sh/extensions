package artifact

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestObservedArtifactInputRefusesChangedPath(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "regular"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			for _, replacement := range []string{"unchanged", "fifo", "symlink_to_original", "foreign_inode", "changed_mode"} {
				t.Run(replacement, func(t *testing.T) {
					root := t.TempDir()
					path := filepath.Join(root, "input")
					if directory {
						if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(path, []byte("original bounded input"), 0600); err != nil {
						t.Fatal(err)
					}
					before, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					original, err := os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := original.Close(); err != nil {
							t.Error(err)
						}
					}()
					if replacement == "changed_mode" {
						if err := os.Chmod(path, 0755); err != nil {
							t.Fatal(err)
						}
					} else if replacement != "unchanged" {
						saved := filepath.Join(root, "original")
						if err := os.Rename(path, saved); err != nil {
							t.Fatal(err)
						}
						switch replacement {
						case "fifo":
							err = syscall.Mkfifo(path, 0600)
						case "symlink_to_original":
							err = os.Symlink(saved, path)
						case "foreign_inode":
							if directory {
								err = os.Mkdir(path, 0700)
							} else {
								err = os.WriteFile(path, []byte("original bounded input"), 0600)
							}
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					err, blocked := joinedArtifactInputCall(t, path, func() error {
						file, err := openObservedFile(path, before)
						if err != nil {
							if file != nil {
								return errors.Join(errors.New("refused input retained a descriptor"), err, file.Close())
							}
							return err
						}
						if replacement == "unchanged" && !directory {
							body, readErr := io.ReadAll(file)
							if string(body) != "original bounded input" {
								readErr = errors.Join(readErr, errors.New("unchanged input bytes differ"))
							}
							return errors.Join(readErr, file.Close())
						}
						return file.Close()
					})
					if blocked {
						t.Fatal("observed input open blocked until a FIFO writer was supplied")
					}
					switch replacement {
					case "unchanged":
						if err != nil {
							t.Fatal("unchanged input refused", err)
						}
					case "symlink_to_original":
						if !errors.Is(err, syscall.ELOOP) {
							t.Fatal("replacement symlink did not refuse at non-following open", err)
						}
					default:
						if !errors.Is(err, ErrRecord) {
							t.Fatal("changed input did not refuse at observed identity", err)
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestVerifyExecutableBuildInfoUsesOpenedFile(t *testing.T) {
	metadata, path := publicationFixture(t, "opened executable input")
	if err := VerifyExecutable(t.Context(), path, metadata); err != nil {
		t.Fatal("valid original executable refused", err)
	}
	different := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(different, []byte("different executable bytes"), 0500); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutable(t.Context(), different, metadata); !errors.Is(err, ErrRecord) {
		t.Fatal("measured executable mismatch did not identify a refused artifact", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if open, err := artifactInputIsOpen(before); err != nil || open {
		t.Fatal("fixture executable already has an open descriptor", open, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	swap := &replaceOpenedArtifactInput{Context: ctx, cancel: cancel, path: path, saved: filepath.Join(t.TempDir(), "original"), before: before}
	err, blocked := joinedArtifactInputCall(t, path, func() error { return VerifyExecutable(swap, path, metadata) })
	if swap.replaced {
		if restoreErr := errors.Join(os.Remove(path), os.Rename(swap.saved, path)); restoreErr != nil {
			t.Fatal("restore original after joined verification", restoreErr)
		}
	}
	if swap.setupErr != nil || !swap.replaced {
		t.Fatal("fixture did not replace the opened executable", swap.replaced, swap.setupErr)
	}
	if controlErr := VerifyExecutable(t.Context(), path, metadata); controlErr != nil {
		t.Fatal("restored executable refused", controlErr)
	}
	if blocked {
		t.Fatal("build information reopened the replaced path and blocked on its FIFO")
	}
	if !errors.Is(err, ErrRecord) {
		t.Fatal("replaced executable path did not return changed-input refusal", err)
	}
}

// The writer releases the old blocking open before the test reports its failure.
func joinedArtifactInputCall(t *testing.T, fifoPath string, call func() error) (error, bool) {
	t.Helper()
	results := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		results <- call()
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-results:
		<-joined
		return err, false
	case <-timer.C:
	}
	writer, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("could not release the FIFO opener", err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	join := time.NewTimer(2 * time.Second)
	defer join.Stop()
	select {
	case err := <-results:
		<-joined
		return err, true
	case <-join.C:
		t.Fatal("FIFO opener did not positively join after release")
		return nil, true
	}
}

type replaceOpenedArtifactInput struct {
	context.Context
	cancel   context.CancelFunc
	path     string
	saved    string
	before   os.FileInfo
	replaced bool
	setupErr error
}

func (c *replaceOpenedArtifactInput) Err() error {
	if c.replaced || c.setupErr != nil {
		return c.Context.Err()
	}
	open, err := artifactInputIsOpen(c.before)
	if err != nil {
		c.setupErr = err
		c.cancel()
		return c.Context.Err()
	}
	if !open {
		return c.Context.Err()
	}
	if err := os.Rename(c.path, c.saved); err != nil {
		c.setupErr = err
		c.cancel()
		return c.Context.Err()
	}
	if err := syscall.Mkfifo(c.path, 0600); err != nil {
		c.setupErr = err
		c.cancel()
		return c.Context.Err()
	}
	c.replaced = true
	return c.Context.Err()
}

func artifactInputIsOpen(before os.FileInfo) (bool, error) {
	identity, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("fixture input has no native file identity")
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var actual syscall.Stat_t
		if err := syscall.Fstat(fd, &actual); err != nil {
			if errors.Is(err, syscall.EBADF) {
				continue
			}
			return false, err
		}
		if identity.Dev == actual.Dev && identity.Ino == actual.Ino {
			return true, nil
		}
	}
	return false, nil
}
