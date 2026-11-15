//go:build !windows

package osutil

import (
	"errors"
	"os"
	"syscall"
)

// Lock takes an exclusive lock on f, waiting for it.
func Lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// TryLock takes an exclusive lock on f or fails at once with ErrWouldBlock.
func TryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrWouldBlock
	}
	return err
}

// Unlock releases a lock taken by Lock or TryLock.
func Unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// OpenNoFollow opens path like os.OpenFile but fails when its last element
// is a symlink; nonblock also keeps a FIFO from blocking the open.
func OpenNoFollow(path string, flag int, perm os.FileMode, nonblock bool) (*os.File, error) {
	flag |= syscall.O_NOFOLLOW
	if nonblock {
		flag |= syscall.O_NONBLOCK
	}
	return os.OpenFile(path, flag, perm)
}
