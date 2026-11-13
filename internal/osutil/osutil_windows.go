//go:build windows

package osutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
	errorIOPending          = syscall.Errno(997)
)

func lockFileEx(f *os.File, flags uint32) error {
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), uintptr(flags), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

// Lock takes an exclusive lock on the first byte of f, waiting for it.
func Lock(f *os.File) error { return lockFileEx(f, lockfileExclusiveLock) }

// TryLock takes the lock or fails at once with ErrWouldBlock.
func TryLock(f *os.File) error {
	err := lockFileEx(f, lockfileExclusiveLock|lockfileFailImmediately)
	if errors.Is(err, errorLockViolation) || errors.Is(err, errorIOPending) {
		return ErrWouldBlock
	}
	return err
}

// Unlock releases a lock taken by Lock or TryLock.
func Unlock(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

// OpenNoFollow refuses a symlink or junction in the last element. Windows
// has no O_NOFOLLOW for os.OpenFile, so this checks with Lstat first and
// compares the opened file with what Lstat saw, which closes the swap
// window that a plain check-then-open would leave. nonblock has no meaning
// here (Windows named pipes do not live in the file system).
func OpenNoFollow(path string, flag int, perm os.FileMode, nonblock bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err == nil && before.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("symlink or junction not followed")}
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil || before == nil {
		return f, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("file changed while opening")}
	}
	return f, nil
}
