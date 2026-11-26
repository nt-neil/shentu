//go:build windows

package osutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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

// beforeOpen runs right before OpenNoFollow's open (tests swap the file for
// a link there).
var beforeOpen = func(string) {}

// OpenNoFollow refuses a symlink or junction in the last element. Windows
// has no O_NOFOLLOW for os.OpenFile: the path is opened once, not following
// a reparse point (FILE_FLAG_OPEN_REPARSE_POINT), that handle's own
// attributes are checked, and it is the file returned, so nothing can be
// swapped between the check and the use. (A Lstat, an open and os.SameFile
// could not tell a swap: on Windows SameFile reads the Lstat's ID from the
// path only when asked, by then the swapped-in file's.) flag takes
// O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_CREATE, O_EXCL, O_TRUNC, as
// os.OpenFile does; perm only says read-only for a file it creates.
// nonblock has no meaning here (named pipes do not live in the file system).
func OpenNoFollow(path string, flag int, perm os.FileMode, nonblock bool) (*os.File, error) {
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = syscall.GENERIC_READ
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= syscall.GENERIC_WRITE
		access |= syscall.FILE_APPEND_DATA
	}
	var create uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		create = syscall.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		create = syscall.CREATE_ALWAYS
	case flag&os.O_CREATE == os.O_CREATE:
		create = syscall.OPEN_ALWAYS
	case flag&os.O_TRUNC == os.O_TRUNC:
		create = syscall.TRUNCATE_EXISTING
	default:
		create = syscall.OPEN_EXISTING
	}
	attrs := uint32(syscall.FILE_ATTRIBUTE_NORMAL | fileFlagOpenReparsePoint | syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if flag&os.O_CREATE != 0 && perm&0o200 == 0 {
		attrs |= syscall.FILE_ATTRIBUTE_READONLY
	}
	share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	beforeOpen(path)
	h, err := syscall.CreateFile(p16, access, share, nil, create, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var ti struct{ FileAttributes, ReparseTag uint32 } // FILE_ATTRIBUTE_TAG_INFO
	if err := windows.GetFileInformationByHandleEx(windows.Handle(h), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti))); err != nil {
		syscall.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	switch kind := ReparseKind(ti.FileAttributes, ti.ReparseTag); {
	case kind == "link":
		syscall.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("symlink or junction not followed")}
	case kind != "":
		syscall.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New(kind)}
	case ti.FileAttributes&FileAttributeReparsePoint == 0:
		return os.NewFile(uintptr(h), path), nil
	}
	// Deduplicated (Data Deduplication): a regular file, opened again
	// through its filter, and used only if it is the same file.
	id, ok := handleID(h)
	syscall.CloseHandle(h)
	h2, err := syscall.CreateFile(p16, access, share, nil, syscall.OPEN_EXISTING, attrs&^fileFlagOpenReparsePoint, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if id2, ok2 := handleID(h2); !ok || !ok2 || id2 != id {
		syscall.CloseHandle(h2)
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("file changed while opening")}
	}
	return os.NewFile(uintptr(h2), path), nil
}

// handleID is the volume and file index of an open handle.
func handleID(h syscall.Handle) ([3]uint32, bool) {
	var fi syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(h, &fi) != nil {
		return [3]uint32{}, false
	}
	return [3]uint32{fi.VolumeSerialNumber, fi.FileIndexHigh, fi.FileIndexLow}, true
}

// fileFlagOpenReparsePoint is FILE_FLAG_OPEN_REPARSE_POINT (syscall lacks it).
const fileFlagOpenReparsePoint = 0x00200000
