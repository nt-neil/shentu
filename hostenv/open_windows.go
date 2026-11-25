//go:build windows

package hostenv

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/nt-neil/shentu/internal/osutil"
	"golang.org/x/sys/windows"
)

// beforeOpen runs right before the open of a no-follow read (tests swap the
// file for a link there).
var beforeOpen = func(string) {}

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO, class FileAttributeTagInfo.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

const fileAttributeTagInfoClass = 9

// openRead on Windows refuses a link (symlink, junction, mount point) in the
// last element. Windows has no O_NOFOLLOW: the path is opened once, not
// following a reparse point (FILE_FLAG_OPEN_REPARSE_POINT), and that
// handle's attributes and reparse tag decide (osutil.ReparseKind, as Go's
// os.Lstat reads them): a name surrogate is refused, another tag is not a
// regular file, a plain file is read from that handle. There is no window
// between the check and the read (a Lstat, an open and os.SameFile, which
// reads the Lstat's ID from the path only when asked, read a file swapped
// in between). A deduplicated file (Data Deduplication) is a regular file:
// opened again without the flag, so its filter gives its contents, and read
// only if that is the same file (its ID).
func openRead(path string, noFollow bool) (*os.File, error) {
	if !noFollow {
		return os.Open(path)
	}
	beforeOpen(path)
	h, err := openHandle(path, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return nil, err
	}
	var ti fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(h, fileAttributeTagInfoClass, (*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti))); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	switch kind := osutil.ReparseKind(ti.FileAttributes, ti.ReparseTag); {
	case kind == "link":
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	case kind != "":
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("%w: %s", ErrNotRegular, kind)}
	case ti.FileAttributes&osutil.FileAttributeReparsePoint == 0:
		return os.NewFile(uintptr(h), path), nil
	}
	// Deduplicated: the same file, opened through its filter.
	id := handleFileID(h)
	windows.CloseHandle(h)
	h2, err := openHandle(path, 0)
	if err != nil {
		return nil, err
	}
	if id == "" || handleFileID(h2) != id {
		windows.CloseHandle(h2)
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrChanged}
	}
	return os.NewFile(uintptr(h2), path), nil
}

func openHandle(path string, flags uint32) (windows.Handle, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p16, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return h, nil
}
