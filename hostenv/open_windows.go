//go:build windows

package hostenv

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// beforeOpen runs right before the open of a no-follow read (tests swap the
// file for a link there).
var beforeOpen = func(string) {}

// openRead on Windows refuses a reparse point (symlink or junction) in the
// last element. Windows has no O_NOFOLLOW: the path is opened once, not
// following a reparse point (FILE_FLAG_OPEN_REPARSE_POINT), the handle's
// own attributes are checked, and that handle is what is read. There is no
// window between the check and the read: a Lstat then an open, compared by
// os.SameFile (which reads the Lstat's ID from the path only when asked),
// read a file swapped in between.
func openRead(path string, noFollow bool) (*os.File, error) {
	if !noFollow {
		return os.Open(path)
	}
	beforeOpen(path)
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p16, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	return os.NewFile(uintptr(h), path), nil
}
