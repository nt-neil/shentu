//go:build windows

package hostenv

import (
	"fmt"
	"io/fs"
	"os"
)

// beforeOpen runs between the Lstat and the open of a no-follow read (tests
// swap the file there).
var beforeOpen = func(string) {}

// openRead on Windows refuses a reparse point (symlink or junction) in the
// last element: Windows has no O_NOFOLLOW, so it Lstats, takes the file's
// ID then (volume and index, by a handle of its own), opens, and compares
// that with the opened handle's ID: one swapped in between is refused,
// never read. os.SameFile cannot tell: on Windows it reads a Lstat's ID
// from the path only when asked, so after the swap, the new file's.
func openRead(path string, noFollow bool) (*os.File, error) {
	if !noFollow {
		return os.Open(path)
	}
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	id := pathFileID(path, lst)
	beforeOpen(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if id == "" || openedFileID(f, nil) != id {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: ErrChanged}
	}
	return f, nil
}
