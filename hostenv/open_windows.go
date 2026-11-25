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
// last element: Windows has no O_NOFOLLOW, so it Lstats, opens, and
// compares the opened file with what the Lstat saw (as osutil.OpenNoFollow
// does): one swapped in between is refused, never read.
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
	beforeOpen(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !os.SameFile(lst, st) {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: ErrChanged}
	}
	return f, nil
}
