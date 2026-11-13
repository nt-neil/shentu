//go:build windows

package hostenv

import (
	"fmt"
	"os"
)

// openRead on Windows checks for a reparse point (symlink or junction)
// before opening. Phase 2 replaces this with CreateFile and
// FILE_FLAG_OPEN_REPARSE_POINT to close the check-then-open window.
func openRead(path string, noFollow bool) (*os.File, error) {
	if noFollow {
		if st, err := os.Lstat(path); err == nil && st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
		}
	}
	return os.Open(path)
}
