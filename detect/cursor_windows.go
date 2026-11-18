//go:build windows

package detect

import (
	"fmt"
	"os"
)

// openNoFollow refuses a link (a reparse point) and opens the file.
func openNoFollow(p string) (*os.File, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s: a symbolic link", p)
	}
	return os.Open(p)
}

// syncDir: Windows makes a rename durable with the file; nothing to sync.
func syncDir(string) error { return nil }

// ownedByUs: Windows has no uid to compare (the state directory's ACL is
// the service's); links and non-regular files are still refused.
func ownedByUs(st os.FileInfo) string {
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return "a symbolic link"
	case !st.Mode().IsRegular():
		return "not a regular file"
	}
	return ""
}
