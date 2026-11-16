//go:build windows

package detect

import "os"

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
