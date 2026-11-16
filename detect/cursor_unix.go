//go:build !windows

package detect

import (
	"os"
	"strconv"
	"syscall"
)

// ownedByUs says why a state file is not to be believed: a link, not a
// regular file, owned by another user, or writable by group or others.
func ownedByUs(st os.FileInfo) string {
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return "a symbolic link"
	case !st.Mode().IsRegular():
		return "not a regular file"
	case st.Mode().Perm()&0o022 != 0:
		return "writable by group or others"
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && int(s.Uid) != os.Geteuid() {
		return "owned by uid " + strconv.Itoa(int(s.Uid))
	}
	return ""
}
