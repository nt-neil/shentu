//go:build !windows

package tools

import (
	"os"
	"syscall"
)

// rootOnlyFile: p is a regular file (or, with dir, a folder) owned by root
// that no other user can write, as the system's package manager leaves
// what it installs.
func rootOnlyFile(p string, dir bool) bool {
	st, err := os.Lstat(p)
	if err != nil || (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) || st.Mode().Perm()&0o022 != 0 {
		return false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0
}
