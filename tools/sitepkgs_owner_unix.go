//go:build !windows

package tools

import "github.com/nt-neil/shentu/hostenv"

// rootOnlyFile: p is a regular file (or, with dir, a folder) owned by root
// that no other user can write, as the system's package manager leaves
// what it installs.
// It is read through the host source.
func rootOnlyFile(p string, dir bool) bool {
	st, err := hostenv.Lstat(hostSource(), p)
	if err != nil || (dir && !st.Mode.IsDir()) || (!dir && !st.Mode.IsRegular()) || st.Mode.Perm()&0o022 != 0 {
		return false
	}
	return st.UID == 0
}
