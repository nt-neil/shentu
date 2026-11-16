//go:build !windows

package main

import (
	"os"
	"syscall"
)

// ownDir: st, a directory of the state's, is this process's user's.
func ownDir(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}
