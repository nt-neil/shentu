//go:build !windows

package hostenv

import (
	"fmt"
	"os"
	"syscall"
)

// fileID is "device:inode", which os.SameFile compares.
func fileID(st os.FileInfo) string {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
	}
	return ""
}

func fileUID(st os.FileInfo) int {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
