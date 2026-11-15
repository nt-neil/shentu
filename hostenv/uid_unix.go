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

// openedFileID and pathFileID are fileID here; Windows needs the file.
func openedFileID(_ *os.File, st os.FileInfo) string { return fileID(st) }

func pathFileID(_ string, st os.FileInfo) string { return fileID(st) }

func fileUID(st os.FileInfo) int {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
