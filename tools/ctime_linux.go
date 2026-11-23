package tools

import (
	"io/fs"
	"syscall"
	"time"
)

func ctimeUID(info fs.FileInfo) (time.Time, uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, 0, false
	}
	return time.Unix(st.Ctim.Sec, st.Ctim.Nsec), st.Uid, true
}

// nlink is a file's hard-link count (S-186-1).
func nlink(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
