package tools

import (
	"io/fs"
	"syscall"
	"time"
)

// ctimeUID is a file's status-change time and owner on macOS (M0): a
// changed mtime is easy to fake, ctime is not, as on Linux.
func ctimeUID(info fs.FileInfo) (time.Time, uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, 0, false
	}
	return time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec), st.Uid, true
}
