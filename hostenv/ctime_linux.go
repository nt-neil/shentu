package hostenv

import (
	"io/fs"
	"syscall"
	"time"
)

// statExtra is a file's status-change time and hard links on Linux.
func statExtra(info fs.FileInfo) (*time.Time, *uint64, []string) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, nil
	}
	ct, n := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), uint64(st.Nlink)
	return &ct, &n, nil
}
