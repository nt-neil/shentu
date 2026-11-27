package hostenv

import (
	"io/fs"
	"syscall"
	"time"
)

// statExtra is a file's status-change time and hard links on macOS.
func statExtra(info fs.FileInfo) (*time.Time, *uint64, []string) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, nil
	}
	ct, n := time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec), uint64(st.Nlink)
	return &ct, &n, nil
}
