//go:build linux

package hostenv

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// pathBorn is the file's birth time (statx btime), zero where the file
// system or kernel does not keep one: what tells a file from a later one
// given the same inode.
func pathBorn(p string) time.Time {
	var st unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, p, 0, unix.STATX_BTIME, &st) != nil || st.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}
	}
	return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)).UTC()
}

// fileBorn is pathBorn of an open file.
func fileBorn(f *os.File, _ os.FileInfo) time.Time {
	var st unix.Statx_t
	if unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &st) != nil || st.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}
	}
	return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)).UTC()
}
