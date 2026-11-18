//go:build windows

package hostenv

import (
	"os"
	"syscall"
	"time"
)

// pathBorn is the file's CreationTime, which NTFS keeps.
func pathBorn(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return born(st)
}

func fileBorn(_ *os.File, st os.FileInfo) time.Time { return born(st) }

func born(st os.FileInfo) time.Time {
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok && d.CreationTime.Nanoseconds() > 0 {
		return time.Unix(0, d.CreationTime.Nanoseconds()).UTC()
	}
	return time.Time{}
}
