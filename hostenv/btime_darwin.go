//go:build darwin

package hostenv

import (
	"os"
	"syscall"
	"time"
)

func pathBorn(p string) time.Time {
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return born(st)
}

func fileBorn(_ *os.File, st os.FileInfo) time.Time { return born(st) }

func born(st os.FileInfo) time.Time {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return time.Unix(s.Birthtimespec.Sec, s.Birthtimespec.Nsec).UTC()
	}
	return time.Time{}
}
