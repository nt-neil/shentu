//go:build !windows

package hostenv

import (
	"os"
	"syscall"
)

func fileUID(st os.FileInfo) int {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
