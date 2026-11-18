//go:build !windows

package detect

import (
	"os"
	"strconv"
	"syscall"
)

// openNoFollow opens p for reading, refusing a link (ELOOP), and never
// blocking on a FIFO.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// syncDir syncs a directory, making a rename in it durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ownedByUs says why a state file is not to be believed: a link, not a
// regular file, owned by another user, or writable by group or others.
func ownedByUs(st os.FileInfo) string {
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return "a symbolic link"
	case !st.Mode().IsRegular():
		return "not a regular file"
	case st.Mode().Perm()&0o022 != 0:
		return "writable by group or others"
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && int(s.Uid) != os.Geteuid() {
		return "owned by uid " + strconv.Itoa(int(s.Uid))
	}
	return ""
}
