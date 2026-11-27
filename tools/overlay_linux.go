package tools

import (
	"io/fs"
	"syscall"
)

// overlayWhiteoutFile: fi is overlayfs' whiteout, a character device 0:0.
func overlayWhiteoutFile(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0
}

// overlayOpaqueDir: p carries overlayfs' opaque mark (trusted.overlay.opaque
// "y", or user.overlay.opaque for an unprivileged overlay).
func overlayOpaqueDir(p string) bool {
	buf := make([]byte, 8)
	for _, a := range []string{"trusted.overlay.opaque", "user.overlay.opaque"} {
		if n, err := syscall.Getxattr(p, a, buf); err == nil && n == 1 && buf[0] == 'y' {
			return true
		}
	}
	return false
}
