//go:build !windows

package hostenv

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openRead never blocks on a FIFO (O_NONBLOCK) and, when asked, refuses a
// symlink in the final element (O_NOFOLLOW).
func openRead(path string, noFollow bool) (*os.File, error) {
	flag := os.O_RDONLY | syscall.O_NONBLOCK
	if noFollow {
		flag |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil && noFollow && errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	return f, err
}
