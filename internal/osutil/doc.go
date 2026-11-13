// Package osutil holds the few file operations whose system calls differ
// between Unix and Windows: advisory file locks, and opening a file without
// following a symlink in its last element. Everything else in Shentu uses
// the standard library directly.
package osutil

import "errors"

// ErrWouldBlock is returned by TryLock when another process holds the lock.
var ErrWouldBlock = errors.New("osutil: lock held by another process")
