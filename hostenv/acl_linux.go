//go:build linux

package hostenv

import (
	"errors"
	"syscall"
)

// hasACL: the path has a system.posix_acl_access attribute. A file system
// without ACLs (ENOTSUP) has none.
func hasACL(p string) (bool, error) {
	n, err := syscall.Getxattr(p, "system.posix_acl_access", nil)
	switch {
	case err == nil:
		return n > 0, nil
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
		return false, nil
	}
	return false, err
}
