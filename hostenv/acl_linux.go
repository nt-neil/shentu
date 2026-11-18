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

// aclEntries reads and parses system.posix_acl_access: none without one.
func aclEntries(p string) ([]ACLEntry, error) {
	n, err := syscall.Getxattr(p, "system.posix_acl_access", nil)
	switch {
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
		return nil, nil
	case err != nil:
		return nil, err
	case n <= 0:
		return nil, nil
	}
	b := make([]byte, n)
	if n, err = syscall.Getxattr(p, "system.posix_acl_access", b); err != nil {
		return nil, err
	}
	return parseACL(b[:n])
}
