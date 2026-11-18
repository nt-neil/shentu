//go:build !linux

package hostenv

// hasACL is not read off Linux: the log checks it serves are Linux's.
func hasACL(string) (bool, error) { return false, ErrNoACL }

func aclEntries(string) ([]ACLEntry, error) { return nil, ErrNoACL }
