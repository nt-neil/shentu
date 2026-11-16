package hostenv

import (
	"errors"
	"os"
)

// Lstater is implemented by Sources that can stat a symbolic link itself,
// not what it points to: who may repoint a link is its owner.
type Lstater interface {
	Lstat(path string) (FileStat, error)
}

// Lstat stats the link at path through src; ErrNoStat when it cannot.
func Lstat(src Source, path string) (FileStat, error) {
	if s, ok := src.(Lstater); ok {
		return s.Lstat(path)
	}
	return FileStat{}, ErrNoStat
}

func (l *Live) Lstat(path string) (FileStat, error) {
	st, err := os.Lstat(l.path(path))
	if err != nil {
		return FileStat{}, err
	}
	return FileStat{Mode: st.Mode(), Size: st.Size(), ModTime: st.ModTime(), UID: fileUID(st), GID: fileGID(st)}, nil
}

// ACLReader is implemented by Sources that can tell whether a path carries
// a POSIX access ACL: with one, the mode's group bits are only the mask,
// and a named user (u:www-data:rwx) may write what the group seems to.
type ACLReader interface {
	HasACL(path string) (bool, error)
}

// ErrNoACL is returned by HasACL for a Source that cannot tell.
var ErrNoACL = errors.New("hostenv: source cannot read ACLs")

// HasACL asks src; ErrNoACL when it cannot tell.
func HasACL(src Source, path string) (bool, error) {
	if a, ok := src.(ACLReader); ok {
		return a.HasACL(path)
	}
	return false, ErrNoACL
}

func (l *Live) HasACL(path string) (bool, error) { return hasACL(l.path(path)) }
