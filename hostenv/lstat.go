package hostenv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
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
	fst, st, err := l.lstat(path)
	// A regular file's ID, as Stat gives it: ReadFileIfSame compares the
	// file read with the one a walk saw. Only a regular file is read, and a
	// walk lstats every entry: on Windows the ID costs an open.
	if err == nil && st.Mode().IsRegular() {
		fst.ID = pathFileID(l.path(path), st)
	}
	return fst, err
}

// LstatNoID is Lstat without the file ID: no file is opened (on Windows
// the ID costs one). For a walk that reads no file it saw by its ID
// (file_changes, S-276-1).
func (l *Live) LstatNoID(path string) (FileStat, error) {
	fst, _, err := l.lstat(path)
	return fst, err
}

func (l *Live) lstat(path string) (FileStat, os.FileInfo, error) {
	st, err := os.Lstat(l.path(path))
	if err != nil {
		return FileStat{}, nil, err
	}
	return withStatExtra(FileStat{Mode: st.Mode(), Size: st.Size(), ModTime: st.ModTime(), UID: fileUID(st), GID: fileGID(st)}, st), st, nil
}

// lstatNoIDer is implemented by Sources whose Lstat can skip the file ID.
type lstatNoIDer interface {
	LstatNoID(path string) (FileStat, error)
}

// lstatNoID is LstatNoID where the source has it, else Lstat.
func lstatNoID(src Source, path string) (FileStat, error) {
	if s, ok := src.(lstatNoIDer); ok {
		return s.LstatNoID(path)
	}
	return Lstat(src, path)
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

// ACLEntry is one entry of a POSIX access ACL (acl_ea_entry): its tag,
// its permissions (r 4, w 2, x 1) and, for a named user or group, its id.
type ACLEntry struct {
	Tag, Perm uint16
	ID        uint32
}

// ACL entry tags (acl_ea_entry's e_tag).
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
)

// ACLEntryReader is implemented by Sources that can read a path's POSIX
// access ACL entries (none: no ACL).
type ACLEntryReader interface {
	ACLEntries(path string) ([]ACLEntry, error)
}

// ACLEntries asks src; ErrNoACL when it cannot tell.
func ACLEntries(src Source, path string) ([]ACLEntry, error) {
	if a, ok := src.(ACLEntryReader); ok {
		return a.ACLEntries(path)
	}
	return nil, ErrNoACL
}

func (l *Live) ACLEntries(path string) ([]ACLEntry, error) { return aclEntries(l.path(path)) }

// parseACL reads a system.posix_acl_access value: a version 2 header,
// then 8-byte entries, little-endian.
func parseACL(b []byte) ([]ACLEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != 2 {
		return nil, fmt.Errorf("hostenv: not a POSIX ACL (%d bytes)", len(b))
	}
	var out []ACLEntry
	for i := 4; i < len(b); i += 8 {
		out = append(out, ACLEntry{binary.LittleEndian.Uint16(b[i:]), binary.LittleEndian.Uint16(b[i+2:]), binary.LittleEndian.Uint32(b[i+4:])})
	}
	return out, nil
}

// aclWriters names the users and groups an ACL's named entries let write
// (the mask applied), "" when none or when the ACL cannot be read (the
// caller's mode check stands then); webAccount: one is a web account's.
func aclWriters(src Source, p string, web WebAccounts) (names string, webAccount bool) {
	es, err := ACLEntries(src, p)
	if err != nil {
		return "", false
	}
	mask := uint16(7)
	for _, e := range es {
		if e.Tag == aclMask {
			mask = e.Perm
		}
	}
	var ns []string
	for _, e := range es {
		if e.Perm&mask&2 == 0 {
			continue
		}
		id := int(e.ID)
		switch e.Tag {
		case aclUser:
			if n, ok := web.UIDs[id]; ok {
				ns, webAccount = append(ns, fmt.Sprintf("%s (uid %d)", n, id)), true
			} else {
				ns = append(ns, fmt.Sprintf("uid %d", id))
			}
		case aclGroup:
			n, ok := web.GIDs[id]
			webAccount = webAccount || ok
			if !ok {
				n, ok = web.LogGIDs[id]
			}
			if ok {
				ns = append(ns, fmt.Sprintf("group %s (gid %d)", n, id))
			} else {
				ns = append(ns, fmt.Sprintf("gid %d", id))
			}
		}
	}
	return strings.Join(ns, ", "), webAccount
}
