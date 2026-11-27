package hostenv

import (
	"errors"
	"io/fs"
	"path/filepath"
)

// WalkFunc is called by Walk for each path: st is its Lstat (a link is
// the link, never followed), err the Lstat's or, called a second time for
// a directory, its ReadDir's. As fs.WalkDirFunc, fs.SkipDir skips a
// directory (or the rest of a file's directory) and fs.SkipAll stops.
type WalkFunc func(path string, st FileStat, err error) error

// Walk walks the tree at root through src, in lexical order (ReadDir's
// names are sorted), as filepath.WalkDir does on the machine: what is read
// is the host source's (a replay, another host's survey), not the machine
// running the check. Links are not followed. A Source without Lstat gives
// ErrNoStat for every path; a fixture without the path, ErrNotRecorded.
func Walk(src Source, root string, fn WalkFunc) error {
	return walkWith(Lstat, src, root, fn)
}

// WalkNoID is Walk with no file ID in the stats (FileStat.ID ""): no file
// is opened (on Windows Lstat opens every regular file for it), for a walk
// that reads no file by the ID it saw (file_changes, S-276-1).
func WalkNoID(src Source, root string, fn WalkFunc) error {
	return walkWith(lstatNoID, src, root, fn)
}

func walkWith(lstat func(Source, string) (FileStat, error), src Source, root string, fn WalkFunc) error {
	st, err := lstat(src, root)
	err = walk(lstat, src, root, st, err, fn)
	if errors.Is(err, fs.SkipDir) || errors.Is(err, fs.SkipAll) {
		return nil
	}
	return err
}

func walk(lstat func(Source, string) (FileStat, error), src Source, p string, st FileStat, serr error, fn WalkFunc) error {
	if err := fn(p, st, serr); err != nil {
		return err
	}
	if serr != nil || !st.Mode.IsDir() {
		return nil
	}
	names, err := src.ReadDir(p)
	if err != nil {
		if err := fn(p, st, err); err != nil {
			return err
		}
	}
	for _, n := range names {
		c := filepath.Join(p, n)
		cst, cerr := lstat(src, c)
		if err := walk(lstat, src, c, cst, cerr, fn); err != nil {
			if !errors.Is(err, fs.SkipDir) {
				return err
			}
			if cerr != nil || !cst.Mode.IsDir() {
				return nil // SkipDir on a file: the rest of this directory skipped
			}
		}
	}
	return nil
}
