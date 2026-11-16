package hostenv

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
)

// LogFile is an open log, read on from where the last run stopped.
type LogFile interface {
	io.Reader
	io.Seeker
	io.Closer
	// Stat is the opened file's, not the path's now: its ID tells the file
	// read from the one rotated in under the same name since.
	Stat() FileStat
}

// LogOpener is implemented by Sources that can stream a log from an
// offset, however large it is.
type LogOpener interface {
	OpenLog(path string) (LogFile, error)
	// OpenLogNoFollow refuses a symlink in the final element: for files
	// found by a pattern (rotated logs), whose trust was not judged.
	OpenLogNoFollow(path string) (LogFile, error)
}

// OpenLog opens p for reading through src. A Source without LogOpener (a
// fixture) gives the file as it read it, up to MaxFileBytes, with the stat
// it has (none: zero, and an empty ID).
func OpenLog(src Source, p string) (LogFile, error) { return openLog(src, p, false) }

// OpenLogNoFollow is OpenLog refusing a symlink in the final element.
func OpenLogNoFollow(src Source, p string) (LogFile, error) { return openLog(src, p, true) }

func openLog(src Source, p string, noFollow bool) (LogFile, error) {
	if o, ok := src.(LogOpener); ok {
		if noFollow {
			return o.OpenLogNoFollow(p)
		}
		return o.OpenLog(p)
	}
	if noFollow {
		if _, err := src.Readlink(p); err == nil {
			return nil, &fs.PathError{Op: "open", Path: p, Err: ErrSymlink}
		}
	}
	st, err := Stat(src, p)
	if err != nil && !errors.Is(err, ErrNoStat) && !errors.Is(err, ErrNotRecorded) {
		return nil, err
	}
	b, err := ReadFileMax(src, p, MaxFileBytes)
	if err != nil && !errors.Is(err, ErrTruncated) {
		return nil, err
	}
	if st.Size < int64(len(b)) {
		st.Size = int64(len(b))
	}
	return &memLog{Reader: bytes.NewReader(b), st: st}, nil
}

type memLog struct {
	*bytes.Reader
	st FileStat
}

func (m *memLog) Close() error   { return nil }
func (m *memLog) Stat() FileStat { return m.st }

// OpenLog opens a regular file (never a FIFO: openRead does not block),
// following links: the log's trust was judged on the path (LogTrust).
func (l *Live) OpenLog(p string) (LogFile, error) { return l.openLog(p, false) }

func (l *Live) OpenLogNoFollow(p string) (LogFile, error) { return l.openLog(p, true) }

func (l *Live) openLog(p string, noFollow bool) (LogFile, error) {
	f, err := openRead(l.path(p), noFollow)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: p, Err: notRegular("not a regular file")}
	}
	return &liveLog{File: f, st: FileStat{Mode: st.Mode(), Size: st.Size(), ModTime: st.ModTime(), UID: fileUID(st), GID: fileGID(st), ID: openedFileID(f, st)}}, nil
}

type liveLog struct {
	*os.File
	st FileStat
}

func (l *liveLog) Stat() FileStat { return l.st }
