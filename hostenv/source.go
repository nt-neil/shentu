package hostenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Source is the only way a collector reaches the host. Live reads the
// machine; Recorder wraps a Source and saves what it returned; Replay plays a
// saved fixture back. Paths are in the host's own spelling.
type Source interface {
	Info() SourceInfo
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error) // sorted entry names
	Readlink(path string) (string, error)
	Run(ctx context.Context, argv []string) (CmdResult, error)
}

// SourceInfo describes the host as a whole. It is part of every fixture, so
// replay sees the recorded machine's OS and arch rather than its own.
type SourceInfo struct {
	GOOS       string    `json:"goos"`
	GOARCH     string    `json:"goarch"`
	Elevated   bool      `json:"elevated"`
	RecordedAt time.Time `json:"recorded_at"`
}

// MaxFileBytes caps a single file read.
const MaxFileBytes = 8 << 20

var (
	// ErrNotRecorded is returned by Replay for a request the fixture lacks.
	ErrNotRecorded = errors.New("hostenv: not in fixture")
	// ErrSymlink is returned by ReadFileNoFollow for a symbolic link.
	ErrSymlink = errors.New("hostenv: symlink not followed")
	// ErrNotRegular refuses FIFOs, devices and sockets, which could block
	// or never end.
	ErrNotRegular = errors.New("hostenv: not a regular file")
)

// notRegular is ErrNotRegular with the reason in words.
type notRegular string

func (e notRegular) Error() string        { return string(e) }
func (e notRegular) Is(target error) bool { return target == ErrNotRegular }

// NoFollowReader is implemented by Sources that can refuse a symlink in the
// final path element. Use ReadFileNoFollow for paths a user controls.
type NoFollowReader interface {
	ReadFileNoFollow(path string) ([]byte, error)
}

// LargeReader is implemented by Sources that can read past MaxFileBytes,
// for logs a check must see whole (a brute force fills auth.log).
type LargeReader interface {
	ReadFileMax(path string, max int64) ([]byte, error)
}

// ReadFileMax reads up to max bytes through src when it supports it.
func ReadFileMax(src Source, path string, max int64) ([]byte, error) {
	if l, ok := src.(LargeReader); ok {
		return l.ReadFileMax(path, max)
	}
	return src.ReadFile(path)
}

// FileStat is the part of a stat result the collectors use.
type FileStat struct {
	Mode    fs.FileMode `json:"mode"`
	Size    int64       `json:"size"`
	ModTime time.Time   `json:"mtime"`
	UID     int         `json:"uid"`          // owner; -1 when the system has none to tell (Windows)
	ID      string      `json:"id,omitempty"` // device:inode, to tell the same file from a swapped one ("" unknown)
}

// ErrChanged is returned when a file is not the one stat looked at: it was
// swapped between the check and the read.
var ErrChanged = errors.New("hostenv: file changed between check and read")

// SameReader is implemented by Sources that can read a file only if it is
// still the one a Stat returned.
type SameReader interface {
	ReadFileIfSame(path string, want FileStat) ([]byte, error)
}

// ReadFileIfSame reads path without following a final link, and only if it
// is still the file want describes (as v0.2.5's readSmallRegular did with
// os.SameFile); Sources without the check (fixtures) read it as is.
func ReadFileIfSame(src Source, path string, want FileStat) ([]byte, error) {
	if s, ok := src.(SameReader); ok {
		return s.ReadFileIfSame(path, want)
	}
	return ReadFileNoFollow(src, path)
}

// Stater is implemented by Sources that can stat a path (following links).
type Stater interface {
	Stat(path string) (FileStat, error)
}

// ErrNoStat is returned by Stat for a Source that cannot stat.
var ErrNoStat = errors.New("hostenv: source cannot stat")

// Stat stats path through src when it supports it.
func Stat(src Source, path string) (FileStat, error) {
	if s, ok := src.(Stater); ok {
		return s.Stat(path)
	}
	return FileStat{}, ErrNoStat
}

// ReadFileNoFollow reads path without following a final symlink when src
// supports it, and falls back to ReadFile for sources that only replay.
func ReadFileNoFollow(src Source, path string) ([]byte, error) {
	if nf, ok := src.(NoFollowReader); ok {
		return nf.ReadFileNoFollow(path)
	}
	return src.ReadFile(path)
}

// Live reads the machine it runs on.
type Live struct {
	Runner *Runner
	// Remap redirects path prefixes, e.g. {"/proc": "/host/proc"} for a
	// host mounted into a container, or a temp tree in tests. The longest
	// matching prefix wins; commands are not remapped.
	Remap map[string]string
	now   func() time.Time
}

func (l *Live) path(p string) string {
	best := ""
	for from := range l.Remap {
		if (p == from || strings.HasPrefix(p, strings.TrimSuffix(from, "/")+"/")) && len(from) > len(best) {
			best = from
		}
	}
	if best == "" {
		return p
	}
	return l.Remap[best] + strings.TrimPrefix(p, strings.TrimSuffix(best, "/"))
}

// NewLive builds a live Source whose commands are limited to allow.
func NewLive(allow [][]string) (*Live, error) {
	r, err := NewRunner(allow)
	if err != nil {
		return nil, err
	}
	return &Live{Runner: r, now: time.Now}, nil
}

func (l *Live) Info() SourceInfo {
	return SourceInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Elevated: elevated(), RecordedAt: l.now().UTC()}
}

func (l *Live) ReadFile(path string) ([]byte, error) { return l.read(path, false, MaxFileBytes) }

func (l *Live) ReadFileNoFollow(path string) ([]byte, error) { return l.read(path, true, MaxFileBytes) }

func (l *Live) ReadFileMax(path string, max int64) ([]byte, error) { return l.read(path, false, max) }

func (l *Live) ReadFileIfSame(path string, want FileStat) ([]byte, error) {
	return l.readFile(path, true, MaxFileBytes, want.ID)
}

func (l *Live) read(path string, noFollow bool, max int64) ([]byte, error) {
	return l.readFile(path, noFollow, max, "")
}

// readFile reads path; with id set, only if the opened file has that id.
func (l *Live) readFile(path string, noFollow bool, max int64, id string) ([]byte, error) {
	f, err := openRead(l.path(path), noFollow)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if id != "" && openedFileID(f, st) != id {
		return nil, &fs.PathError{Op: "read", Path: path, Err: ErrChanged}
	} else if !st.Mode().IsRegular() {
		why := "not a regular file"
		if st.IsDir() {
			why = "is a directory" // as read(2) says
		}
		return nil, &fs.PathError{Op: "read", Path: path, Err: notRegular(why)}
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(b)) > max
	if truncated {
		b = b[:max]
	}
	// Contents go to parsers raw: masking here corrupted facts (sudo's
	// NOPASSWD:ALL, sshd's sk-ssh-ed25519-cert-v01@openssh.com, and with it
	// the config hash). What leaves as text is masked where it leaves:
	// command lines and cron/systemd commands in facts, streamed log lines,
	// fixtures (Masker). Whole files are never stored in facts.
	if truncated {
		return b, ErrTruncated
	}
	return b, nil
}

func (l *Live) Stat(path string) (FileStat, error) {
	st, err := os.Stat(l.path(path))
	if err != nil {
		return FileStat{}, err
	}
	return FileStat{Mode: st.Mode(), Size: st.Size(), ModTime: st.ModTime(), UID: fileUID(st), ID: pathFileID(l.path(path), st)}, nil
}

func (l *Live) ReadDir(path string) ([]string, error) {
	f, err := os.Open(l.path(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

func (l *Live) Readlink(path string) (string, error) { return os.Readlink(l.path(path)) }

func (l *Live) Run(ctx context.Context, argv []string) (CmdResult, error) {
	return l.Runner.Run(ctx, argv)
}

// Classify maps a Source error to the Reason a fact should carry.
func Classify(err error) Reason {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermission
	case errors.Is(err, fs.ErrNotExist):
		return ReasonNotInstalled
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, ErrTruncated):
		return ReasonTruncated
	case errors.Is(err, ErrNotRecorded):
		return ReasonNotRecorded
	case errors.Is(err, ErrSymlink):
		return ReasonSymlink
	case errors.Is(err, ErrNotRegular):
		return ReasonNotRegular
	}
	return ReasonCommandFailed
}

// unknownFrom is the observation for a failed read of what.
func unknownFrom[T any](what string, err error) Obs[T] {
	return Unknown[T](Classify(err), fmt.Sprintf("%s: %v", what, err))
}
