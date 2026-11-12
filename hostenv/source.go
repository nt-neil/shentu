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

// ErrNotRecorded is returned by Replay for a request the fixture lacks.
var ErrNotRecorded = errors.New("hostenv: not in fixture")

// Live reads the machine it runs on.
type Live struct {
	Runner *Runner
	now    func() time.Time
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

func (l *Live) ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	b = []byte(MaskSecrets(string(b)))
	if len(b) > MaxFileBytes {
		return b[:MaxFileBytes], ErrTruncated
	}
	return b, nil
}

func (l *Live) ReadDir(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

func (l *Live) Readlink(path string) (string, error) { return os.Readlink(path) }

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
	}
	return ReasonCommandFailed
}

// unknownFrom is the observation for a failed read of what.
func unknownFrom[T any](what string, err error) Obs[T] {
	return Unknown[T](Classify(err), fmt.Sprintf("%s: %v", what, err))
}
