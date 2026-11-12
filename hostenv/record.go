package hostenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// FixtureFormat names the on-disk layout written by Recorder.Save:
//
//	<dir>/manifest.json   info + one entry per request, sorted
//	<dir>/blobs/<sha16>   file contents and command stdout, by content hash
const FixtureFormat = "hostenv-fixture/1"

type fixture struct {
	Format  string     `json:"format"`
	Info    SourceInfo `json:"info"`
	Entries []*entry   `json:"entries"`
}

type entry struct {
	Op        string    `json:"op"` // file, dir, link, stat, cmd
	Path      string    `json:"path,omitempty"`
	Argv      []string  `json:"argv,omitempty"`
	Err       string    `json:"err,omitempty"` // not_exist, permission, truncated, timeout, not_allowed, other:<text>
	Blob      string    `json:"blob,omitempty"`
	Names     []string  `json:"names,omitempty"`
	Target    string    `json:"target,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Stat      *FileStat `json:"stat,omitempty"`

	data []byte // blob contents while in memory
}

func (e *entry) key() string {
	if e.Op == "cmd" {
		return "cmd\x00" + argvKey(e.Argv)
	}
	return e.Op + "\x00" + e.Path
}

func errCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrNotExist):
		return "not_exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	case errors.Is(err, ErrTruncated):
		return "truncated"
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrNotAllowed):
		return "not_allowed"
	case errors.Is(err, ErrSymlink):
		return "symlink"
	case errors.Is(err, ErrNotRegular):
		return "not_regular"
	case errors.Is(err, ErrNoStat):
		return "no_stat"
	}
	return "other:" + MaskSecrets(err.Error())
}

func codeErr(code, path string) error {
	switch {
	case code == "":
		return nil
	case code == "not_exist":
		return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	case code == "permission":
		return &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	case code == "truncated":
		return ErrTruncated
	case code == "timeout":
		return ErrTimeout
	case code == "not_allowed":
		return ErrNotAllowed
	case code == "symlink":
		return ErrSymlink
	case code == "not_regular":
		return ErrNotRegular
	case code == "no_stat":
		return ErrNoStat
	}
	return errors.New(strings.TrimPrefix(code, "other:"))
}

// Recorder passes every request through to Inner and remembers the answer.
type Recorder struct {
	Inner Source
	mu    sync.Mutex
	got   map[string]*entry
}

func NewRecorder(inner Source) *Recorder { return &Recorder{Inner: inner, got: map[string]*entry{}} }

func (r *Recorder) put(e *entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got[e.key()] = e
}

func (r *Recorder) Info() SourceInfo { return r.Inner.Info() }

func (r *Recorder) ReadFile(path string) ([]byte, error) {
	b, err := r.Inner.ReadFile(path)
	r.put(&entry{Op: "file", Path: path, Err: errCode(err), data: b})
	return b, err
}

func (r *Recorder) Stat(path string) (FileStat, error) {
	st, err := Stat(r.Inner, path)
	e := &entry{Op: "stat", Path: path, Err: errCode(err)}
	if err == nil {
		e.Stat = &st
	}
	r.put(e)
	return st, err
}

// ReadFileMax records under the same key as ReadFile.
func (r *Recorder) ReadFileMax(path string, max int64) ([]byte, error) {
	b, err := ReadFileMax(r.Inner, path, max)
	r.put(&entry{Op: "file", Path: path, Err: errCode(err), data: b})
	return b, err
}

// ReadFileNoFollow records under the same key as ReadFile, so a replay of
// the fixture answers both.
func (r *Recorder) ReadFileNoFollow(path string) ([]byte, error) {
	b, err := ReadFileNoFollow(r.Inner, path)
	r.put(&entry{Op: "file", Path: path, Err: errCode(err), data: b})
	return b, err
}

func (r *Recorder) ReadDir(path string) ([]string, error) {
	n, err := r.Inner.ReadDir(path)
	r.put(&entry{Op: "dir", Path: path, Err: errCode(err), Names: n})
	return n, err
}

func (r *Recorder) Readlink(path string) (string, error) {
	t, err := r.Inner.Readlink(path)
	r.put(&entry{Op: "link", Path: path, Err: errCode(err), Target: t})
	return t, err
}

func (r *Recorder) Run(ctx context.Context, argv []string) (CmdResult, error) {
	res, err := r.Inner.Run(ctx, argv)
	r.put(&entry{Op: "cmd", Argv: append([]string(nil), argv...), Err: errCode(err), data: res.Stdout,
		ExitCode: res.ExitCode, Stderr: res.Stderr, Truncated: res.Truncated})
	return res, err
}

// Save writes the recording after passing it through m (nil: secrets only,
// which every Source already did). It creates dir itself (0700, files 0600)
// and fails if dir already exists, so it never writes into a directory
// someone else prepared.
func (r *Recorder) Save(dir string, m *Masker) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("hostenv: fixture dir: %w", err)
	}
	r.mu.Lock()
	entries := make([]*entry, 0, len(r.got))
	for _, e := range r.got {
		entries = append(entries, e)
	}
	r.mu.Unlock()
	info := r.Inner.Info()
	if m != nil {
		entries = m.apply(entries)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key() < entries[j].key() })
	if err := os.Mkdir(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return err
	}
	written := map[string]bool{}
	for _, e := range entries {
		if e.data == nil {
			continue
		}
		sum := sha256.Sum256(e.data)
		e.Blob = "blobs/" + hex.EncodeToString(sum[:8])
		if written[e.Blob] {
			continue
		}
		written[e.Blob] = true
		if err := writeNew(filepath.Join(dir, filepath.FromSlash(e.Blob)), e.data); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(fixture{Format: FixtureFormat, Info: info, Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "manifest.json"), append(b, '\n'))
}

// writeNew creates a file that must not exist yet, readable only by us.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Replay answers from a fixture written by Recorder.Save. Anything the
// fixture does not hold fails with ErrNotRecorded, so a collector change that
// asks for new data shows up as "unknown/not_recorded", never as "absent".
type Replay struct {
	info SourceInfo
	byK  map[string]*entry
}

func LoadReplay(dir string) (*Replay, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var fx fixture
	if err := json.Unmarshal(b, &fx); err != nil {
		return nil, err
	}
	if fx.Format != FixtureFormat {
		return nil, fmt.Errorf("hostenv: fixture format %q, want %q", fx.Format, FixtureFormat)
	}
	rp := &Replay{info: fx.Info, byK: map[string]*entry{}}
	for _, e := range fx.Entries {
		if e.Blob != "" {
			if strings.Contains(e.Blob, "..") {
				return nil, fmt.Errorf("hostenv: bad blob path %q", e.Blob)
			}
			if e.data, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(e.Blob))); err != nil {
				return nil, err
			}
		}
		rp.byK[e.key()] = e
	}
	return rp, nil
}

func (rp *Replay) Info() SourceInfo { return rp.info }

func (rp *Replay) find(op, path string, argv []string) (*entry, error) {
	e := rp.byK[(&entry{Op: op, Path: path, Argv: argv}).key()]
	if e == nil {
		return nil, fmt.Errorf("%w: %s %s%s", ErrNotRecorded, op, path, strings.Join(argv, " "))
	}
	return e, nil
}

func (rp *Replay) ReadFile(path string) ([]byte, error) {
	e, err := rp.find("file", path, nil)
	if err != nil {
		return nil, err
	}
	return e.data, codeErr(e.Err, path)
}

func (rp *Replay) Stat(path string) (FileStat, error) {
	e, err := rp.find("stat", path, nil)
	if err != nil {
		return FileStat{}, err
	}
	if e.Stat == nil {
		return FileStat{}, codeErr(e.Err, path)
	}
	return *e.Stat, codeErr(e.Err, path)
}

func (rp *Replay) ReadDir(path string) ([]string, error) {
	e, err := rp.find("dir", path, nil)
	if err != nil {
		return nil, err
	}
	return e.Names, codeErr(e.Err, path)
}

func (rp *Replay) Readlink(path string) (string, error) {
	e, err := rp.find("link", path, nil)
	if err != nil {
		return "", err
	}
	return e.Target, codeErr(e.Err, path)
}

func (rp *Replay) Run(_ context.Context, argv []string) (CmdResult, error) {
	e, err := rp.find("cmd", "", argv)
	if err != nil {
		return CmdResult{}, err
	}
	return CmdResult{Stdout: e.data, Stderr: e.Stderr, ExitCode: e.ExitCode, Truncated: e.Truncated}, codeErr(e.Err, argv[0])
}
