package detect

import (
	"bytes"
	"context"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// memSrc is a Source whose files' ids are set by the test: a file made
// after another's removal can be given its inode, as ext4 and tmpfs do,
// whatever the file system the tests run on.
type memSrc struct{ files map[string]*memFile }

type memFile struct {
	data []byte
	id   string
	mod  time.Time
	born time.Time
}

func (m *memSrc) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }
func (m *memSrc) ReadFile(p string) ([]byte, error) {
	if f, ok := m.files[p]; ok {
		return f.data, nil
	}
	return nil, fs.ErrNotExist
}
func (m *memSrc) ReadDir(d string) ([]string, error) {
	var out []string
	for p := range m.files {
		if path.Dir(p) == d {
			out = append(out, path.Base(p))
		}
	}
	if len(out) == 0 {
		return nil, fs.ErrNotExist
	}
	sort.Strings(out)
	return out, nil
}
func (m *memSrc) Readlink(string) (string, error) { return "", fs.ErrNotExist }
func (m *memSrc) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, fs.ErrNotExist
}
func (m *memSrc) Stat(p string) (hostenv.FileStat, error) {
	f, ok := m.files[p]
	if !ok {
		if _, err := m.ReadDir(p); err == nil {
			return hostenv.FileStat{Mode: fs.ModeDir | 0o755}, nil
		}
		return hostenv.FileStat{}, fs.ErrNotExist
	}
	return hostenv.FileStat{Mode: 0o640, Size: int64(len(f.data)), ModTime: f.mod, ID: f.id, Born: f.born}, nil
}
func (m *memSrc) OpenLog(p string) (hostenv.LogFile, error) {
	f, ok := m.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	st, _ := m.Stat(p)
	return &memOpen{Reader: bytes.NewReader(f.data), st: st}, nil
}
func (m *memSrc) OpenLogNoFollow(p string) (hostenv.LogFile, error) { return m.OpenLog(p) }

type memOpen struct {
	*bytes.Reader
	st hostenv.FileStat
}

func (o *memOpen) Close() error           { return nil }
func (o *memOpen) Stat() hostenv.FileStat { return o.st }

func memRead(t *testing.T, src *memSrc, p string, cur *Cursor) (Cursor, ReadResult, []string) {
	t.Helper()
	var lines []string
	c, r, err := ReadLog(src, p, cur, NewBudget(DefaultBudgetBytes, time.Minute), ReadOpts{}, func(l Line) { lines = append(lines, string(l.Text)) })
	if err != nil {
		t.Fatal(err)
	}
	return c, r, lines
}

// A log removed and made again with the old inode: a new file, not the
// old one rewritten, and the old one's rest is a gap.
func TestReadLogInodeReused(t *testing.T) {
	now := time.Now()
	src := &memSrc{files: map[string]*memFile{"/l/a.log": {data: []byte("one\n"), id: "8:7", mod: now}}}
	c, _, _ := memRead(t, src, "/l/a.log", nil)
	src.files["/l/a.log"] = &memFile{data: []byte("new\n"), id: "8:7", mod: now.Add(time.Second)}
	_, r, lines := memRead(t, src, "/l/a.log", &c)
	eq(t, "inode reused", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// A file planted beside the log with the inode the log had: neither an
// empty head nor the ID alone makes it the file read.
func TestReadLogInodeReusedPlanted(t *testing.T) {
	now := time.Now()
	src := &memSrc{files: map[string]*memFile{"/l/b.log": {id: "8:9", mod: now}}}
	c, _, _ := memRead(t, src, "/l/b.log", nil) // empty: no head
	delete(src.files, "/l/b.log")
	src.files["/l/b.log.old"] = &memFile{data: []byte("planted\n"), id: "8:9", mod: now.Add(time.Second)}
	src.files["/l/b.log"] = &memFile{data: []byte("real\n"), id: "8:10", mod: now.Add(time.Second)}
	_, _, lines := memRead(t, src, "/l/b.log", &c)
	eq(t, "empty head, planted file with the old inode", lines, []string{"real"})

	src = &memSrc{files: map[string]*memFile{"/l/a.log": {data: []byte("one\n"), id: "8:7", mod: now}}}
	c, _, _ = memRead(t, src, "/l/a.log", nil)
	delete(src.files, "/l/a.log")
	src.files["/l/a.log.1"] = &memFile{data: []byte("evil\nforged\n"), id: "8:7", mod: now.Add(time.Second)}
	src.files["/l/a.log"] = &memFile{data: []byte("new\n"), id: "8:11", mod: now.Add(time.Second)}
	_, r, lines := memRead(t, src, "/l/a.log", &c)
	eq(t, "the old inode, another head", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// Review 2, N-9: the same inode with another birth time is a new file even
// when it starts the same way; with no birth time, a short head is not
// enough and the read says so; with an empty head the same file only grows.
func TestReadLogBirthTime(t *testing.T) {
	now := time.Now()
	head := strings.Repeat("h", 300) + "\n"
	src := &memSrc{files: map[string]*memFile{"/l/a.log": {data: []byte(head), id: "8:7", mod: now, born: now}}}
	c, _, _ := memRead(t, src, "/l/a.log", nil)
	src.files["/l/a.log"] = &memFile{data: []byte(head + "x\n"), id: "8:7", mod: now.Add(time.Second), born: now.Add(time.Second)}
	_, r, lines := memRead(t, src, "/l/a.log", &c)
	eq(t, "reborn inode, same head", lines, []string{strings.Repeat("h", 300), "x"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}

	src = &memSrc{files: map[string]*memFile{"/l/b.log": {data: []byte("short\n"), id: "8:8", mod: now}}}
	c, _, _ = memRead(t, src, "/l/b.log", nil)
	src.files["/l/b.log"].data = []byte("short\nmore\n")
	_, r, lines = memRead(t, src, "/l/b.log", &c)
	eq(t, "no birth time, short head", lines, []string{"more"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap (a reused inode cannot be ruled out)", r.Partial)
	}

	src = &memSrc{files: map[string]*memFile{"/l/e.log": {id: "8:9", mod: now, born: now}}}
	c, _, _ = memRead(t, src, "/l/e.log", nil)
	src.files["/l/e.log"] = &memFile{data: []byte("x\n"), id: "8:9", mod: now.Add(-time.Hour), born: now}
	_, r, _ = memRead(t, src, "/l/e.log", &c)
	if !strings.Contains(strings.Join(r.Partial, ","), ReadRotatedGap) {
		t.Errorf("empty head, older file under the same id: partial %v", r.Partial)
	}
}
