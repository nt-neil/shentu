package hostenv

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// walkTree makes a small made-up tree at run time: files, nested folders,
// a link to a folder (never followed) and an empty folder.
func walkTree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, f := range []string{"a.php", "b/c.php", "b/d/e.txt", "b/z.php", "skip/x.php", "y/1.txt", "y/2.txt", "y/3.txt"} {
		p := filepath.Join(d, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("<?php // "+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(d, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(d, "b"), filepath.Join(d, "linkdir")); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// visit is one call of a walk: the path, its type and the error said.
func visit(p string, m fs.FileMode, err error) string {
	return p + " " + m.Type().String() + " " + map[bool]string{true: "err", false: "ok"}[err != nil]
}

// Walk through a live Source visits what filepath.WalkDir does, in the
// same order, with SkipDir on a folder and on a file, and SkipAll.
func TestWalkAsWalkDir(t *testing.T) {
	d := walkTree(t)
	l, err := NewLive(nil)
	if err != nil {
		t.Fatal(err)
	}
	cb := func(p string, isDir bool) error {
		switch {
		case filepath.Base(p) == "skip" && isDir:
			return fs.SkipDir // a folder
		case filepath.Base(p) == "1.txt":
			return fs.SkipDir // a file: the rest of y/
		case filepath.Base(p) == "z.php":
			return fs.SkipAll
		}
		return nil
	}
	var want, got []string
	if err := filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
		want = append(want, visit(p, de.Type(), err))
		return cb(p, de.IsDir())
	}); err != nil {
		t.Fatal(err)
	}
	if err := Walk(l, d, func(p string, st FileStat, err error) error {
		got = append(got, visit(p, st.Mode, err))
		return cb(p, st.Mode.IsDir())
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("Walk\n%s\nWalkDir\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(want) < 6 {
		t.Errorf("walk too short: %q", want)
	}
}

// Lstat is recorded and replayed (a link is the link); a fixture made
// before lstat was, or a path it lacks, says not recorded: unread, never
// "not there". The made-up tree is walked the same way from the replay.
func TestLstatRecordReplay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	d := walkTree(t)
	l, _ := NewLive(nil)
	rec := NewRecorder(l)
	var live []string
	walkAll := func(src Source) []string {
		var out []string
		if err := Walk(src, d, func(p string, st FileStat, err error) error {
			out = append(out, visit(p, st.Mode, err))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	live = walkAll(rec)
	dir := filepath.Join(t.TempDir(), "fx")
	if err := rec.Save(dir, &Masker{}); err != nil {
		t.Fatal(err)
	}
	rp, err := LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := walkAll(rp); !slices.Equal(got, live) {
		t.Errorf("replayed walk\n%s\nlive\n%s", strings.Join(got, "\n"), strings.Join(live, "\n"))
	}
	if st, err := Lstat(rp, filepath.Join(d, "linkdir")); err != nil || st.Mode.Type() != fs.ModeSymlink || st.ID != "" {
		t.Errorf("replayed link: %+v %v (a link, no ID kept)", st, err)
	}
	if _, err := Lstat(rp, filepath.Join(d, "never-asked")); !errors.Is(err, ErrNotRecorded) || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a path not recorded: %v, want ErrNotRecorded", err)
	}
	// A fixture recorded before lstat was: every lstat is not recorded.
	old, err := LoadReplay(filepath.Join("testdata", "linux", "debian12-root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lstat(old, "/etc/passwd"); !errors.Is(err, ErrNotRecorded) || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an old fixture's lstat: %v, want ErrNotRecorded", err)
	}
	var said []error
	if err := Walk(old, "/var/www", func(_ string, _ FileStat, err error) error { said = append(said, err); return nil }); err != nil ||
		len(said) != 1 || !errors.Is(said[0], ErrNotRecorded) {
		t.Errorf("an old fixture's walk: %v %v, want one unread root", said, err)
	}
}

// ReadFileIfSameMax reads the file a Lstat saw, up to max; a swapped one is
// ErrChanged, one past max the first max bytes and ErrTruncated; a fixture
// applies the limit to what it holds.
func TestReadFileIfSameMax(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "composer.lock")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, _ := NewLive(nil)
	st, err := Lstat(l, p)
	if err != nil || st.ID == "" && runtime.GOOS != "windows" {
		t.Fatalf("lstat %+v %v: want an ID", st, err)
	}
	if b, err := ReadFileIfSameMax(l, p, st, 10); err != nil || string(b) != "0123456789" {
		t.Errorf("same file: %q %v", b, err)
	}
	if b, err := ReadFileIfSameMax(l, p, st, 4); !errors.Is(err, ErrTruncated) || string(b) != "0123" {
		t.Errorf("past max: %q %v", b, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Rename(p, p+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("swapped"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFileIfSameMax(l, p, st, 10); !errors.Is(err, ErrChanged) {
			t.Errorf("a swapped file: %v, want ErrChanged", err)
		}
	}
	m := memSrc{p: "0123456789"}
	if b, err := ReadFileIfSameMax(m, p, FileStat{}, 4); !errors.Is(err, ErrTruncated) || string(b) != "0123" {
		t.Errorf("a fixture past max: %q %v", b, err)
	}
}

// memSrc is a file-only Source, as a fixture holding contents only.
type memSrc map[string]string

func (memSrc) Info() SourceInfo { return SourceInfo{GOOS: "linux"} }
func (m memSrc) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}
func (memSrc) ReadDir(string) ([]string, error) { return nil, fs.ErrNotExist }
func (memSrc) Readlink(string) (string, error)  { return "", fs.ErrNotExist }
func (memSrc) Run(context.Context, []string) (CmdResult, error) {
	return CmdResult{}, fs.ErrNotExist
}
