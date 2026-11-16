package detect

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// logDir is a Live source whose /logs is a temporary directory: real
// files, real inodes, real renames.
func logDir(t *testing.T) (*hostenv.Live, string) {
	t.Helper()
	d := t.TempDir()
	return &hostenv.Live{Remap: map[string]string{"/logs": d}}, d
}

func write(t *testing.T, p, s string, flag int) {
	t.Helper()
	f, err := os.OpenFile(p, flag|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func read(t *testing.T, src hostenv.Source, cur *Cursor, b *Budget) (Cursor, ReadResult, []string) {
	t.Helper()
	if b == nil {
		b = NewBudget(DefaultBudgetBytes, time.Minute)
	}
	var lines []string
	trust := func(p string) (bool, hostenv.Reason) { return strings.HasSuffix(p, ".1"), "" }
	c, r, err := ReadLog(src, "/logs/a.log", cur, b, trust, func(_ string, l []byte) { lines = append(lines, string(l)) })
	if err != nil {
		t.Fatal(err)
	}
	return c, r, lines
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s: lines %q, want %q", what, got, want)
	}
}

// A first run reads what is there and says so; a line not ended yet is
// left; the next run reads only what was added.
func TestReadLogContinue(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\ntwo\r\nthr", os.O_CREATE)
	c, r, lines := read(t, src, nil, nil)
	eq(t, "first run", lines, []string{"one", "two"})
	if strings.Join(r.Partial, ",") != ReadFirstRun || c.Offset != 9 || c.ID == "" {
		t.Errorf("first run %+v, cursor %+v", r, c)
	}
	write(t, a, "ee\nfour\n", os.O_APPEND)
	c, r, lines = read(t, src, &c, nil)
	eq(t, "next run", lines, []string{"three", "four"})
	if len(r.Partial) != 0 {
		t.Errorf("next run partial %v", r.Partial)
	}
	_, _, lines = read(t, src, &c, nil)
	eq(t, "nothing new", lines, nil)
}

// logrotate's create: the file read is renamed to .1 (more was written to
// it first) and a new one is made. The rest of .1, then the new file.
func TestReadLogRenamed(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a, "two\n", os.O_APPEND)
	if err := os.Rename(a, a+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, a, "three\n", os.O_CREATE)
	c, r, lines := read(t, src, &c, nil)
	eq(t, "renamed", lines, []string{"two", "three"})
	if len(r.Partial) != 0 || len(r.Rotated) != 1 || r.Rotated[0].Path != "/logs/a.log.1" || !r.Rotated[0].Verified || c.Offset != 6 {
		t.Errorf("result %+v, cursor %+v", r, c)
	}
}

// copytruncate: the file is copied to .1 and truncated in place: the
// same inode, shorter. The rest is in the copy, found by its head.
func TestReadLogCopyTruncate(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a+".1", "one\ntwo\n", os.O_CREATE)
	write(t, a, "", os.O_TRUNC)
	write(t, a, "x\n", os.O_APPEND)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "copytruncate", lines, []string{"two", "x"})
	if len(r.Partial) != 0 || len(r.Rotated) != 1 {
		t.Errorf("result %+v", r)
	}
}

// Rotated and compressed at once (no delaycompress): found in the .gz.
func TestReadLogGzip(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	f, err := os.Create(a + ".1.gz")
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	z.Write([]byte("one\ntwo\nlast without newline"))
	z.Close()
	f.Close()
	os.Remove(a)
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "gzip", lines, []string{"two", "last without newline", "new"})
	if len(r.Rotated) != 1 || r.Rotated[0].Path != "/logs/a.log.1.gz" || r.Rotated[0].Verified {
		t.Errorf("result %+v", r)
	}
}

// The rotated file is gone: what it got after the cursor is lost, and the
// read says so.
func TestReadLogGap(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	os.Remove(a)
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "gap", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// The same file, its start written over: read again, flagged.
func TestReadLogRewritten(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\ntwo\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	f, _ := os.OpenFile(a, os.O_WRONLY, 0)
	f.WriteAt([]byte("ONE"), 0)
	f.Close()
	_, r, lines := read(t, src, &c, nil)
	eq(t, "rewritten", lines, []string{"ONE", "two"})
	if strings.Join(r.Partial, ",") != ReadRewritten {
		t.Errorf("partial %v, want rewritten", r.Partial)
	}
}

// A line past MaxLine is cut and counted; reading goes on.
func TestReadLogLongLine(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, strings.Repeat("x", 20<<10)+"\nshort\n", os.O_CREATE)
	c, r, lines := read(t, src, nil, nil)
	if len(lines) != 2 || len(lines[0]) != MaxLine || lines[1] != "short" || r.LongLines != 1 || c.Offset != 20<<10+7 {
		t.Errorf("%d lines (first %d bytes), result %+v, offset %d", len(lines), len(lines[0]), r, c.Offset)
	}
}

// Out of budget: stops at a whole line, says truncated, and the next run
// goes on from there.
func TestReadLogBudget(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "aaaa\nbbbb\ncccc\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a, "dddd\neeee\n", os.O_APPEND)
	c, r, lines := read(t, src, &c, NewBudget(5, time.Minute))
	eq(t, "budget", lines, []string{"dddd"})
	if strings.Join(r.Partial, ",") != ReadTruncated {
		t.Errorf("partial %v, want truncated", r.Partial)
	}
	_, _, lines = read(t, src, &c, nil)
	eq(t, "after budget", lines, []string{"eeee"})
}

// A first run on a log larger than the budget reads its end, from a whole
// line.
func TestReadLogFirstRunTail(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "aaaa\nbbbb\ncccc\n", os.O_CREATE)
	_, r, lines := read(t, src, nil, NewBudget(7, time.Minute))
	eq(t, "tail", lines, []string{"cccc"})
	if strings.Join(r.Partial, ",") != ReadFirstRun {
		t.Errorf("partial %v", r.Partial)
	}
}

func TestCursorsSaveLoad(t *testing.T) {
	d := t.TempDir()
	c, err := LoadCursors(d)
	if err != nil || len(c.Sources) != 0 {
		t.Fatalf("no file: %v, %+v", err, c)
	}
	now := time.Now().UTC()
	for i := 0; i < MaxCursors+3; i++ {
		c.Sources["/logs/"+string(rune('a'+i%26))+strings.Repeat("x", i/26)] = Cursor{Offset: int64(i), ReadAt: now.Add(time.Duration(i) * time.Second)}
	}
	if err := c.Save(d); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(d, CursorFileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("saved file %v %v", st, err)
	}
	back, err := LoadCursors(d)
	if err != nil || len(back.Sources) != MaxCursors {
		t.Fatalf("%v, %d cursors, want %d", err, len(back.Sources), MaxCursors)
	}
	if _, ok := back.Sources["/logs/a"]; ok { // read first, so dropped first
		t.Error("the least recently read cursor was kept")
	}
	os.WriteFile(filepath.Join(d, CursorFileName), []byte("{"), 0o600)
	if c, err := LoadCursors(d); err == nil || len(c.Sources) != 0 {
		t.Errorf("corrupt file: %v, %d cursors; want an error and none", err, len(c.Sources))
	}
}

// A rotated candidate that is a symlink is not followed (it could point at
// any file), and an empty head matches no candidate.
func TestReadLogRotatedNotFollowed(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, filepath.Join(d, "secret"), "one\nsecret\n", os.O_CREATE)
	os.Rename(a, filepath.Join(d, "moved"))
	if err := os.Symlink(filepath.Join(d, "secret"), a+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "symlinked candidate", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}

	write(t, filepath.Join(d, "b.log"), "", os.O_CREATE)
	var got []string
	bsrc := src
	cb, _, err := ReadLog(bsrc, "/logs/b.log", nil, NewBudget(DefaultBudgetBytes, time.Minute), nil, func(_ string, l []byte) { got = append(got, string(l)) })
	if err != nil || cb.HeadLen != 0 {
		t.Fatalf("empty log: %v, %+v", err, cb)
	}
	os.Remove(filepath.Join(d, "b.log"))
	write(t, filepath.Join(d, "b.log.old"), "planted\n", os.O_CREATE)
	write(t, filepath.Join(d, "b.log"), "real\n", os.O_CREATE)
	_, _, err = ReadLog(bsrc, "/logs/b.log", &cb, NewBudget(DefaultBudgetBytes, time.Minute), nil, func(_ string, l []byte) { got = append(got, string(l)) })
	if err != nil || strings.Join(got, "|") != "real" {
		t.Errorf("after an empty head: %v, lines %q; want only real", err, got)
	}
}

// A long line not ended yet: its start is given once, and the next run
// skips the rest instead of reading it again.
func TestReadLogLongLineUnended(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, strings.Repeat("x", 20<<10), os.O_CREATE)
	c, r, lines := read(t, src, nil, nil)
	if len(lines) != 1 || len(lines[0]) != MaxLine || !c.MidLine || c.Offset != 20<<10 || r.LongLines != 1 {
		t.Fatalf("%d lines, cursor %+v, result %+v", len(lines), c, r)
	}
	write(t, a, strings.Repeat("y", 100)+"\nnext\n", os.O_APPEND)
	c, _, lines = read(t, src, &c, nil)
	eq(t, "after the long line", lines, []string{"next"})
	if c.MidLine {
		t.Error("still mid-line")
	}
}

// The budget holds inside a long line too: a gigabyte without a newline
// costs no more than the budget, and the next run does not read it again.
func TestReadLogLongLineBudget(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "ok\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a, strings.Repeat("z", 200<<10)+"\nafter\n", os.O_APPEND)
	c, r, _ := read(t, src, &c, NewBudget(40<<10, time.Minute))
	if !c.MidLine || c.Offset >= 3+200<<10 || strings.Join(r.Partial, ",") != ReadTruncated {
		t.Fatalf("cursor %+v, result %+v: want stopped inside the line, truncated", c, r)
	}
	_, _, lines := read(t, src, &c, nil)
	eq(t, "next run", lines, []string{"after"})
}
