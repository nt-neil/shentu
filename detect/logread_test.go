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
	rootUID = os.Getuid()
	trust := func(p string) hostenv.TrustResult { // .1 files are trusted here, judged by their stat now
		st, _ := hostenv.Stat(src, p)
		return hostenv.TrustResult{Verified: strings.HasSuffix(p, ".1"), File: st}
	}
	c, r, err := ReadLog(src, "/logs/a.log", cur, b, ReadOpts{Trust: trust}, func(l Line) { lines = append(lines, string(l.Text)) })
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
	cb, _, err := ReadLog(bsrc, "/logs/b.log", nil, NewBudget(DefaultBudgetBytes, time.Minute), ReadOpts{}, func(l Line) { got = append(got, string(l.Text)) })
	if err != nil || cb.HeadLen != 0 {
		t.Fatalf("empty log: %v, %+v", err, cb)
	}
	os.Remove(filepath.Join(d, "b.log"))
	write(t, filepath.Join(d, "b.log.old"), "planted\n", os.O_CREATE)
	write(t, filepath.Join(d, "b.log"), "real\n", os.O_CREATE)
	_, _, err = ReadLog(bsrc, "/logs/b.log", &cb, NewBudget(DefaultBudgetBytes, time.Minute), ReadOpts{}, func(l Line) { got = append(got, string(l.Text)) })
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

// N-1: a log judged verified is read as verified only while the file
// opened is the one judged, still root's alone.
func TestReadLogVerifiedFileChecked(t *testing.T) {
	rootUID = os.Getuid()
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	st, _ := hostenv.Stat(src, "/logs/a.log")
	want := hostenv.LogSource{Path: "/logs/a.log", Verified: true, FileID: st.ID}
	read := func(w hostenv.LogSource) (ReadResult, []bool) {
		var v []bool
		_, r, err := ReadLog(src, "/logs/a.log", nil, NewBudget(DefaultBudgetBytes, time.Minute), ReadOpts{Want: &w}, func(l Line) { v = append(v, l.Verified) })
		if err != nil {
			t.Fatal(err)
		}
		return r, v
	}
	if r, v := read(want); !r.Verified || len(v) != 1 || !v[0] {
		t.Errorf("the file judged: %+v %v", r, v)
	}
	os.Rename(a, a+".old") // swapped after the judgment
	write(t, a, "forged\n", os.O_CREATE)
	if r, v := read(want); r.Verified || len(v) != 1 || v[0] {
		t.Errorf("a swapped file: %+v %v", r, v)
	}
	os.Chmod(a, 0o666)
	st, _ = hostenv.Stat(src, "/logs/a.log")
	want.FileID = st.ID
	if r, _ := read(want); r.Verified || r.Reason != hostenv.ReasonUntrusted {
		t.Errorf("writable by others since: %+v", r)
	}
}

// N-6: a first run whose budget is gone stops at the end of a whole line,
// and the next run reads the first new line.
func TestReadLogFirstRunNoBudget(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "old\n", os.O_CREATE)
	c, _, lines := read(t, src, nil, NewBudget(0, time.Minute))
	eq(t, "no budget", lines, nil)
	if c.MidLine || c.Offset != 4 {
		t.Fatalf("cursor %+v: want at the end, not mid-line", c)
	}
	write(t, a, "new\n", os.O_APPEND)
	_, _, lines = read(t, src, &c, nil)
	eq(t, "next run", lines, []string{"new"})
}

// N-7: a rotated file not read to its end (out of budget) is said lost.
func TestReadLogRotatedBudget(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a, "two\nthree\nfour\n", os.O_APPEND)
	os.Rename(a, a+".1")
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, NewBudget(4, time.Minute))
	eq(t, "rotated, out of budget", lines, []string{"two"})
	if !strings.Contains(strings.Join(r.Partial, ","), ReadRotatedGap) {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// N-8: a corrupt .gz is an error, not an end.
func TestReadLogCorruptGzip(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	var buf strings.Builder
	z := gzip.NewWriter(&buf)
	z.Write([]byte("one\n" + strings.Repeat("line\n", 5000)))
	z.Close()
	gz := []byte(buf.String())
	os.WriteFile(a+".1.gz", gz[:len(gz)/2], 0o640) // cut in half
	os.Remove(a)
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	p := strings.Join(r.Partial, ",")
	if !strings.Contains(p, ReadIOError) || !strings.Contains(p, ReadRotatedGap) || len(lines) == 0 || lines[len(lines)-1] != "new" {
		t.Errorf("partial %v, %d lines (last %q)", r.Partial, len(lines), lines[len(lines)-1])
	}
}

// N-11: with dozens of dated rotations the newest is looked at, whatever
// its name sorts as.
func TestReadLogManyRotations(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "one\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 40; i++ {
		n := filepath.Join(d, "a.log-2025"+strings.Repeat("0", 1)+string(rune('a'+i%26))+string(rune('a'+i/26)))
		write(t, n, "old\n", os.O_CREATE)
		os.Chtimes(n, old, old)
	}
	write(t, a, "two\n", os.O_APPEND)
	os.Rename(a, a+"-20991231") // dateext: the newest sorts last by name, past the 32nd of the 40 above
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "many rotations", lines, []string{"two", "new"})
	if len(r.Partial) != 0 {
		t.Errorf("partial %v", r.Partial)
	}
}

// A non-gzip rotated file shorter than the cursor is not the one read: gap.
func TestReadLogRotatedShorter(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, strings.Repeat("x", 300)+"\n", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	write(t, a+".1", strings.Repeat("x", 300)[:280], os.O_CREATE) // same head, shorter than the cursor
	os.Remove(a)
	write(t, a, "new\n", os.O_CREATE)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "shorter rotated", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// Empty when last read, copied and truncated since: the lost lines cannot
// be told apart, and the read says so.
func TestReadLogEmptyThenCopyTruncate(t *testing.T) {
	src, d := logDir(t)
	a := filepath.Join(d, "a.log")
	write(t, a, "", os.O_CREATE)
	c, _, _ := read(t, src, nil, nil)
	time.Sleep(10 * time.Millisecond)
	write(t, a+".1", "lost\n", os.O_CREATE) // what the copy took
	write(t, a, "", os.O_TRUNC)
	write(t, a, "new\n", os.O_APPEND)
	_, r, lines := read(t, src, &c, nil)
	eq(t, "after copytruncate", lines, []string{"new"})
	if strings.Join(r.Partial, ",") != ReadRotatedGap {
		t.Errorf("partial %v, want rotated_gap", r.Partial)
	}
}

// N-9 and the cursor file: invalid entries are dropped and said, a file
// writable by others or a link is not believed, and saving does not follow
// a link left at a temporary name.
func TestCursorsInvalidAndUnsafe(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, CursorFileName)
	os.WriteFile(p, []byte(`{"version":1,"sources":{"/a":{"offset":5,"head_len":-1},"/b":{"offset":-3},"/c":{"offset":1,"head_len":2,"head":"zz"},"/ok":{"offset":7}}}`), 0o600)
	c, err := LoadCursors(d)
	if err != nil || len(c.Sources) != 1 || c.Sources["/ok"].Offset != 7 || len(c.Dropped) != 3 {
		t.Fatalf("%v, %+v", err, c)
	}
	if _, _, rerr := ReadLog(&hostenv.Live{}, "/nonexistent", nil, NewBudget(1, time.Minute), ReadOpts{}, func(Line) {}); rerr == nil {
		t.Error("reading a missing log did not fail")
	}
	os.Chmod(p, 0o666)
	if _, err := LoadCursors(d); err == nil {
		t.Error("a cursor file others may write was believed")
	}
	os.Remove(p)
	other := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(other, []byte(`{"version":1,"sources":{}}`), 0o600)
	os.Symlink(other, p)
	if _, err := LoadCursors(d); err == nil {
		t.Error("a linked cursor file was believed")
	}
	os.Remove(p)
	os.Symlink(other, filepath.Join(d, CursorFileName+".tmp")) // the old fixed temporary name
	if err := (&Cursors{Sources: map[string]Cursor{"/x": {Offset: 1}}}).Save(d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); string(b) != `{"version":1,"sources":{}}` {
		t.Errorf("Save wrote through a link: %s", b)
	}
	if c, err := LoadCursors(d); err != nil || c.Sources["/x"].Offset != 1 {
		t.Errorf("saved: %v %+v", err, c)
	}
}
