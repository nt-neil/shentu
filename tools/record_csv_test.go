package tools

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// S-272-5: RECORD is read as CSV: a quoted path (a comma or a quote in a
// file's name) is the file's path, quotes removed; a line with no sha256
// is not verified; a line cut at the size cap ends the rows before it.
func TestRecordRows(t *testing.T) {
	rows := recordRows([]byte("plain.py,sha256=AAA,5\n\"pkg/a,b.py\",sha256=BBB,10\n\"q\"\"uote.py\",sha256=CCC,1\nRECORD,,\nother.py,md5=DDD,3\n\"cut-off"))
	want := []recordRow{{"plain.py", "AAA"}, {"pkg/a,b.py", "BBB"}, {`q"uote.py`, "CCC"}, {"RECORD", ""}, {"other.py", ""}}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, rows[i], want[i])
		}
	}
}

// S-285-1: a line it cannot parse (a bare quote) is skipped: the lines
// after it still verify, and a wrong hash still does not.
func TestRecordRowsSkipsBadLine(t *testing.T) {
	rows := recordRows([]byte("first.py,sha256=AAA,1\nbad\"quote.py,sha256=BBB,2\nafter.py,sha256=CCC,3\n"))
	if len(rows) != 2 || rows[0] != (recordRow{"first.py", "AAA"}) || rows[1] != (recordRow{"after.py", "CCC"}) {
		t.Fatalf("rows %+v", rows)
	}
	content := "print(1)\n"
	sum := sha256.Sum256([]byte(content))
	h := base64.RawURLEncoding.EncodeToString(sum[:])
	src := dirHost{scriptHost{memHost: memHost{
		"/sp/pkg-1.0.dist-info/RECORD": "x\"y.py,sha256=ZZZ,1\npkg/ok.py,sha256=" + h + ",9\npkg/bad.py,sha256=" + h + "x,9\n",
		"/sp/pkg/ok.py":                content,
		"/sp/pkg/bad.py":               content,
	}}}
	if _, ok := recordHas(src, "/sp", "pkg-*.dist-info", "pkg/ok.py"); !ok {
		t.Error("the line after a bad one not verified")
	}
	if _, ok := recordHas(src, "/sp", "pkg-*.dist-info", "pkg/bad.py"); ok {
		t.Error("a wrong hash verified")
	}
}

// The file a quoted RECORD path names is matched and its hash verified.
func TestRecordHasQuotedPath(t *testing.T) {
	content := "print(1)\n"
	sum := sha256.Sum256([]byte(content))
	h := base64.RawURLEncoding.EncodeToString(sum[:])
	src := dirHost{scriptHost{memHost: memHost{
		"/sp/pkg-1.0.dist-info/RECORD": "\"pkg/a,b.py\",sha256=" + h + ",9\n",
		"/sp/pkg/a,b.py":               content,
	}}}
	if rec, ok := recordHas(src, "/sp", "pkg-*.dist-info", "pkg/a,b.py"); !ok || rec != "/sp/pkg-1.0.dist-info/RECORD" {
		t.Errorf("recordHas: %q %v", rec, ok)
	}
}

// t12: the site-packages search walks with LstatNoID: it needs folders and
// names only, no file opened for an ID.
func TestFindSitePackagesWalksWithoutIDs(t *testing.T) {
	var lstat, noID int
	withHost(t, countNoID{statHost{files: map[string]string{"/srv/v/lib/python3.12/site-packages/x/__init__.py": ""}}, &lstat, &noID})
	dirs, _ := findSitePackages([]string{"/srv/v"}, false)
	if len(dirs) != 1 || noID == 0 || lstat != 0 {
		t.Errorf("dirs %q, LstatNoID %d, Lstat %d: want every entry by LstatNoID", dirs, noID, lstat)
	}
}
