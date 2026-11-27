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
