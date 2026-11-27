//go:build linux || darwin

package hostenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PR-2c: Stat, Lstat and an opened log give the status-change time and
// the hard links; a recording keeps them; an older fixture's are nil (not
// known), never 0.
func TestStatCtimeNlink(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(d, "b")); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil { // mtime faked back; ctime moves on
		t.Fatal(err)
	}
	live, err := NewLive(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := live.Stat(p)
	if err != nil || st.CTime == nil || st.NLink == nil || *st.NLink != 2 || !st.CTime.After(st.ModTime) || st.NotApplicable != nil {
		t.Fatalf("Stat: %+v %v", st, err)
	}
	if l, err := live.Lstat(p); err != nil || l.CTime == nil || l.NLink == nil || *l.NLink != 2 {
		t.Errorf("Lstat: %+v %v", l, err)
	}
	if lf, err := OpenLog(live, p); err != nil {
		t.Errorf("OpenLog: %v", err)
	} else {
		if s := lf.Stat(); s.NLink == nil || *s.NLink != 2 || s.CTime == nil {
			t.Errorf("opened log: %+v", s)
		}
		lf.Close()
	}
	r := NewRecorder(live)
	if _, err := r.Stat(p); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.got {
		if e.Stat != nil && (e.Stat.CTime == nil || e.Stat.NLink == nil || *e.Stat.NLink != 2) {
			t.Errorf("recorded: %+v", e.Stat)
		}
	}
	var before FileStat
	if err := json.Unmarshal([]byte(`{"mode":420,"size":1,"mtime":"2026-11-01T00:00:00Z","uid":0}`), &before); err != nil || before.CTime != nil || before.NLink != nil {
		t.Errorf("an older fixture's stat: %+v %v", before, err)
	}
}
