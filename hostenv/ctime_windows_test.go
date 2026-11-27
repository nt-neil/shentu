package hostenv

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// PR-2c: on Windows ctime, nlink and the Unix owner do not apply: said,
// never 0.
func TestStatCtimeNlinkWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := NewLive(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, stat := range map[string]func(string) (FileStat, error){"Stat": live.Stat, "Lstat": live.Lstat} {
		st, err := stat(p)
		if err != nil || st.CTime != nil || st.NLink != nil || st.UID != -1 {
			t.Errorf("%s: %+v %v", name, st, err)
		}
		for _, f := range []string{"uid", "gid", "ctime", "nlink"} {
			if !slices.Contains(st.NotApplicable, f) {
				t.Errorf("%s: %s not said not to apply: %v", name, f, st.NotApplicable)
			}
		}
	}
}
