package hostenv

import (
	"os"
	"path/filepath"
	"testing"
)

// Round 3 re-review: a fixture keeps no file ID (device and inode, or a
// Windows volume serial and file index); the caller still gets it.
func TestRecorderStatDropsID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := NewLive(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRecorder(live)
	st, err := r.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID == "" {
		t.Fatal("the caller gets the file ID")
	}
	for _, e := range r.got {
		if e.Stat != nil && e.Stat.ID != "" {
			t.Errorf("recorded file ID %q", e.Stat.ID)
		}
	}
}
