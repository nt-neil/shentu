//go:build windows

package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Round 3 (S4): Stat gives Windows files an ID (volume serial and file
// index), so ReadFileIfSame refuses a file swapped in after the stat.
func TestReadFileIfSameWindows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &Live{}
	st, err := l.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d+:\d+$`).MatchString(st.ID) {
		t.Fatalf("Stat gave no file ID: %q", st.ID)
	}
	if b, err := l.ReadFileIfSame(p, st); err != nil || string(b) != "one" {
		t.Fatalf("same file: %q %v", b, err)
	}
	other := filepath.Join(dir, "b.conf")
	if err := os.WriteFile(other, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if b, err := l.ReadFileIfSame(p, st); !errors.Is(err, ErrChanged) {
		t.Errorf("a swapped file must be refused: %q %v", b, err)
	}
	if st2, _ := l.Stat(p); st2.ID == st.ID || st2.ID == "" {
		t.Errorf("the new file has its own ID: %q, was %q", st2.ID, st.ID)
	}
}

// Round 3 re-review: with no file ID to compare, ReadFileIfSame refuses
// and says why, never reads unchecked.
func TestReadFileIfSameNoID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.conf")
	if err := os.WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Live{}).ReadFileIfSame(p, FileStat{}); !errors.Is(err, ErrChanged) {
		t.Errorf("no ID: %v", err)
	}
}
