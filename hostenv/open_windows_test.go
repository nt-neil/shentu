//go:build windows

package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// N-257-1: a file swapped between the Lstat and the open of a no-follow
// read is refused (before, Windows only Lstat'ed and opened: what was
// swapped in was read). A plain file is read as before.
func TestOpenReadNoFollowSwapped(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "METADATA")
	if err := os.WriteFile(p, []byte("Name: example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, _ := NewLive(nil)
	if b, err := ReadFileNoFollowMax(l, p, 100); err != nil || string(b) != "Name: example\n" {
		t.Fatalf("a plain file: %q %v", b, err)
	}
	old := beforeOpen
	t.Cleanup(func() { beforeOpen = old })
	beforeOpen = func(path string) {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("Name: swapped\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := ReadFileNoFollowMax(l, p, 100); !errors.Is(err, ErrChanged) {
		t.Errorf("a swapped file: %q %v, want ErrChanged", b, err)
	}
}
