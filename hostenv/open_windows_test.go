//go:build windows

package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// N-257-1: a no-follow read on Windows checks and reads one handle: a file
// swapped for a link right before the open is refused (before, a Lstat and
// an open: what was swapped in was read). A plain file is read, a link
// there from the start refused.
func TestOpenReadNoFollowSwapped(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "METADATA")
	secret := filepath.Join(d, "elsewhere")
	for f, c := range map[string]string{p: "Name: example\n", secret: "Name: swapped\n"} {
		if err := os.WriteFile(f, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := NewLive(nil)
	if b, err := ReadFileNoFollowMax(l, p, 100); err != nil || string(b) != "Name: example\n" {
		t.Fatalf("a plain file: %q %v", b, err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if b, err := ReadFileNoFollowMax(l, link, 100); !errors.Is(err, ErrSymlink) {
		t.Errorf("a link: %q %v, want ErrSymlink", b, err)
	}
	old := beforeOpen
	t.Cleanup(func() { beforeOpen = old })
	beforeOpen = func(path string) { // the Lstat a caller made saw a file; now it is a link
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(secret, path); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := ReadFileNoFollowMax(l, p, 100); !errors.Is(err, ErrSymlink) {
		t.Errorf("a file swapped for a link: %q %v, want ErrSymlink", b, err)
	}
}
