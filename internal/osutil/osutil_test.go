package osutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLockExcludes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _ := os.OpenFile(p, os.O_RDWR, 0o600)
	defer b.Close()
	if err := TryLock(a); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(b); !errors.Is(err, ErrWouldBlock) {
		t.Errorf("second lock: %v, want ErrWouldBlock", err)
	}
	if err := Unlock(a); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(b); err != nil {
		t.Errorf("after unlock: %v", err)
	}
	Unlock(b)
}

func TestOpenNoFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t")
	os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(dir, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if f, err := OpenNoFollow(link, os.O_RDONLY, 0, true); err == nil {
		f.Close()
		t.Error("opened through a symlink")
	}
	f, err := OpenNoFollow(target, os.O_RDONLY, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
