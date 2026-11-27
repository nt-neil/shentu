//go:build windows

package osutil

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// OpenNoFollow on Windows checks and returns one handle: a file swapped for
// a link right before the open is refused (before: a Lstat, an open and
// os.SameFile, which read the swapped-in file's ID; the open went through
// the link). The flags the callers pass still work.
func TestOpenNoFollowWindows(t *testing.T) {
	d := t.TempDir()
	p, target := filepath.Join(d, "dispatch.log"), filepath.Join(d, "elsewhere")
	for f, c := range map[string]string{p: "kept\n", target: "not to be read or written\n"} {
		if err := os.WriteFile(f, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(f *os.File) string { b, _ := io.ReadAll(f); f.Close(); return string(b) }
	f, err := OpenNoFollow(p, os.O_RDONLY, 0, true)
	if err != nil || read(f) != "kept\n" {
		t.Fatalf("a plain file: %v", err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err) // the runners may make links (hostenv's TestFileSecurityDanglingLink needs it too)
	}
	for _, flag := range []int{os.O_RDONLY, os.O_RDWR | os.O_CREATE, os.O_RDWR | os.O_APPEND | os.O_CREATE,
		os.O_WRONLY | os.O_CREATE | os.O_TRUNC, os.O_RDWR | os.O_TRUNC, os.O_WRONLY | os.O_APPEND | os.O_CREATE | os.O_TRUNC} {
		if f, err := OpenNoFollow(link, flag, 0o600, true); err == nil {
			f.Close()
			t.Errorf("flag %#x: opened through a link", flag)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "not to be read or written\n" {
		t.Errorf("the link's target changed: %q", b)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link itself was replaced: %v %v", st, err)
	}

	// Created, read-write and appended as os.OpenFile does.
	n := filepath.Join(d, "new.lock")
	if f, err := OpenNoFollow(n, os.O_RDWR|os.O_CREATE, 0o600, false); err != nil {
		t.Fatalf("create: %v", err)
	} else if _, err := f.WriteString("a"); err != nil {
		t.Errorf("write: %v", err)
	} else {
		f.Close()
	}
	if f, err := OpenNoFollow(n, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600, true); err != nil {
		t.Fatalf("append: %v", err)
	} else {
		f.WriteString("b")
		f.Close()
	}
	if b, _ := os.ReadFile(n); string(b) != "ab" {
		t.Errorf("after create and append: %q", b)
	}
	// O_TRUNC truncates once the file is known not to be a link, with append too.
	if f, err := OpenNoFollow(n, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600, true); err != nil {
		t.Fatalf("truncate: %v", err)
	} else {
		f.WriteString("c")
		f.Close()
	}
	if f, err := OpenNoFollow(n, os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0o600, true); err != nil {
		t.Fatalf("append and truncate: %v", err)
	} else {
		f.WriteString("d")
		f.WriteString("e")
		f.Close()
	}
	if b, _ := os.ReadFile(n); string(b) != "de" {
		t.Errorf("after truncating: %q, want \"de\"", b)
	}
	if f, err := OpenNoFollow(n, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600, true); err == nil {
		f.Close()
		t.Error("O_EXCL opened an existing file")
	}

	// The swap: the caller's file is replaced by a link right before the open.
	old := beforeOpen
	t.Cleanup(func() { beforeOpen = old })
	beforeOpen = func(path string) {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	if f, err := OpenNoFollow(p, os.O_RDONLY, 0, true); err == nil {
		t.Errorf("a file swapped for a link: read %q", read(f))
	}
}
