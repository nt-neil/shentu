//go:build !windows

package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLiveRefusesLinksAndFIFOs(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(dir, "authorized_keys")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	l, _ := NewLive(nil)
	if _, err := l.ReadFileNoFollow(link); !errors.Is(err, ErrSymlink) || Classify(err) != ReasonSymlink {
		t.Errorf("no-follow read of a link: %v", err)
	}
	if b, err := l.ReadFile(link); err != nil || string(b) != "x" {
		t.Errorf("plain read should follow: %q %v", b, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := l.ReadFile(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("fifo: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
