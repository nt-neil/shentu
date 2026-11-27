//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// appendBad opens its .bad file with OpenNoFollow(O_RDWR|O_APPEND|O_CREATE)
// and Syncs it: on Windows that handle has the append access Go's
// syscall.Open gives (S-267-3), and the lines are added once each.
func TestAppendBadWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dispatch.jsonl.bad")
	if n, err := appendBad(p, []byte("a\nb\n")); err != nil || n != 2 {
		t.Fatalf("first: %d %v", n, err)
	}
	if n, err := appendBad(p, []byte("b\nc\n")); err != nil || n != 1 {
		t.Fatalf("again: %d %v", n, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "a\nb\nc\n" {
		t.Errorf("file %q", b)
	}
}
