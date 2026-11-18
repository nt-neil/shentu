//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P6 measurement (plan 0743f0 n30): a fresh host's first `shentu detect`
// failed on "open attacks.lock: no such file". As root the state directory
// is made (0700, this user's); otherwise the error says what to do.
func TestDetectStateDirFirstRun(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := detectStateDir(dir, false); err == nil || !strings.Contains(err.Error(), "需要 root") || !strings.Contains(err.Error(), "state_dir") {
		t.Errorf("missing, not root: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("made without root")
	}
	if err := detectStateDir(dir, true); err != nil {
		t.Fatalf("missing, root: %v", err)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("made %v, %v", st.Mode(), err)
	}
	if err := detectStateDir(dir, false); err != nil {
		t.Errorf("own directory: %v", err)
	}
	os.Chmod(dir, 0o770)
	if err := detectStateDir(dir, true); err == nil {
		t.Error("group-writable accepted")
	}
	link := filepath.Join(base, "link")
	os.Symlink(dir, link)
	if err := detectStateDir(link, true); err == nil {
		t.Error("a link accepted")
	}
}
