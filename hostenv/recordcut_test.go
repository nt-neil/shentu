package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Recording never cuts a stream silently: past what a fixture keeps, the
// file is recorded as truncated and the caller hears it.
func TestRecorderOpenSaysTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	os.WriteFile(p, []byte(strings.Repeat("line of a large log\n", MaxFileBytes/19+10)), 0o600)
	live, err := NewLive(nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(live)
	if _, err := rec.Open(p); !errors.Is(err, ErrTruncated) {
		t.Errorf("Open past MaxFileBytes: %v", err)
	}
	if e := rec.got[(&entry{Op: "file", Path: p}).key()]; e == nil || e.Err != "truncated" {
		t.Errorf("recorded entry %+v", e)
	}
	small := filepath.Join(dir, "small.log")
	os.WriteFile(small, []byte("one\n"), 0o600)
	if _, err := rec.Open(small); err != nil {
		t.Errorf("small file: %v", err)
	}
}
