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
	// The first MaxFileBytes are read, then the scan hears the cut (N-P4).
	lines := 0
	if err := ScanLinesUnmasked(rec, p, func(string) { lines++ }); !errors.Is(err, ErrTruncated) || lines < MaxFileBytes/20-1 {
		t.Errorf("scan past MaxFileBytes: %d lines, %v", lines, err)
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

// A replayed file that was cut gives the lines it kept, then ErrTruncated.
func TestReplayOpenTruncatedGivesLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	os.WriteFile(p, []byte(strings.Repeat("line of a large log\n", MaxFileBytes/19+10)), 0o600)
	live, _ := NewLive(nil)
	rec := NewRecorder(live)
	ScanLinesUnmasked(rec, p, func(string) {})
	out := filepath.Join(dir, "fx")
	if err := rec.Save(out, &Masker{}); err != nil {
		t.Fatal(err)
	}
	rp, err := LoadReplay(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	// The fixture holds the path as masked: on Windows t.TempDir is below
	// the profile (C:\Users\...\AppData\Local\Temp), whose tail is masked.
	if err := ScanLinesUnmasked(rp, maskWinHome(p), func(string) { lines++ }); !errors.Is(err, ErrTruncated) || lines < MaxFileBytes/20-1 {
		t.Errorf("replayed scan: %d lines, %v", lines, err)
	}
}
