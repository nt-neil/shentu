package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// H: Repair moves what Since cannot read aside and keeps the rest, so the
// automatic count works again at once.
func TestDispatchRepair(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	a1 := testRecord("000000000001", now.Add(-time.Minute))
	a1.Origin = originAuto
	if err := s.Save(a1); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":1,"id":"0000000000`) // cut short
	f.Close()
	a2 := testRecord("000000000002", now)
	a2.Origin = originAuto
	if err := s.Save(a2); err != nil {
		t.Fatal(err)
	}
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n" + `{"v":1,"id":"000000000003","ts":"` + now.UTC().Format(time.RFC3339) + `","origin":"SYSTEM","status":"complete","subs":[]}` + "\n")
	f.Close()
	if _, _, err := s.AutoSince(now.Add(-time.Hour)); !errors.Is(err, errArchive) {
		t.Fatalf("before: %v", err)
	}

	n, err := s.Repair()
	if err != nil || n != 3 {
		t.Fatalf("Repair: %d %v", n, err)
	}
	recs, bad, err := s.Since(now.Add(-time.Hour))
	if err != nil || bad != 0 || len(recs) != 2 {
		t.Errorf("after: %d records, %d bad, %v", len(recs), bad, err)
	}
	if n, _, err := s.AutoSince(now.Add(-time.Hour)); err != nil || n != 2 {
		t.Errorf("AutoSince after: %d %v", n, err)
	}
	b, err := os.ReadFile(p + ".bad")
	if err != nil || strings.Count(string(b), "\n") != 3 || !strings.Contains(string(b), "not json") || !strings.Contains(string(b), `"origin":"SYSTEM"`) {
		t.Errorf(".bad: %q %v", b, err)
	}
	if st, _ := os.Stat(p + ".bad"); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf(".bad mode %v", st.Mode())
	}
	if line := s.repairedLine(now); !strings.Contains(line, "3 lines are kept in 1") {
		t.Errorf("daily line: %q", line)
	}
	if err := s.Save(testRecord("000000000004", now)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Repair(); err != nil || n != 0 {
		t.Errorf("second Repair: %d %v", n, err)
	}
	if recs, bad, _ := s.Since(now.Add(-time.Hour)); bad != 0 || len(recs) != 3 {
		t.Errorf("after a save: %d records, %d bad", len(recs), bad)
	}
}

// Repair touches nothing in an archive Since would not read.
func TestDispatchRepairRefusesUntrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes and links are not checked this way on Windows")
	}
	s := testStore(t)
	now := time.Now()
	if err := s.Save(testRecord("0123456789ab", now)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("not json\n"), 0o600)
	os.Remove(p)
	os.Symlink(target, p)
	if _, err := s.Repair(); !errors.Is(err, errArchive) {
		t.Errorf("a linked day file: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "not json\n" {
		t.Errorf("the link's target was changed: %q", b)
	}
	os.Remove(p)
	os.Chmod(s.dir, 0o750)
	if _, err := s.Repair(); !errors.Is(err, errArchive) {
		t.Errorf("a 0750 directory: %v", err)
	}
}

func TestDispatchRepairCommand(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	if err := dispatchCommand(cfg, []string{"repair"}, false); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("not root: %v", err)
	}
	if err := dispatchCommand(cfg, []string{"wipe"}, true); err == nil {
		t.Error("an unknown subcommand was taken")
	}
	if err := dispatchCommand(cfg, []string{"repair"}, true); err != nil {
		t.Errorf("no archive yet: %v", err)
	}
}

// The day files Repair moved lines from age out with their .bad files.
func TestDispatchRepairPruned(t *testing.T) {
	s := testStore(t)
	if err := s.Save(testRecord("0123456789ab", time.Now())); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(s.dir, time.Now().Add(-40*24*time.Hour).Format(time.DateOnly)+".jsonl.bad")
	os.WriteFile(old, []byte("x\n"), 0o600)
	s.Since(time.Now().Add(-time.Hour))
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an old .bad file was kept: %v", err)
	}
}
