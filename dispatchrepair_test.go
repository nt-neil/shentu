package main

import (
	"errors"
	"github.com/nt-neil/shentu/internal/osutil"
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

	n, d, err := s.Repair()
	if err != nil || n != 3 || d != 0 {
		t.Fatalf("Repair: %d %d %v", n, d, err)
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
	if line := s.repairedLine(now); !strings.Contains(line, "ran 1 times: 3 unreadable archive lines moved") {
		t.Errorf("daily line: %q", line)
	}
	if err := s.Save(testRecord("000000000004", now)); err != nil {
		t.Fatal(err)
	}
	if n, d, err := s.Repair(); err != nil || n != 0 || d != 0 {
		t.Errorf("second Repair: %d %d %v", n, d, err)
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
	if _, _, err := s.Repair(); !errors.Is(err, errArchive) {
		t.Errorf("a linked day file: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "not json\n" {
		t.Errorf("the link's target was changed: %q", b)
	}
	os.Remove(p)
	os.Chmod(s.dir, 0o750)
	if _, _, err := s.Repair(); !errors.Is(err, errArchive) {
		t.Errorf("a 0750 directory: %v", err)
	}
}

func TestDispatchRepairCommand(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	if err := dispatchCommand(cfg, []string{"repair"}, false); err == nil || !strings.Contains(err.Error(), repairHint()) {
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

// N-H1: an empty line, which Since counts unreadable, is dropped, and the
// automatic count works again.
func TestDispatchRepairEmptyLine(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	a1 := testRecord("000000000001", now)
	a1.Origin = originAuto
	if err := s.Save(a1); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n") // left by a hand edit
	f.Close()
	if _, _, err := s.AutoSince(now.Add(-time.Hour)); !errors.Is(err, errArchive) {
		t.Fatalf("before: %v", err)
	}
	if n, d, err := s.Repair(); err != nil || n != 0 || d != 1 {
		t.Fatalf("Repair: %d %d %v", n, d, err)
	}
	if _, err := os.Stat(p + ".bad"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an empty line was moved to .bad: %v", err)
	}
	if n, _, err := s.AutoSince(now.Add(-time.Hour)); err != nil || n != 1 {
		t.Errorf("AutoSince after: %d %v", n, err)
	}
}

// N-H2: a rewrite that fails midway (a full disk) leaves the day file as
// it was, and no temporary file behind.
func TestDispatchRepairWriteFails(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.Save(testRecord("000000000001", now)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n")
	f.Close()
	before, _ := os.ReadFile(p)
	old := replaceWrite
	replaceWrite = func(f *os.File, b []byte) error {
		if strings.HasPrefix(filepath.Base(f.Name()), ".repairs.jsonl") { // the note itself is written (N-158-1)
			_, err := f.Write(b)
			return err
		}
		f.Write(b[:len(b)/2])
		return errors.New("no space left on device")
	}
	t.Cleanup(func() { replaceWrite = old })
	if _, _, err := s.Repair(); err == nil {
		t.Fatal("Repair said it worked")
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Errorf("the day file changed:\n%s\nwas\n%s", after, before)
	}
	if tmp, _ := filepath.Glob(filepath.Join(s.dir, ".*.tmp")); len(tmp) > 0 {
		t.Errorf("left behind: %v", tmp)
	}
	// S-H1: run again once the disk has room: the moved lines are in .bad once.
	replaceWrite = old
	if n, _, err := s.Repair(); err != nil || n != 1 {
		t.Fatalf("Repair again: %d %v", n, err)
	}
	if b, _ := os.ReadFile(p + ".bad"); strings.Count(string(b), "not json") != 1 {
		t.Errorf(".bad after a second run: %q", b)
	}
	// S-H2: the daily line counts each run's own lines, not the whole .bad file.
	// N-158-1: the run that failed still noted what it put in .bad.
	if notes := s.repairNotes(now.Add(-time.Hour)); len(notes) != 2 || notes[0].Added != 1 || notes[0].Moved != 0 || notes[1].Moved != 1 || notes[1].Added != 0 {
		t.Errorf("notes: %+v", notes)
	}
	if line := s.repairedLine(now); !strings.Contains(line, "ran 2 times: 1 unreadable archive lines moved out (1 of them new") {
		t.Errorf("daily line: %q", line)
	}
}

// N-H2: a Save waiting while Repair replaced the file writes to the new
// file, not to the one that was replaced.
func TestDispatchSaveAfterReplace(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.Save(testRecord("000000000001", now)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	unlock, err := s.lock() // a Repair holds the archive
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p) // what the Repair read, under the lock
	done := make(chan error)
	go func() { done <- s.Save(testRecord("000000000002", now)) }()
	time.Sleep(100 * time.Millisecond) // Save waits for the lock meanwhile
	if err := replaceFile(p, b); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if recs, bad, err := s.Since(now.Add(-time.Hour)); err != nil || bad != 0 || len(recs) != 2 {
		t.Errorf("after: %d records, %d bad, %v", len(recs), bad, err)
	}
}

// S-H2 (round 2): a temporary file a Repair left (it died before its
// rename) goes after a day, not before.
func TestDispatchPruneTemp(t *testing.T) {
	s := testStore(t)
	if err := s.Save(testRecord("0123456789ab", time.Now())); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(s.dir, "."+time.Now().Format(time.DateOnly)+".jsonl.123.tmp")
	fresh := filepath.Join(s.dir, ".repairs.jsonl.456.tmp")
	os.WriteFile(old, []byte("x"), 0o600)
	os.WriteFile(fresh, []byte("x"), 0o600)
	os.Chtimes(old, time.Now().Add(-25*time.Hour), time.Now().Add(-25*time.Hour))
	s.Since(time.Now().Add(-time.Hour))
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a day-old temporary file was kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a fresh temporary file was removed: %v", err)
	}
}

// S-H3: the day files are never locked themselves, so a reader (on
// Windows, where a lock is mandatory, it would fail) can read one while a
// Save writes it.
func TestDispatchDayFileNotLocked(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.Save(testRecord("000000000001", now)); err != nil {
		t.Fatal(err)
	}
	var tryErr error
	ran := false
	saveHeld = func(p string) {
		ran = true
		f, err := os.Open(p)
		if err != nil {
			tryErr = err
			return
		}
		defer f.Close()
		tryErr = osutil.TryLock(f) // taken: Save holds a lock on the file itself
		osutil.Unlock(f)
	}
	t.Cleanup(func() { saveHeld = nil })
	if err := s.Save(testRecord("000000000002", now)); err != nil {
		t.Fatal(err)
	}
	if !ran || tryErr != nil {
		t.Errorf("the day file was locked while saving: %v (hook ran %v)", tryErr, ran)
	}
}

// S-H4-1: an untrusted lock file stops writes, Repair included, and the
// error names the file and the command; nothing moves it aside on its own.
func TestDispatchLockUntrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes are not checked on Windows")
	}
	s := testStore(t)
	if err := s.Save(testRecord("000000000001", time.Now())); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(s.dir, ".lock")
	os.Chmod(lock, 0o644)
	err := s.Save(testRecord("000000000002", time.Now()))
	if !errors.Is(err, errArchive) || !strings.Contains(err.Error(), lock) || !strings.Contains(err.Error(), "sudo mv '"+lock+"' '"+lock+".bad'") {
		t.Errorf("Save: %v", err)
	}
	if _, _, err := s.Repair(); !errors.Is(err, errArchive) {
		t.Errorf("Repair: %v", err)
	}
	if _, err := os.Stat(lock + ".bad"); !errors.Is(err, os.ErrNotExist) {
		t.Error("the lock file was moved aside on its own")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"/var/lib/shentu/dispatch/.lock": "'/var/lib/shentu/dispatch/.lock'", "/srv/開源 x/it's": `'/srv/開源 x/it'\''s'`} {
		if got := shellQuote(in); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
}
