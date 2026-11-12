package hostenv

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeJournal answers journalctl with fixed lines, stderr and error.
type fakeJournal struct {
	*Live
	lines  []string
	stderr string
	err    error
}

func (j *fakeJournal) RunLinesUnmasked(_ context.Context, _ []string, fn func(string)) (CmdResult, error) {
	for _, l := range j.lines {
		fn(l)
	}
	return CmdResult{Stderr: j.stderr}, j.err
}

// journald first; the text logs only as an unverified fallback.
func TestAuthEventsSourceOrder(t *testing.T) {
	now := time.Now()
	at := func(ip string) string {
		return now.Add(-time.Hour).UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from " + ip + " port 22 ssh2"
	}
	jline, tline := at("203.0.113.1"), at("203.0.113.2")
	hint := "Hint: You are currently not seeing messages from other users and the system.\n"
	for _, c := range []struct {
		name    string
		journal fakeJournal
		text    string // "" no file, "-" unreadable
		status  Status
		reason  Reason
		ip      string
		detail  string
	}{
		{"journald has entries", fakeJournal{lines: []string{jline}}, tline, StatusOK, "", "203.0.113.1", "from journald"},
		{"journald timed out", fakeJournal{lines: []string{jline}, err: ErrTimeout}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "journald timed out after"},
		{"journald cut short", fakeJournal{lines: []string{jline}, err: ErrTruncated}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "journald was cut short"},
		{"journald timed out, no text log", fakeJournal{lines: []string{jline}, err: ErrTimeout}, "", StatusPartial, ReasonTimeout, "203.0.113.1", "no text auth log"},
		{"journald empty, text has sshd lines", fakeJournal{lines: []string{"-- No entries --"}}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "journald has no sshd entries"},
		{"journald empty, text without sshd lines", fakeJournal{lines: []string{"-- No entries --"}}, "x CRON[1]: ok", StatusOK, "", "", "from journald"},
		{"journald empty, no text log", fakeJournal{lines: []string{"-- No entries --"}}, "", StatusOK, "", "", "from journald"},
		{"journald empty, text unreadable", fakeJournal{lines: []string{"-- No entries --"}}, "-", StatusUnknown, ReasonPermission, "", "unreadable"},
		{"journald hidden from this user", fakeJournal{lines: []string{"-- No entries --"}, stderr: hint}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "hides the system's entries"},
		{"journald hidden, text unreadable", fakeJournal{stderr: hint}, "-", StatusUnknown, ReasonPermission, "", "none"},
		{"no journald", fakeJournal{err: &fs.PathError{Op: "exec", Path: "journalctl", Err: fs.ErrNotExist}}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "journald unavailable"},
	} {
		dir := t.TempDir()
		switch c.text {
		case "":
		case "-":
			if runtime.GOOS == "windows" {
				continue // mode 0 does not stop reading there
			}
			os.WriteFile(filepath.Join(dir, "auth.log"), []byte(tline+"\n"), 0o000) // stat works, reading fails (not root)
		default:
			os.WriteFile(filepath.Join(dir, "auth.log"), []byte(c.text+"\n"), 0o600)
		}
		src := c.journal
		src.Live = &Live{Remap: map[string]string{"/var/log": dir}}
		f := LinuxCollector{}.AuthEvents(context.Background(), &src, now, []string{"/var/log/auth.log"})
		n := 0
		for _, v := range f.Value.FailedBySrc {
			n += v
		}
		want := 0
		if c.ip != "" {
			want = 1
		}
		if f.Status != c.status || f.Reason != c.reason || n != want || (c.ip != "" && f.Value.FailedBySrc[c.ip] != 1) || !strings.Contains(f.Detail, c.detail) {
			t.Errorf("%s: %s %s %q %v", c.name, f.Status, f.Reason, f.Detail, f.Value.FailedBySrc)
		}
	}
}
