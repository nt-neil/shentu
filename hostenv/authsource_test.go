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
		ips     string // comma-separated, one failed login each
		detail  string
	}{
		{"journald has entries", fakeJournal{lines: []string{jline}}, tline, StatusOK, "", "203.0.113.1", "from journald"},
		{"journald timed out: what it gave is kept", fakeJournal{lines: []string{jline}, err: ErrTimeout}, tline, StatusPartial, ReasonUnverified, "203.0.113.1,203.0.113.2", "journald timed out after"},
		{"journald cut short: what it gave is kept", fakeJournal{lines: []string{jline}, err: ErrTruncated}, tline, StatusPartial, ReasonUnverified, "203.0.113.1,203.0.113.2", "journald was cut short"},
		{"journald timed out, no text log", fakeJournal{lines: []string{jline}, err: ErrTimeout}, "", StatusPartial, ReasonTimeout, "203.0.113.1", "no text auth log"},
		{"journald empty, text has sshd lines", fakeJournal{lines: []string{"-- No entries --"}}, tline, StatusPartial, ReasonUnverified, "203.0.113.2", "journald has no sshd entries"},
		{"journald empty, text without sshd lines", fakeJournal{lines: []string{"-- No entries --"}}, "x CRON[1]: ok", StatusOK, "", "", "from journald"},
		{"journald empty, no text log: cannot tell", fakeJournal{lines: []string{"-- No entries --"}}, "", StatusPartial, ReasonUnverified, "", "journald may not keep them"},
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
		ok := true
		var ips []string
		if c.ips != "" {
			ips = strings.Split(c.ips, ",")
		}
		for _, ip := range ips {
			ok = ok && f.Value.FailedBySrc[ip] == 1
		}
		if f.Status != c.status || f.Reason != c.reason || n != len(ips) || !ok || !strings.Contains(f.Detail, c.detail) {
			t.Errorf("%s: %s %s %q %v", c.name, f.Status, f.Reason, f.Detail, f.Value.FailedBySrc)
		}
	}
}

// journald cut short and a text log holding the same events: per source the
// larger count, not the sum.
func TestAuthEventsTimeoutTakesMax(t *testing.T) {
	now := time.Now()
	line := func(ip string, min int) string {
		return now.Add(-time.Duration(min)*time.Minute).UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from " + ip + " port 22 ssh2"
	}
	j := []string{line("203.0.113.1", 3), line("203.0.113.1", 2), line("203.0.113.1", 1)} // 3 before the cut
	text := []string{line("203.0.113.1", 3), line("203.0.113.1", 2), line("203.0.113.9", 1)}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(strings.Join(text, "\n")+"\n"), 0o600)
	src := &fakeJournal{Live: &Live{Remap: map[string]string{"/var/log": dir}}, lines: j, err: ErrTimeout}
	f := LinuxCollector{}.AuthEvents(context.Background(), src, now, []string{"/var/log/auth.log"})
	if f.Value.FailedBySrc["203.0.113.1"] != 3 || f.Value.FailedBySrc["203.0.113.9"] != 1 || f.Reason != ReasonUnverified {
		t.Errorf("%s %s %v", f.Status, f.Reason, f.Value.FailedBySrc)
	}
	a, b := NewSSHLogins(now.Add(-time.Hour), now, ""), NewSSHLogins(now.Add(-time.Hour), now, "")
	a.Add(line("203.0.113.1", 5))
	b.Add(line("203.0.113.1", 2))
	got, _ := MaxLogins(a, nil, b)
	if len(got) != 1 || got[0].Failed != 1 || !got[0].First.Before(got[0].Last) {
		t.Errorf("MaxLogins %+v", got)
	}
}

// sockJournal has sshd entries only under the socket-activated units.
type sockJournal struct {
	*Live
	asked []string
}

func (j *sockJournal) RunLinesUnmasked(_ context.Context, argv []string, fn func(string)) (CmdResult, error) {
	j.asked = append(j.asked, argv[2])
	if argv[2] == "ssh@*" {
		fn(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + " vm sshd[9]: Invalid user x from 203.0.113.5 port 22")
	} else {
		fn("-- No entries --")
	}
	return CmdResult{}, nil
}

// A socket-activated sshd (ssh@*.service) is read from journald, verified;
// the sock units are asked only when ssh and sshd have nothing.
func TestAuthEventsSocketActivated(t *testing.T) {
	src := &sockJournal{Live: &Live{Remap: map[string]string{"/var/log": t.TempDir()}}}
	f := LinuxCollector{}.AuthEvents(context.Background(), src, time.Now(), []string{"/var/log/auth.log"})
	if f.Status != StatusOK || f.Value.FailedBySrc["203.0.113.5"] != 1 || strings.Join(src.asked, ",") != "ssh,ssh@*" {
		t.Errorf("%s %q %v asked %v", f.Status, f.Detail, f.Value.FailedBySrc, src.asked)
	}
	r, _ := NewRunner(LinuxCollector{}.Allowlist())
	for _, a := range [][]string{journalSockArgv, journalSockBinArgv} {
		argv := append([]string(nil), a...)
		argv[6] = "2026-11-13 00:00:00 UTC"
		if !r.Allowed(argv) {
			t.Errorf("not allowlisted: %q", argv)
		}
	}
}
