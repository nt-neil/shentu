package hostenv

import (
	"context"
	"strings"
	"testing"
	"time"
)

// sshJournalArgvFilled is a read of sshd's units with its slot filled in.
func sshJournalArgvFilled(bin, after string, fields bool) []string {
	a := sshJournalArgv(bin, after != "", fields)
	for i, s := range a {
		switch s {
		case SlotCursor:
			a[i] = after
		case SlotTime:
			a[i] = "2026-11-15 00:00:00 UTC"
		}
	}
	return a
}

// The login index's read of sshd's units is on the allowlist, after a
// cursor or since a time, with or without --output-fields; a made-up
// cursor is not.
func TestSSHJournalAllowlist(t *testing.T) {
	r, err := NewRunner(LinuxCollector{}.Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	for _, bin := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		for _, after := range []string{"", cur1} {
			for _, fields := range []bool{true, false} {
				if a := sshJournalArgvFilled(bin, after, fields); !r.Allowed(a) {
					t.Errorf("not allowlisted: %q", a)
				}
			}
		}
	}
	if a := sshJournalArgvFilled("/usr/bin/journalctl", "s=x;--root=/", true); r.Allowed(a) {
		t.Errorf("a made-up cursor was allowed: %q", a)
	}
	for _, a := range sshJournalArgvs() {
		if !contains(a, "--all") || !contains(a, "ssh@*") || !contains(a, "sshd@*") {
			t.Errorf("not every unit, or no --all: %q", a)
		}
		// N-213-1: from the cursor's own entry, so the read tells when the
		// journal no longer has it; --after-cursor would skip the first
		// entry after the gap.
		if contains(a, "--after-cursor") {
			t.Errorf("--after-cursor: %q", a)
		}
	}
}

// ReadSSHJournal reads all of sshd's units in one read, after the cursor.
func TestReadSSHJournal(t *testing.T) {
	h := newFake(true)
	line := `{"__CURSOR":"` + cur2 + `","__REALTIME_TIMESTAMP":"1794700000000000","_SYSTEMD_UNIT":"ssh.service","_UID":"0","_PID":"812","_COMM":"sshd","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2"}`
	h.cmds[argvKey(sshJournalArgvFilled("/usr/bin/journalctl", cur1, true))] = CmdResult{Stdout: []byte(line + "\n")}
	var got []JournalEntry
	last, err := ReadSSHJournal(context.Background(), h, cur1, time.Time{}, func(e JournalEntry) error {
		got = append(got, e)
		return nil
	})
	if err != nil || last != cur2 || len(got) != 1 {
		t.Fatalf("last %q, err %v, %+v", last, err, got)
	}
	if ip, own, ok := SSHDLoginEvent(got[0]); !ok || !own || ip != "203.0.113.9" {
		t.Errorf("event: %q own %v ok %v", ip, own, ok)
	}
}

// An entry of sshd's units is an event as its short-iso line would be
// (the tag, else _COMM, and _PID before the message), and sshd's own only
// when journald says sshd (or sshd-session) as root sent it.
func TestSSHDLoginEvent(t *testing.T) {
	at := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	failed := "Failed password for root from 203.0.113.9 port 22 ssh2"
	for _, c := range []struct {
		name    string
		e       JournalEntry
		ip      string
		own, ok bool
	}{
		{"sshd", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Ident: "sshd", Message: failed}, "203.0.113.9", true, true},
		{"sshd-session", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd-session", Ident: "sshd-session", Message: "Invalid user x from ::ffff:203.0.113.9 port 22"}, "203.0.113.9", true, true},
		{"no tag: _COMM", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Message: "Accepted publickey for a from 203.0.113.9 port 22 ssh2"}, "203.0.113.9", true, true},
		{"logger -t sshd", JournalEntry{Time: at, UID: 1000, PID: 9, Comm: "logger", Ident: "sshd", Message: failed}, "203.0.113.9", false, true},
		{"root logger", JournalEntry{Time: at, UID: 0, PID: 9, Comm: "logger", Ident: "sshd", Message: failed}, "203.0.113.9", false, true},
		{"sshd not root", JournalEntry{Time: at, UID: 1000, PID: 9, Comm: "sshd", Ident: "sshd", Message: failed}, "203.0.113.9", false, true},
		{"another tag", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Ident: "cron", Message: failed}, "", false, false},
		{"not a login", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Ident: "sshd", Message: "Server listening on 0.0.0.0 port 22."}, "", false, false},
		{"no pid", JournalEntry{Time: at, UID: 0, Comm: "sshd", Ident: "sshd", Message: failed}, "", false, false},
		{"cut", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Ident: "sshd", Message: failed, Cut: true}, "", false, false},
		{"bait in the user", JournalEntry{Time: at, UID: 0, PID: 7, Comm: "sshd", Ident: "sshd", Message: "Failed password for invalid user x from 198.51.100.1 port 1 from 203.0.113.9 port 22 ssh2"}, "203.0.113.9", true, true},
	} {
		ip, own, ok := SSHDLoginEvent(c.e)
		if ip != c.ip || own != c.own || ok != c.ok {
			t.Errorf("%s: %q own %v ok %v, want %q %v %v", c.name, ip, own, ok, c.ip, c.own, c.ok)
		}
	}
}

// N-213-2: an entry past the SSH read's line (maxSSHJournalLine) is cut,
// but keeps its time (the field journalctl writes right after the cursor),
// so what cannot be read of it is still placed in time.
func TestReadSSHJournalCutKeepsTime(t *testing.T) {
	h := newFake(true)
	huge := `{"__CURSOR":"` + cur1 + `","__REALTIME_TIMESTAMP":"1794700000000000","_UID":"1000","_COMM":"logger","MESSAGE":"` + strings.Repeat("x", maxSSHJournalLine+100) + `"}`
	h.cmds[argvKey(sshJournalArgvFilled("/usr/bin/journalctl", "", true))] = CmdResult{Stdout: []byte(huge + "\n")}
	var got []JournalEntry
	_, err := ReadSSHJournal(context.Background(), h, "", time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), func(e JournalEntry) error {
		got = append(got, e)
		return nil
	})
	if err != nil || len(got) != 1 || !got[0].Cut || !got[0].Time.Equal(time.UnixMicro(1794700000000000)) || SSHDWrote(got[0]) {
		t.Fatalf("%v %+v", err, got)
	}
}

// S-213-3: where sshd's units start in the journal is one fixed read,
// allowlisted, stopped at its first entry.
func TestSSHJournalFirst(t *testing.T) {
	r, _ := NewRunner(LinuxCollector{}.Allowlist())
	for _, fields := range []bool{true, false} {
		if a := sshJournalFirstArgv("/usr/bin/journalctl", fields); !r.Allowed(a) {
			t.Errorf("not allowlisted: %q", a)
		}
	}
	h := newFake(true)
	l := func(c string) string {
		return `{"__CURSOR":"` + c + `","__REALTIME_TIMESTAMP":"1794700000000000","_UID":"0","_PID":"7","_COMM":"sshd","MESSAGE":"x"}`
	}
	h.cmds[argvKey(sshJournalFirstArgv("/usr/bin/journalctl", true))] = CmdResult{Stdout: []byte(l(cur1) + "\n" + l(cur2) + "\n")}
	e, ok, err := SSHJournalFirst(context.Background(), h)
	if err != nil || !ok || e.Cursor != cur1 || !e.Time.Equal(time.UnixMicro(1794700000000000)) {
		t.Errorf("%+v %v %v", e, ok, err)
	}
	h.cmds[argvKey(sshJournalFirstArgv("/usr/bin/journalctl", true))] = CmdResult{}
	if _, ok, err := SSHJournalFirst(context.Background(), h); ok || err != nil {
		t.Errorf("no entries: %v %v", ok, err)
	}
}

// S-213-4: sshd's units are read whole up to what the whole read takes
// (a 70 KB message is not cut, its address read); past it, cut.
func TestReadSSHJournalMessageCap(t *testing.T) {
	h := newFake(true)
	msg := func(n int) string {
		return "Failed password for invalid user " + strings.Repeat("x", n) + " from 203.0.113.9 port 22 ssh2"
	}
	line := func(c, m string) string {
		return `{"__CURSOR":"` + c + `","__REALTIME_TIMESTAMP":"1794700000000000","_UID":"1000","_PID":"9","_COMM":"logger","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"` + m + `"}`
	}
	h.cmds[argvKey(sshJournalArgvFilled("/usr/bin/journalctl", "", true))] = CmdResult{Stdout: []byte(line(cur1, msg(70<<10)) + "\n" + line(cur2, msg(MaxLineBytes)) + "\n")}
	var got []JournalEntry
	_, err := ReadSSHJournal(context.Background(), h, "", time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), func(e JournalEntry) error {
		got = append(got, e)
		return nil
	})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v, %d entries", err, len(got))
	}
	if ip, own, ok := SSHDLoginEvent(got[0]); got[0].Cut || !ok || own || ip != "203.0.113.9" {
		t.Errorf("70 KB: cut %v, %q own %v ok %v", got[0].Cut, ip, own, ok)
	}
	if !got[1].Cut {
		t.Errorf("past the whole read's line: not cut")
	}
}

// The flat reading of a journal line is the full one's, field for field,
// for every line it takes; any other line goes to the full one.
func TestParseJournalFlatAgrees(t *testing.T) {
	c := `"__CURSOR":"` + cur1 + `"`
	for _, l := range []string{
		`{` + c + `,"__REALTIME_TIMESTAMP":"1794700000000000","_UID":"0","_PID":"7","_COMM":"sshd","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2"}`,
		`{` + c + `,"MESSAGE":"tab\there \"q\" \\ \u00e9 \u4e2d \ud83d\ude00 \/","_UID":"1000"}`,
		`{` + c + `,"MESSAGE":"é中文"}`,
		`{` + c + `}`,
		`{` + c + `,"MESSAGE":"a","MESSAGE":"b"}`,
		`{` + c + `,"MESSAGE":[104,105]}`,
		`{` + c + `,"MESSAGE":null}`,
		`{` + c + `,"_UID":0}`,
		`{` + c + `,"MESSAGE":"` + "\xff\xfe" + `"}`,
		`{` + c + `,"MESSAGE":"a"} x`,
		`{` + c + `,"MESSAGE":"` + strings.Repeat("m", 300) + `"}`,
		` { ` + c + ` , "MESSAGE" : "spaced" } `,
		`{"MESSAGE":"no cursor"}`,
		`{` + c + `,"MESSAGE":"unterminated}`,
	} {
		full, ferr := parseJournalJSONFull(l, 100)
		got, gerr := parseJournalJSON(l, 100)
		if (ferr == nil) != (gerr == nil) || ferr == nil && got != full {
			t.Errorf("%.60q:\nflat %+v %v\nfull %+v %v", l, got, gerr, full, ferr)
		}
	}
	if _, ok := parseJournalFlat(`{`+c+`,"MESSAGE":"x","_UID":"0","_PID":"7"}`, 100); !ok {
		t.Error("the common line is not read flat")
	}
}
