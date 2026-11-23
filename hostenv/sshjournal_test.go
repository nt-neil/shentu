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

// N-213-2: an entry past MaxJournalLine is cut, but keeps its time (the
// field journalctl writes right after the cursor), so what cannot be read
// of it is still placed in time.
func TestReadSSHJournalCutKeepsTime(t *testing.T) {
	h := newFake(true)
	huge := `{"__CURSOR":"` + cur1 + `","__REALTIME_TIMESTAMP":"1794700000000000","_UID":"1000","_COMM":"logger","MESSAGE":"` + strings.Repeat("x", MaxJournalLine+100) + `"}`
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
