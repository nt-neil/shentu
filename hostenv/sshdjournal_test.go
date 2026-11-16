package hostenv

import (
	"context"
	"strings"
	"testing"
	"time"
)

// P5 review 1 (S-4): the gate's confirming read asks journald for sshd's
// own lines only (_COMM, _UID), and counts those naming the address, not
// one it is a prefix of.
func TestSSHDJournalLines(t *testing.T) {
	since := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	h := newFake(true)
	argv := append([]string(nil), journalSSHDArgv...)
	argv[6] = "2026-11-16 00:00:00 UTC"
	h.cmds[argvKey(argv)] = CmdResult{Stdout: []byte(strings.Join([]string{
		"2026-11-16T10:00:00+0000 host sshd[100]: Failed password for root from 198.51.100.7 port 4000 ssh2",
		"2026-11-16T10:00:01+0000 host sshd[101]: Failed password for root from 198.51.100.70 port 4001 ssh2",
		"2026-11-16T10:00:02+0000 host sshd-session[102]: Invalid user marker from 198.51.100.7 port 4002",
		// sshd's own line naming the address only as a user name: not its event.
		"2026-11-16T10:00:03+0000 host sshd[103]: Invalid user 198.51.100.7 from 203.0.113.9 port 4003",
	}, "\n") + "\n")}
	if !strings.Contains(strings.Join(argv, " "), "_COMM=sshd _COMM=sshd-session _UID=0") {
		t.Fatalf("argv %v", argv)
	}
	own, err := SSHDJournalLines(context.Background(), h, since, time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC), "198.51.100.7")
	if err != nil || own.Failed != 1 || own.InvalidUser != 1 {
		t.Errorf("%+v, %v (want one failed, one invalid: not .70's, not the user name)", own, err)
	}
	// An event after the summary's read is not counted.
	own, _ = SSHDJournalLines(context.Background(), h, since, time.Date(2026, 11, 16, 10, 0, 1, 0, time.UTC), "198.51.100.7")
	if own.Failed != 1 || own.InvalidUser != 0 {
		t.Errorf("until 10:00:01: %+v", own)
	}
	found := false
	for _, a := range (LinuxCollector{}).Allowlist() {
		found = found || strings.Join(a, " ") == strings.Join(journalSSHDArgv, " ")
	}
	if !found {
		t.Error("the confirming read is not in the allowlist")
	}
}
