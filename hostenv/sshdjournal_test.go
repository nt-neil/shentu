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
	}, "\n") + "\n")}
	if !strings.Contains(strings.Join(argv, " "), "_COMM=sshd _COMM=sshd-session _UID=0") {
		t.Fatalf("argv %v", argv)
	}
	n, err := SSHDJournalLines(context.Background(), h, since, "198.51.100.7")
	if err != nil || n != 2 {
		t.Errorf("%d lines, %v (want 2: not .70's)", n, err)
	}
	found := false
	for _, a := range (LinuxCollector{}).Allowlist() {
		found = found || strings.Join(a, " ") == strings.Join(journalSSHDArgv, " ")
	}
	if !found {
		t.Error("the confirming read is not in the allowlist")
	}
}
