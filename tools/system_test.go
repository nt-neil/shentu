package tools

import (
	"slices"
	"testing"
)

// A process started from the initramfs (plymouthd at boot) shows its
// executable as deleted after the switch to the real root and is not flagged;
// one started later whose executable was deleted is, whatever its name.
func TestUnflagBootSurvivors(t *testing.T) {
	deleted := []string{"deleted_executable"}
	ps := []Proc{
		{PID: 1, Exe: "/usr/lib/systemd/systemd"},
		{PID: 2}, // a kernel thread
		{PID: 297, Exe: "/usr/sbin/plymouthd (deleted)", Flags: deleted}, // from the initramfs
		{PID: 410, Exe: "/usr/lib/systemd/systemd-journald"},
		{PID: 900, Exe: "/usr/lib/systemd/systemd-udevd"},
		{PID: 5000, Exe: "/usr/sbin/plymouthd (deleted)", Flags: deleted}, // named so, started later
		{PID: 6000, Exe: "/tmp/.x/kworker (deleted)", Flags: deleted},
	}
	start := map[int]int64{1: 5, 2: 5, 297: 120, 410: 310, 900: 330, 5000: 90000, 6000: 4000000}
	flagged := map[int]bool{}
	for _, p := range unflagBootSurvivors(slices.Clone(ps), start) {
		flagged[p.PID] = slices.Contains(p.Flags, "deleted_executable")
	}
	if flagged[297] || !flagged[5000] || !flagged[6000] {
		t.Errorf("flagged %v", flagged)
	}
	// Every early process gone since: a late one is flagged all the same.
	late := []Proc{{PID: 1, Exe: "/usr/lib/systemd/systemd"}, {PID: 7000, Exe: "/usr/bin/x (deleted)", Flags: deleted},
		{PID: 8000, Exe: "/usr/sbin/sshd"}}
	got := unflagBootSurvivors(late, map[int]int64{1: 5, 7000: 50000, 8000: 900000})
	if !slices.Contains(got[1].Flags, "deleted_executable") {
		t.Error("a process started long after boot was unflagged")
	}
}
