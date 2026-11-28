package main

import (
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// S2 (v0.5.8 acceptance): sudo:nopasswd joins every no-password rule in one
// risk; its cooldown compares the rules too. A rule added is pushed again
// within the cooldown; the same rules stay cooled. Fails on the base: the
// key alone was compared, and the added rule waited out the cooldown.
func TestCooldownComparesRules(t *testing.T) {
	now := time.Now()
	sent := finding{Key: "sudo:nopasswd", Severity: "warning", Summary: "rules a", cooling: "aaaa"}
	alerted := map[string]time.Time{coolKey(sent): now.Add(-time.Hour)}
	same := sent
	if got := freshFindings([]finding{same}, alerted, 24*time.Hour, now); len(got) != 0 {
		t.Errorf("the same rules pushed again within the cooldown: %+v", got)
	}
	added := finding{Key: "sudo:nopasswd", Severity: "warning", Summary: "rules a, b", cooling: "bbbb"}
	if got := freshFindings([]finding{added}, alerted, 24*time.Hour, now); len(got) != 1 {
		t.Errorf("a rule added not pushed: %+v", got)
	}
	// A finding without cooling is keyed as before (the alerted state of
	// an earlier version holds for it).
	plain := finding{Key: "reboot:pending", Severity: "warning"}
	if got := freshFindings([]finding{plain}, map[string]time.Time{"reboot:pending": now}, 24*time.Hour, now); len(got) != 0 || coolKey(plain) != "reboot:pending" {
		t.Errorf("a finding without cooling: %+v %q", got, coolKey(plain))
	}
}

// The survey's cooling reaches the risk's finding; info is not pushed.
func TestRiskFindingsCooling(t *testing.T) {
	prof := tools.SiteProfile{Cooling: map[string]string{"sudo:nopasswd": "abcd"}}
	fs := riskFindings(prof, []tools.Risk{{Key: "sudo:nopasswd", Severity: "warning"}, {Key: "reboot:pending", Severity: "warning"}, {Key: "x", Severity: "info"}})
	if len(fs) != 2 || coolKey(fs[0]) != "sudo:nopasswd#abcd" || coolKey(fs[1]) != "reboot:pending" {
		t.Errorf("%+v", fs)
	}
}

// S-307-1: two patrols, the rules the same: the second pushes nothing.
// Marking by Key, not coolKey, fails it (the second looks for key#digest).
func TestTwoPatrolsSameRules(t *testing.T) {
	alerted := map[string]time.Time{}
	f := finding{Key: "sudo:nopasswd", Severity: "warning", Summary: "rules a", cooling: "aaaa"}
	now := time.Now()
	first := freshFindings([]finding{f}, alerted, 24*time.Hour, now)
	if len(first) != 1 {
		t.Fatalf("first patrol: %+v", first)
	}
	markAlerted(alerted, first, now)
	if second := freshFindings([]finding{f}, alerted, 24*time.Hour, now.Add(30*time.Minute)); len(second) != 0 {
		t.Errorf("second patrol, the same rules, pushed %+v (alerted %v)", second, alerted)
	}
}
