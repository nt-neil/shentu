package detect

import (
	"fmt"
	"testing"
	"time"
)

// v0.4.1 gate fix: the addresses past a group's listed ones (MaxGroupIPs)
// stay known by hash, in one form, and through a merge into an overflow
// group, so the gate can refuse them (MayHold).
func TestMayHoldPastCap(t *testing.T) {
	now := time.Now()
	a := &Attacks{Version: 1, Groups: map[string]*Group{}, Overflow: map[string]*Group{}}
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if i == 12 {
			ip = "::ffff:203.0.113.12" // as a dual-stack listener logs it
		}
		a.Add(Attempt{Entry: "code:marker:a.php:1", Level: LevelPayload, Severity: "high", IP: ip, Verified: false, Reason: "marker"}, now)
	}
	for _, c := range []struct {
		ip   string
		hold bool
	}{
		{"203.0.113.11", true},  // past the cap
		{"203.0.113.12", true},  // logged mapped
		{"203.0.113.200", true}, // never seen, its network's group is past its cap
		{"203.0.113.1", false},  // listed: GroupsOf's
		{"198.51.100.7", false}, // another network
	} {
		if got := len(a.MayHold(c.ip)) > 0; got != c.hold {
			t.Errorf("before the merge, %s: may hold %v", c.ip, got)
		}
	}
	a.evict(0) // into the overflow group, as past MaxGroups
	if len(a.Groups) != 0 || len(a.Overflow) != 1 {
		t.Fatalf("groups %d, overflow %d", len(a.Groups), len(a.Overflow))
	}
	for _, o := range a.Overflow {
		if o.IPsSeen != 12 || len(o.IPs) != MaxGroupIPs {
			t.Errorf("overflow: %d seen, %d listed", o.IPsSeen, len(o.IPs))
		}
	}
	for _, c := range []struct {
		ip   string
		hold bool
	}{
		{"203.0.113.11", true},
		{"203.0.113.12", true},
		{"::ffff:203.0.113.11", true},
		{"203.0.113.200", false}, // an overflow group's hashes are not cut: they tell it
		{"198.51.100.7", false},
	} {
		if got := len(a.MayHold(c.ip)) > 0; got != c.hold {
			t.Errorf("after the merge, %s: may hold %v", c.ip, got)
		}
	}
}

// An overflow summary whose hashes were cut cannot tell its members: it
// may hold any address.
func TestMayHoldOverflowCut(t *testing.T) {
	now := time.Now()
	a := &Attacks{Version: 1, Groups: map[string]*Group{}, Overflow: map[string]*Group{}}
	for i := 0; i < MaxGroupSeen+6; i++ {
		a.Add(Attempt{Entry: "code:marker:a.php:1", Level: LevelPayload, Severity: "high", IP: fmt.Sprintf("192.0.%d.1", i), Verified: false, Reason: "marker"}, now)
	}
	a.evict(0)
	if len(a.MayHold("198.51.100.7")) == 0 {
		t.Error("a cut overflow summary does not hold an address it cannot tell")
	}
}
