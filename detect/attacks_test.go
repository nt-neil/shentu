package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P4 part 2: aggregation, notification, campaigns, attacks.json.

var t0 = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func att(ip, entry, level string, at time.Time) Attempt {
	return Attempt{IP: ip, Entry: entry, Level: level, Time: at, Verified: true, Sample: "GET /marker?q=" + entry,
		Severity: SeverityOf(level, false, false, true)}
}

func newAttacks() *Attacks {
	return &Attacks{Version: 1, Groups: map[string]*Group{}, IPs: map[string]*ipRecord{}}
}

func TestNetworkOf(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77":           "203.0.113.0/24",
		"::ffff:203.0.113.77":    "203.0.113.0/24",
		"2001:db8:1:2:3:4:5:6":   "2001:db8:1:2::/64",
		"not-an-address.example": "not-an-address.example",
	} {
		if got := NetworkOf(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestAttacksGroups(t *testing.T) {
	a := newAttacks()
	a.Add(att("203.0.113.1", "e1", LevelPayload, t0), t0)
	a.Add(att("203.0.113.2", "e1", LevelPayload, t0.Add(time.Minute)), t0)
	a.Add(att("203.0.113.2", "e1", LevelPayload, t0.Add(2*time.Minute)), t0)
	a.Add(att("198.51.100.1", "e1", LevelPayload, t0), t0)
	a.Add(att("203.0.113.1", "e1", LevelRoute, t0), t0)
	if len(a.Groups) != 3 {
		t.Fatalf("%d groups, want 3 (/24 x level)", len(a.Groups))
	}
	g := a.Groups["203.0.113.0/24|e1|L2"]
	if g == nil || g.Count != 3 || strings.Join(g.IPs, ",") != "203.0.113.1,203.0.113.2" || g.IPsSeen != 2 ||
		!g.First.Equal(t0) || !g.Last.Equal(t0.Add(2*time.Minute)) || len(g.Samples) != 1 || g.Severity != "high" {
		t.Errorf("group %+v", g)
	}
	// IPv6 /64: many addresses, ten listed, all counted.
	for i := 0; i < MaxGroupIPs+2; i++ {
		a.Add(att(fmt.Sprintf("2001:db8::%x", i+1), "e2", LevelPayload, t0), t0)
	}
	g = a.Groups["2001:db8::/64|e2|L2"]
	if len(g.IPs) != MaxGroupIPs || g.IPsSeen != MaxGroupIPs+2 {
		t.Errorf("v6: %d listed, %d seen", len(g.IPs), g.IPsSeen)
	}
	// At most MaxGroupSamples samples.
	for i := 0; i < 5; i++ {
		x := att("192.0.2.1", "e3", LevelPayload, t0)
		x.Sample = fmt.Sprintf("GET /marker/%d", i)
		a.Add(x, t0)
	}
	if g = a.Groups["192.0.2.0/24|e3|L2"]; len(g.Samples) != MaxGroupSamples {
		t.Errorf("samples %v", g.Samples)
	}
	// An unverified IP: at most medium, the reason kept.
	u := att("192.0.2.9", "e4", LevelPayload, t0)
	u.Verified, u.Reason, u.Severe = false, ReasonXFF, true
	if g = a.Add(u, t0); !g.Unverified || g.Severity != "medium" || strings.Join(g.Reasons, "") != ReasonXFF {
		t.Errorf("unverified: %+v", g)
	}
}

func TestAttacksDue(t *testing.T) {
	a := newAttacks()
	a.Add(att("203.0.113.1", "e1", LevelPayload, t0), t0)
	due := a.Due(t0)
	if len(due) != 1 {
		t.Fatalf("first: %d due", len(due))
	}
	a.Notified(due[0], t0)
	a.Add(att("203.0.113.1", "e1", LevelPayload, t0.Add(time.Hour)), t0)
	if len(a.Due(t0.Add(2*time.Hour))) != 0 {
		t.Error("notified again within 24 hours")
	}
	due = a.Due(t0.Add(NotifyEvery))
	if len(due) != 1 || due[0].Since != 1 || due[0].Count != 2 {
		t.Errorf("after 24 hours: %+v", due)
	}
	a.Notified(due[0], t0.Add(NotifyEvery))
	if len(a.Due(t0.Add(3*NotifyEvery))) != 0 {
		t.Error("due with nothing new")
	}
}

// Unknown attempts: grouped by sink whatever the source, counted, and
// notified only at UnknownNotifyAt in a window.
func TestAttacksUnknown(t *testing.T) {
	a := newAttacks()
	for i := 0; i < UnknownNotifyAt-1; i++ {
		a.Add(att(fmt.Sprintf("198.51.%d.1", i), "sink-1", LevelUnknown, t0.Add(time.Duration(i)*time.Minute)), t0)
	}
	if len(a.Groups) != 1 || len(a.Due(t0.Add(time.Hour))) != 0 {
		t.Fatalf("%d groups, %d due before the threshold", len(a.Groups), len(a.Due(t0.Add(time.Hour))))
	}
	a.Add(att("192.0.2.1", "sink-1", LevelUnknown, t0.Add(30*time.Minute)), t0)
	due := a.Due(t0.Add(time.Hour))
	if len(due) != 1 || due[0].Prefix != "*" || due[0].Count != UnknownNotifyAt {
		t.Fatalf("at the threshold: %+v", due)
	}
	a.Notified(due[0], t0.Add(time.Hour))
	a.Add(att("192.0.2.1", "sink-1", LevelUnknown, t0.Add(2*time.Hour)), t0)
	if len(a.Due(t0.Add(3*time.Hour))) != 0 {
		t.Error("notified again within 24 hours")
	}
	// A new window: the count starts again.
	a.Add(att("192.0.2.1", "sink-1", LevelUnknown, t0.Add(NotifyEvery+2*time.Hour)), t0)
	if len(a.Due(t0.Add(NotifyEvery+3*time.Hour))) != 0 {
		t.Error("one in a new window notified")
	}
}

// One address trying three vulnerabilities (L2 or L3) in 24 hours is a
// campaign: a step up. L1 does not count; older tries fall out.
func TestAttacksCampaign(t *testing.T) {
	a := newAttacks()
	a.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0)
	a.Add(att("192.0.2.1", "e2", LevelRoute, t0), t0)
	a.Add(att("192.0.2.1", "e3", LevelRoute, t0), t0)
	if g := a.Add(att("192.0.2.1", "e4", LevelPayload, t0), t0); g.Campaign {
		t.Errorf("two L2 and two L1 taken for a campaign: %+v", g)
	}
	g := a.Add(att("192.0.2.1", "e5", LevelPayload, t0.Add(time.Hour)), t0)
	if !g.Campaign || g.Severity != "critical" {
		t.Errorf("third L2 in 24 hours: %+v", g)
	}
	b := newAttacks()
	b.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0)
	b.Add(att("192.0.2.1", "e2", LevelPayload, t0), t0)
	if g := b.Add(att("192.0.2.1", "e3", LevelPayload, t0.Add(CampaignWindow+time.Minute)), t0); g.Campaign {
		t.Errorf("tries past the window counted: %+v", g)
	}
	// Bounds: entries per address, addresses.
	c := newAttacks()
	for i := 0; i < MaxIPEntries+5; i++ {
		c.Add(att("192.0.2.1", fmt.Sprintf("e%02d", i), LevelPayload, t0.Add(time.Duration(i)*time.Second)), t0)
	}
	if r := c.IPs["192.0.2.1"]; len(r.Entries) != MaxIPEntries {
		t.Errorf("%d entries kept", len(r.Entries))
	} else if _, ok := r.Entries["e00"]; ok {
		t.Error("the oldest entry kept")
	}
	for i := 0; i < MaxIPIndex+3; i++ {
		c.Add(att(fmt.Sprintf("10.%d.%d.1", i/256, i%256), "e", LevelPayload, t0.Add(time.Duration(i)*time.Second)), t0)
	}
	if len(c.IPs) != MaxIPIndex {
		t.Errorf("%d addresses kept", len(c.IPs))
	}
}

func TestAttacksSaveLoad(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadAttacks(dir, t0)
	if err != nil || len(a.Groups) != 0 {
		t.Fatalf("%v %+v", err, a)
	}
	a.Add(att("203.0.113.1", "e1", LevelPayload, t0), t0)
	a.Add(att("203.0.113.1", "old", LevelPayload, t0.Add(-AttackTTL-time.Hour)), t0)
	if err := a.Save(dir, t0); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, AttacksFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, st.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
	b, err := LoadAttacks(dir, t0)
	if err != nil || len(b.Groups) != 1 || b.Groups["203.0.113.0/24|e1|L2"] == nil || b.Groups["203.0.113.0/24|e1|L2"].Count != 1 {
		t.Errorf("after a save past the TTL: %v %+v", err, b.Groups)
	}
	// MaxGroups: the least recently seen go.
	for i := 0; i < MaxGroups+5; i++ {
		b.Add(att("203.0.113.1", fmt.Sprintf("g%d", i), LevelRoute, t0.Add(time.Duration(i)*time.Second)), t0)
	}
	if err := b.Save(dir, t0.Add(time.Hour)); err != nil || len(b.Groups) != MaxGroups {
		t.Errorf("%v: %d groups", err, len(b.Groups))
	}
	// A file that does not parse is set aside, said, and the state starts empty.
	if err := os.WriteFile(filepath.Join(dir, AttacksFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadAttacks(dir, t0)
	if err != nil || len(c.Groups) != 0 || c.Note == "" {
		t.Fatalf("%v %+v", err, c)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, AttacksFile+".bad-*")); len(m) != 1 {
		t.Errorf("not set aside: %v", m)
	}
}

func TestRoundJudged(t *testing.T) {
	var r Round
	r.Judged(Judgment{Noise: []Hit{{}, {}}, Unanchored: []Hit{{}}, Unknown: true})
	r.Judged(Judgment{})
	if r != (Round{Noise: 2, Unanchored: 1, Unknown: 1}) {
		t.Errorf("%+v", r)
	}
}

// Security review of part 2: a flood of new groups (L1 from many
// networks, unverified) does not push out an attempt not yet notified;
// what is dropped while pending is counted.
func TestAttacksEvictionKeepsPending(t *testing.T) {
	a := newAttacks()
	a.Add(att("203.0.113.1", "target", LevelPayload, t0), t0) // pending, verified, high, the oldest
	for i := 0; i < MaxGroups+MaxGroups/2; i++ {
		x := att(fmt.Sprintf("10.%d.%d.1", i/256, i%256), "e", LevelRoute, t0.Add(time.Duration(i+1)*time.Second))
		x.Verified = false
		a.Add(x, t0)
		if len(a.Groups) > MaxGroups+MaxGroups/4 {
			t.Fatalf("%d groups between saves", len(a.Groups))
		}
	}
	a.prune(t0.Add(time.Hour))
	if len(a.Groups) != MaxGroups || a.Groups["203.0.113.0/24|target|L2"] == nil {
		t.Fatalf("%d groups; the pending L2 kept: %v", len(a.Groups), a.Groups["203.0.113.0/24|target|L2"] != nil)
	}
	if a.DroppedPending == 0 {
		t.Error("pending groups dropped without being counted")
	}
}
