package detect

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// VM acceptance of adff9e6, N2: rules that flag the same sink (one file,
// one line) make one attempt and one group, all rules named in its
// alert; the campaign counts the sink once, so merging never widens it.
func TestOneGroupPerSinkLocation(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	route := engine.RouteRef{Model: "m", Framework: "flask", Method: "get", Pattern: "/marker/<id>", File: "app.py", Line: 14}
	sink := func(rule string) CodeSink {
		return CodeSink{Rule: rule, CWE: "CWE-89", Severity: "warning", Path: "app.py", Line: 14, Routes: []engine.RouteRef{route}}
	}
	s := Build([]CodeSink{sink("marker-rule-a"), sink("marker-rule-b"), sink("marker-rule-c")}, nil)
	j, m := NewJudge(s, ss), NewMatcher(ss)
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	rec := AccessRecord{Client: "203.0.113.10", Time: at, Method: "GET", Path: "/marker/5", Query: "q=marker-one", Status: 200, Bytes: 512}
	as := attemptsOf(j, m, rec, Origin{Verified: true})
	if len(as) != 1 || as[0].Level != LevelPayload || strings.Join(as[0].Rules, ",") != "marker-rule-a,marker-rule-b,marker-rule-c" {
		t.Fatalf("attempts: %+v", as)
	}
	a := newAttacks()
	for _, x := range as {
		a.Add(x, at)
	}
	if len(a.Groups) != 1 {
		t.Fatalf("groups: %d", len(a.Groups))
	}
	var g *Group
	for _, g = range a.Groups {
	}
	if g.Count != 1 || g.Campaign || len(a.Due(at.Add(time.Minute))) != 1 {
		t.Errorf("group %+v, due %d: one request, one sink: count 1, no campaign, one push", g, len(a.Due(at.Add(time.Minute))))
	}
	txt := AlertText(g, &s)
	for _, r := range []string{"marker-rule-a", "marker-rule-b", "marker-rule-c"} {
		if !strings.Contains(txt, r) {
			t.Errorf("alert lacks %s:\n%s", r, txt)
		}
	}
	// The L1 route alone: one attempt too.
	if as = attemptsOf(j, m, AccessRecord{Client: "203.0.113.10", Method: "GET", Path: "/marker/5"}, Origin{Verified: true}); len(as) != 1 || as[0].Level != LevelRoute {
		t.Errorf("L1: %+v", as)
	}
	// Overflow: an evicted group goes to the overflow group of its sink,
	// one for the location.
	b := newAttacks()
	for i, r := range []string{"marker-rule-a", "marker-rule-b"} {
		x := as[0]
		x.Entry, x.Rules, x.IP, x.Level = "code:"+r+":app.py:14", []string{r}, []string{"198.51.100.7", "192.0.2.7"}[i], LevelPayload
		b.Add(x, at)
	}
	b.evict(0)
	if len(b.Overflow) != 1 {
		t.Fatalf("overflow groups: %d, want one for the sink", len(b.Overflow))
	}
	for _, o := range b.Overflow {
		if o.Count != 2 || strings.Join(o.Rules, ",") != "marker-rule-a,marker-rule-b" {
			t.Errorf("overflow %+v", o)
		}
	}
}

// N3: the note on what routes mean is for a code sink's alert only.
func TestRoutesNoteCodeOnly(t *testing.T) {
	s := Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/pkg", Version: "1.0", ID: "CVE-2099-0007"}})
	g := &Group{Prefix: "203.0.113.0/24", Entry: "pkg:CVE-2099-0007:marker/pkg@1.0#/srv/composer.lock", Level: LevelPayload, CVE: "CVE-2099-0007", Count: 1, Severity: "medium", IPs: []string{"203.0.113.10"}}
	if txt := AlertText(g, &s); strings.Contains(txt, RoutesMeaningZh) || strings.Contains(txt, NoRoutesMeaningZh) {
		t.Errorf("a package's alert carries the routes note:\n%s", txt)
	}
	c := Build([]CodeSink{{Rule: "marker-rule-a", CWE: "CWE-89", Severity: "warning", Path: "app.py", Line: 14}}, nil)
	g = &Group{Prefix: "203.0.113.0/24", Entry: "code:marker-rule-a:app.py:14", Level: LevelPayload, File: "app.py", Line: 14, Count: 1, Severity: "medium", IPs: []string{"203.0.113.10"}}
	if txt := AlertText(g, &c); !strings.Contains(txt, RoutesMeaningZh) {
		t.Errorf("a code sink's alert lacks the routes note:\n%s", txt)
	}
}

// Review 1 of #97, N-1 and S-1: a state saved before sinks were keyed by
// location keeps its old keys (code:<rule>:<path>:<line>). Loaded, they are
// the sink's: the campaign counts the sink once, and its old groups and the
// new one are one group, notified when they were. Review 2: an old Unknown
// group (no File) is the sink's too; levels and the verified flag stay
// apart; an overflow group stays one; a key that does not hold together is
// kept as it is.
func TestOldSinkKeysLoaded(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	hour := at.Add(-time.Hour)
	old := newAttacks()
	old.Overflow = map[string]*Group{}
	ip, prefix := "203.0.113.10", "203.0.113.0/24"
	old.IPs[ip] = &ipRecord{Entries: map[string]time.Time{
		"code:marker-rule-a:app.py:14": hour,
		"code:marker-rule-b:app.py:14": hour,
	}, Last: hour}
	put := func(gs map[string]*Group, pfx, entry, file string, line int, level string, verified bool, notified time.Time) *Group {
		k := groupKey(pfx, entry, level, verified)
		g := &Group{Key: k, Prefix: pfx, Entry: entry, Level: level, File: file, Line: line, First: hour, Last: hour, Count: 1, Severity: "medium", IPs: []string{ip}, IPsSeen: 1, Unverified: !verified, Notified: notified}
		if notified.IsZero() {
			g.Since = 1
		}
		gs[k] = g
		return g
	}
	for _, r := range []string{"marker-rule-a", "marker-rule-b"} {
		put(old.Groups, prefix, "code:"+r+":app.py:14", "app.py", 14, LevelPayload, true, hour)
	}
	put(old.Groups, prefix, "code:marker-rule-a:app.py:14", "app.py", 14, LevelRoute, true, time.Time{})
	put(old.Groups, prefix, "code:marker-rule-a:app.py:14", "app.py", 14, LevelPayload, false, hour)
	// An Unknown group as v0.4.0 saved it: the hidden sink's entry, no File.
	u := put(old.Groups, "*", "code:marker-rule-c:app.py:30", "", 0, LevelUnknown, true, time.Time{})
	u.Count, u.Since = 15, 15
	for i := range 15 {
		u.Recent = append(u.Recent, hour.Add(time.Duration(i)*time.Second))
	}
	o := put(old.Overflow, PrefixOverflow, "code:marker-rule-a:app.py:40", "app.py", 40, LevelPayload, true, hour)
	o.IPs, o.Merged = []string{"198.51.100.7"}, 2
	// Keys that do not hold together are kept as they are.
	weird := put(old.Groups, "192.0.2.0/24", "code:weird", "app.py", 14, LevelPayload, true, hour).Key
	other := put(old.Groups, "192.0.2.0/24", "code:marker-rule-a:app.py:60", "other.py", 60, LevelPayload, true, hour).Key
	if err := old.Save(dir, at); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAttacks(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	x := Attempt{IP: ip, Entry: "code:marker-rule-a:app.py:14", Rules: []string{"marker-rule-a"}, File: "app.py", Line: 14, Level: LevelPayload, Verified: true, Severity: "medium"}
	g := a.Add(x, at)
	if n := len(a.IPs[ip].Entries); n != 1 || g.Campaign {
		t.Errorf("campaign entries %v (campaign %v): one sink, want 1", a.IPs[ip].Entries, g.Campaign)
	}
	if g.Count != 2 || strings.Join(g.Rules, ",") != "marker-rule-a,marker-rule-b" { // the two rules' groups are the same request (VM acceptance of 5b57563), and one new
		t.Errorf("group %+v: want the sink's, count 2, both rules", g)
	}
	for _, k := range []string{groupKey(prefix, "code@app.py:14", LevelRoute, true), groupKey(prefix, "code@app.py:14", LevelPayload, true), groupKey(prefix, "code@app.py:14", LevelPayload, false), weird, other} {
		if a.Groups[k] == nil {
			t.Errorf("no group %s", k)
		}
	}
	// The hidden sink: 15 before, 5 now, one group at the threshold.
	for i := range 5 {
		a.Add(Attempt{IP: ip, Entry: "code:marker-rule-c:app.py:30", Rules: []string{"marker-rule-c"}, File: "app.py", Line: 30, Level: LevelUnknown, Verified: true}, at.Add(time.Duration(i)*time.Second))
	}
	if len(a.Groups) != 6 {
		t.Errorf("groups %d, want 6: %v", len(a.Groups), keys(a.Groups))
	}
	d := a.Due(at.Add(time.Minute))
	if len(d) != 1 || d[0].Level != LevelUnknown || d[0].Count != 20 {
		t.Errorf("due %d (%v): want the hidden sink's Unknown group at 20, the others notified an hour ago", len(d), d)
	}
	// The overflow group: one, still an overflow summary (never a source's own).
	ok := a.Overflow[groupKey(PrefixOverflow, "code@app.py:40", LevelPayload, true)]
	if len(a.Overflow) != 1 || ok == nil || ok.Merged != 2 {
		t.Errorf("overflow %v", keys(a.Overflow))
	}
	if gs := a.GroupsOf("198.51.100.7"); len(gs) != 1 || gs[0].Prefix != PrefixOverflow {
		t.Errorf("groups of the overflow's address: %+v", gs)
	}
}

func keys(gs map[string]*Group) []string {
	var out []string
	for k := range gs {
		out = append(out, k)
	}
	return out
}

// VM acceptance of 5b57563: v0.4.0 saved one group per rule for the same
// requests at a sink. Loaded, they are the same requests, not added up:
// counts and Merged are the largest, Recent their times once each. Added to
// a group already keyed by the sink (other requests), they are added up.
func TestOldRuleGroupsNotAdded(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	hour := at.Add(-time.Hour)
	old := newAttacks()
	ip, prefix := "203.0.113.10", "203.0.113.0/24"
	put := func(entry string, line int, level string, count int, sinkKeyed bool) *Group {
		e := entry
		if sinkKeyed {
			e = "code@app.py:" + strconv.Itoa(line)
		}
		pfx := prefix
		if level == LevelUnknown {
			pfx = "*"
		}
		k := groupKey(pfx, e, level, true)
		g := &Group{Key: k, Prefix: pfx, Entry: entry, Level: level, File: "app.py", Line: line, First: hour, Last: hour, Count: count, Since: count, Severity: "medium", IPs: []string{ip}, IPsSeen: 1}
		old.Groups[k] = g
		return g
	}
	for _, r := range []string{"marker-rule-a", "marker-rule-b"} {
		put("code:"+r+":app.py:14", 14, LevelRoute, 32, false)
		u := put("code:"+r+":app.py:30", 30, LevelUnknown, 15, false)
		u.File, u.Line = "", 0 // as v0.4.0 saved an Unknown group
		for i := range 15 {
			u.Recent = append(u.Recent, hour.Add(time.Duration(i)*time.Second))
		}
		put("code:"+r+":app.py:40", 40, LevelPayload, 2, false)
	}
	put("code:marker-rule-a:app.py:20", 20, LevelSuccess, 2, false)
	put("code:marker-rule-b:app.py:20", 20, LevelSuccess, 1, false)
	put("code:marker-rule-a:app.py:40", 40, LevelPayload, 3, true) // saved after the upgrade: other requests
	if err := old.Save(dir, at); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAttacks(dir, at)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want := map[string]int{
		groupKey(prefix, "code@app.py:14", LevelRoute, true):   32,
		groupKey(prefix, "code@app.py:20", LevelSuccess, true): 2,
		groupKey("*", "code@app.py:30", LevelUnknown, true):    15,
		groupKey(prefix, "code@app.py:40", LevelPayload, true): 5,
	}
	if len(a.Groups) != len(want) {
		t.Errorf("groups %v", keys(a.Groups))
	}
	for k, n := range want {
		if g := a.Groups[k]; g == nil || g.Count != n || g.Since != n || g.Merged != 0 {
			t.Errorf("%s: %+v, want count %d", k, g, n)
		}
	}
	if g := a.Groups[groupKey("*", "code@app.py:30", LevelUnknown, true)]; g == nil || len(g.Recent) != 15 {
		t.Errorf("Unknown group's times: %+v, want the 15 once each", g)
	}
	for _, g := range a.Due(at) {
		if g.Level == LevelUnknown {
			t.Errorf("the Unknown group is due at 15 requests: %+v", g)
		}
	}
}
