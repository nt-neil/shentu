package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// v0.4.1 (n35-a): a hit one entry takes at L2 is not also unanchored
// because another entry of its class, reached first in map order, did
// not take it. Run with -count=200: map order changes every run.
func TestUnanchoredOrderFree(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	m := NewMatcher(ss)
	sink := func(line int, pattern string) CodeSink {
		return CodeSink{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: line,
			Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: pattern, File: "a.js", Line: line}}}
	}
	// The same request reaches both: one takes the segment in its
	// placeholder, the other has it as its own word.
	j := NewJudge(Build([]CodeSink{sink(1, "/user/:id"), sink(2, "/user/marker-one")}, nil), ss)
	mr := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/user/marker-one"}))
	for i := 0; i < 50; i++ {
		g := j.Judge(mr)
		if len(g.Candidates) != 2 || g.Candidates[0].Level != LevelPayload || g.Candidates[1].Level != LevelRoute || len(g.Unanchored) != 0 {
			t.Fatalf("run %d: %+v", i, g)
		}
	}
	// No entry takes it: unanchored once, whichever comes first.
	j = NewJudge(Build([]CodeSink{sink(1, "/user/marker-one"), sink(2, "/:a/marker-one")}, nil), ss)
	for i := 0; i < 50; i++ {
		if g := j.Judge(mr); len(g.Unanchored) != 1 {
			t.Fatalf("run %d: %+v", i, g)
		}
	}
}

// v0.4.1 (n36): the size baseline leaves out only requests at L2; one
// whose hit stays unanchored (L1) is an ordinary response of the route.
func TestBaselineSkipsOnlyL2(t *testing.T) {
	_, d, in := passSetup(t)
	write(t, filepath.Join(d, "access.log"), accessLine("203.0.113.9", t0.Add(70*time.Second), "/marker-one/marker/5", 200, 4321), os.O_APPEND)
	p, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	b := p.baselines.Routes["GET /marker/{id}"]
	if b == nil {
		t.Fatalf("no baseline: %+v", p.baselines.Routes)
	}
	if !slices.Contains(b.Sizes, 4321) || slices.Contains(b.Sizes, 9000) || len(b.Sizes) != 31 {
		t.Errorf("sizes %v: want the 30 ordinary and the unanchored one, not the L2 one", fmt.Sprint(b.Sizes))
	}
}

// Reviews of #97 and #98 for v0.4.1: loading v0.4.0's per-rule groups of
// one sink counts a time as often as one group holds it (fix2 S-1), takes
// samples and Success in the order of the rules' entries, whatever the
// map's order (fix2 S-2), and converts only a line past 0 (#97 r3 S-1).
func TestOldGroupsLoadedStable(t *testing.T) {
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	hour := at.Add(-time.Hour)
	ip, prefix := "203.0.113.10", "203.0.113.0/24"
	for n := range 20 {
		dir := t.TempDir()
		old := newAttacks()
		old.IPs[ip] = &ipRecord{Entries: map[string]time.Time{"code:marker-rule-a:app.py:-1": hour}, Last: hour}
		for _, r := range []string{"marker-rule-a", "marker-rule-b", "marker-rule-c"} {
			e := "code:" + r + ":app.py:30"
			k := groupKey("*", e, LevelUnknown, true)
			old.Groups[k] = &Group{Key: k, Prefix: "*", Entry: e, Level: LevelUnknown, First: hour, Last: hour, Count: 3, Since: 3, Severity: "low", IPs: []string{ip}, IPsSeen: 1,
				Recent: []time.Time{hour, hour, hour.Add(time.Second)}}
			e = "code:" + r + ":app.py:20"
			k = groupKey(prefix, e, LevelSuccess, true)
			old.Groups[k] = &Group{Key: k, Prefix: prefix, Entry: e, Level: LevelSuccess, File: "app.py", Line: 20, First: hour, Last: hour, Count: 1, Since: 1, Severity: "high", IPs: []string{ip}, IPsSeen: 1,
				Samples: []string{"sample-" + r}, Success: "success-" + r}
		}
		e := "code:marker-rule-a:app.py:-1"
		k := groupKey(prefix, e, LevelPayload, true)
		old.Groups[k] = &Group{Key: k, Prefix: prefix, Entry: e, Level: LevelPayload, File: "app.py", Line: -1, First: hour, Last: hour, Count: 1, Since: 1, Severity: "medium", IPs: []string{ip}, IPsSeen: 1}
		if err := old.Save(dir, at); err != nil {
			t.Fatal(err)
		}
		a, err := LoadAttacks(dir, at)
		if err != nil {
			t.Fatal(err)
		}
		u := a.Groups[groupKey("*", "code@app.py:30", LevelUnknown, true)]
		if u == nil || !slices.Equal(u.Recent, []time.Time{hour, hour, hour.Add(time.Second)}) {
			t.Fatalf("load %d: Unknown group %+v: want each time as often as one group holds it", n, u)
		}
		s := a.Groups[groupKey(prefix, "code@app.py:20", LevelSuccess, true)]
		if s == nil || !slices.Equal(s.Samples, []string{"sample-marker-rule-a", "sample-marker-rule-b", "sample-marker-rule-c"}) || s.Success != "success-marker-rule-a" {
			t.Fatalf("load %d: L3 group %+v: want the rules' order", n, s)
		}
		if a.Groups[k] == nil || a.IPs[ip].Entries[e].IsZero() {
			t.Fatalf("load %d: line -1 converted: %v %v", n, keys(a.Groups), a.IPs[ip].Entries)
		}
		a.Close()
	}
}

// #97 review 1, S-5: rules flagging one sink at different levels make an
// attempt whose entry and route are the level's rule's; at one level, the
// smaller entry's, whatever the order.
func TestMergedSinkEntryOfItsLevel(t *testing.T) {
	ra := &engine.RouteRef{Pattern: "/marker/a", File: "app.py", Line: 3}
	rb := &engine.RouteRef{Pattern: "/marker/b", File: "app.py", Line: 4}
	a := Attempt{Entry: "code:marker-rule-a:app.py:14", File: "app.py", Line: 14, Level: LevelRoute, Rules: []string{"marker-rule-a"}, Route: ra}
	b := Attempt{Entry: "code:marker-rule-b:app.py:14", File: "app.py", Line: 14, Level: LevelPayload, Rules: []string{"marker-rule-b"}, Route: rb}
	for _, in := range [][]Attempt{{a, b}, {b, a}} {
		out := mergeSinks(in)
		if len(out) != 1 || out[0].Entry != b.Entry || out[0].Route != rb || out[0].Level != LevelPayload {
			t.Errorf("L1 and L2: %+v", out)
		}
	}
	a.Level = LevelPayload
	for _, in := range [][]Attempt{{a, b}, {b, a}} {
		out := mergeSinks(in)
		if len(out) != 1 || out[0].Entry != a.Entry || out[0].Route != ra {
			t.Errorf("two L2: %+v", out)
		}
	}
}
