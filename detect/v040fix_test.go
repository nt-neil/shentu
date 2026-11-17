package detect

import (
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
