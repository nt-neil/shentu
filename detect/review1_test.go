package detect

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

// Review 1 of #87, the structural fixes. Inputs are neutral markers and
// ordinary requests: what is tested is the order, the bounds and the
// route and version logic, not any payload.

// Signatures of neutral markers: a class one first in the file, then one
// with a route, then one for a CVE.
const markerSigs = `
[[signature]]
id = "class-marker"
title = "a class signature"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]

[[signature]]
id = "route-marker"
title = "a route signature"
class = "path"
source = "shentu"
license = "Apache-2.0"
[[signature.route]]
path = "/marker/route"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]

[[signature]]
id = "cve-marker"
title = "a CVE signature"
class = "cmdi"
cves = ["CVE-2099-0007"]
source = "shentu"
license = "Apache-2.0"
[[signature.applies_to]]
ecosystem = "PyPI"
package = "Marker_Pkg.Core"
versions = "<2.0"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]
`

// B-1: signatures with a route or a CVE are tried first.
func TestMatchSpecificFirst(t *testing.T) {
	m := NewMatcher(loadSigs(t, markerSigs))
	r := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/marker/route", Query: "a=marker-one"}))
	var ids []string
	for _, h := range r.Hits {
		ids = append(ids, h.Signature)
	}
	if got := strings.Join(ids, ","); got != "route-marker,cve-marker,class-marker" {
		t.Errorf("order %q, want the route's and the CVE's before the class's", got)
	}
}

// B-1: the cost is bounded by length: all the parameters' values together
// stop at MaxParamsText, said as Cut; a value under PHP's second name is
// not counted (nor tried) twice.
func TestNormalizeRequestBound(t *testing.T) {
	v := strings.Repeat("a", MaxNormalized-10)
	var qs []string
	for i := 0; i < 4; i++ {
		qs = append(qs, "p"+string(rune('a'+i))+"="+v)
	}
	q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: strings.Join(qs, "&")})
	total := 0
	for k, vs := range q.Params {
		if q.Sent[k] {
			for _, x := range vs {
				total += len(x)
			}
		}
	}
	if !q.Cut || total > MaxParamsText {
		t.Errorf("4 values of %d bytes: cut %v, %d bytes kept (bound %d)", len(v), q.Cut, total, MaxParamsText)
	}
	two := Normalize(AccessRecord{Method: "GET", Path: "/", Query: "a[]=" + v + "&b[]=" + v})
	if two.Cut || two.Params["a"][0] != v || !two.Sent["a[]"] || two.Sent["a"] {
		t.Errorf("a[] and b[]: cut %v, sent %v", two.Cut, two.Sent)
	}
	m := NewMatcher(loadSigs(t, markerSigs))
	r := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "x[]=marker-one"}))
	if len(r.Hits) != 2 || r.Hits[0].Param != "x[]" || r.Hits[1].Param != "x[]" {
		t.Errorf("x[]: %+v, want each signature's hit naming x[]", r.Hits)
	}
}

// B-1, S: the judgment carries Cut and TimedOut.
func TestJudgmentCarriesBounds(t *testing.T) {
	j := NewJudge(Surface{}, nil)
	g := j.Judge(MatchResult{Request: Request{Cut: true}, TimedOut: true})
	if !g.Cut || !g.TimedOut {
		t.Errorf("%+v: want cut and timed out", g)
	}
	if g = j.Judge(MatchResult{}); g.Cut || g.TimedOut {
		t.Errorf("%+v", g)
	}
}

// B-3, N-9, N-10: route patterns as the frameworks write them.
func TestRouteRegexpForms(t *testing.T) {
	for pattern, paths := range map[string][2][]string{
		"report/<str:name>/":            {{"/report/x/", "/app/report/x"}, {"/report/", "/xreport/x"}},
		"^report/(?P<name>[^/]+)/$":     {{"/report/x/", "/app/report/x"}, {"/report/x/y"}},
		"lookup/{host}":                 {{"/lookup/example.com"}, {"/lookup"}},
		"/":                             {{"/", ""}, {"/admin/other", "/x"}},
		"/files/<path:f>":               {{"/files/a/b/c"}, {"/files/"}},
		"/files/{p:path}":               {{"/files/a/b"}, {"/other/a"}},
		"/files/*":                      {{"/files/a/b/c"}, {"/other/a"}},
		"/users/{id}":                   {{"/api/users/5"}, {"/xusers/5"}},
		"/wp-json/shop/v1/(?P<id>\\d+)": {{"/wp-json/shop/v1/12"}, {"/wp-json/shop/v1/x"}},
	} {
		re := routeRegexp(pattern)
		if re == nil {
			t.Errorf("%s: no expression", pattern)
			continue
		}
		for _, p := range paths[0] {
			if !re.MatchString(p) {
				t.Errorf("%s should match %q (%s)", pattern, p, re)
			}
		}
		for _, p := range paths[1] {
			if re.MatchString(p) {
				t.Errorf("%s should not match %q (%s)", pattern, p, re)
			}
		}
	}
}

// B-3: a Django route without a leading / is matched; N-10: the path as
// sent is tried as well as the routed one; HEAD reaches a GET route.
func TestJudgeRoutes(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	route := func(method, pattern string) []engine.RouteRef {
		return []engine.RouteRef{{Model: "m", Framework: "django", Method: method, Pattern: pattern, File: "urls.py", Line: 1}}
	}
	judge := func(sinks []CodeSink, r AccessRecord) Judgment {
		return NewJudge(Build(sinks, nil), ss).Judge(NewMatcher(ss).Match(Normalize(r)))
	}
	sink := []CodeSink{{Rule: "py-sqli", CWE: "CWE-89", Severity: "critical", Path: "v.py", Line: 3, Routes: route("", "report/<str:name>/")}}
	g := judge(sink, AccessRecord{Method: "GET", Path: "/report/x/", Query: "h=marker-one"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload {
		t.Errorf("Django route without /: %+v", g)
	}
	two := []CodeSink{{Rule: "py-sqli", CWE: "CWE-89", Severity: "critical", Path: "v.py", Line: 3, Routes: route("get", "/view/<a>/<b>")}}
	if g = judge(two, AccessRecord{Method: "GET", Path: "/view/./page"}); len(g.Candidates) != 1 {
		t.Errorf("the path as sent (/view/./page) not tried: %+v", g)
	}
	if g = judge(two, AccessRecord{Method: "HEAD", Path: "/view/a/b"}); len(g.Candidates) != 1 {
		t.Errorf("HEAD to a GET route: %+v", g)
	}
	root := []CodeSink{{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 1, Routes: route("get", "/")}}
	if g = judge(root, AccessRecord{Method: "GET", Path: "/admin/other", Query: "id=marker-one"}); len(g.Candidates) != 0 {
		t.Errorf("the root route reached by /admin/other: %+v", g)
	}
}

// B-3, N-11: a route whose pattern makes no expression, or a route list
// the engine cut: the sink's class hits are unanchored, never noise.
func TestJudgeUnmatchedRoutes(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	ref := func(p string) []engine.RouteRef {
		return []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: p, File: "a.js", Line: 1}}
	}
	for name, sink := range map[string]CodeSink{
		"pattern not an expression": {Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 2, Routes: ref("/x/(")},
		"routes truncated":          {Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 2, Routes: ref("/known"), RoutesTruncated: true},
	} {
		g := NewJudge(Build([]CodeSink{sink}, nil), ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/other", Query: "q=marker-one"})))
		if len(g.Unanchored) != 1 || g.Unanchored[0].Signature != "class-marker" || len(g.Noise) != 1 || g.Noise[0].Signature != "cve-marker" {
			t.Errorf("%s: %+v, want the class hit unanchored (the CVE one, not installed, noise)", name, g)
		}
	}
}

// Package names (PEP 503 for PyPI); a CVE matched whose applies_to does
// not list this package: a candidate, version unknown.
func TestJudgePackages(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	judge := func(p PackageVuln) Judgment {
		return NewJudge(Build(nil, []PackageVuln{p}), ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	}
	g := judge(PackageVuln{Source: "/srv/requirements.txt", Ecosystem: "PyPI", Package: "marker-pkg-core", Version: "1.0", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || g.Candidates[0].VersionUnknown {
		t.Errorf("PEP 503 name: %+v", g)
	}
	g = judge(PackageVuln{Source: "/srv/requirements.txt", Ecosystem: "PyPI", Package: "marker-fork", Version: "1.0", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("CVE matched, package not in applies_to: %+v", g)
	}
	g = judge(PackageVuln{Source: "/srv/requirements.txt", Ecosystem: "PyPI", Package: "marker-pkg-core", Version: "2.1", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 0 {
		t.Errorf("fixed version: %+v", g)
	}
	// An advisory of several CVEs: one entry, and a signature for any of them finds it.
	s := Build(nil, []PackageVuln{{Source: "/srv/requirements.txt", Ecosystem: "PyPI", Package: "marker-pkg-core", Version: "1.0", ID: "GHSA-mark-0000-0000", CVE: "CVE-2099-0001", CVEs: []string{"CVE-2099-0001", "CVE-2099-0007"}}})
	g = NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	if len(s.Entries) != 1 || len(g.Candidates) != 1 {
		t.Errorf("multi-CVE advisory: %+v %+v", s.Entries, g)
	}
}
