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
ecosystem = "Packagist"
package = "Marker/Pkg-Core"
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
	if !q.Cut || total > MaxParamsText+2*MinValueKept {
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
		re, _ := routeRegexp(pattern)
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
		"pattern not an expression": {Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 2, Routes: ref("/x/(?P<")},
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
	g := judge(PackageVuln{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/pkg-core", Version: "1.0", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || g.Candidates[0].VersionUnknown {
		t.Errorf("Packagist name, case: %+v", g)
	}
	for _, c := range [][3]string{{"PyPI", "Marker_Pkg.Core", "marker-pkg-core"}, {"pypi", "a--b", "A._b"}, {"Packagist", "Marker/X", "marker/x"}} {
		if !samePackage(c[0], c[1], c[2]) {
			t.Errorf("%s: %s and %s are one package", c[0], c[1], c[2])
		}
	}
	if samePackage("npm", "Marker", "marker") || samePackage("PyPI", "marker-a", "marker-b") {
		t.Error("different packages taken as one")
	}
	g = judge(PackageVuln{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/fork", Version: "1.0", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("CVE matched, package not in applies_to: %+v", g)
	}
	g = judge(PackageVuln{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/pkg-core", Version: "2.1", ID: "CVE-2099-0007"})
	if len(g.Candidates) != 0 {
		t.Errorf("fixed version: %+v", g)
	}
	// An advisory of several CVEs: one entry, and a signature for any of them finds it.
	s := Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/pkg-core", Version: "1.0", ID: "GHSA-mark-0000-0000", CVE: "CVE-2099-0001", CVEs: []string{"CVE-2099-0001", "CVE-2099-0007"}}})
	g = NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	if len(s.Entries) != 1 || len(g.Candidates) != 1 {
		t.Errorf("multi-CVE advisory: %+v %+v", s.Entries, g)
	}
}

// Review 2 of #87, N-A: padding before a value does not push it out: a
// text cut keeps its end, a value past the parameters' bound keeps
// MinValueKept; a cut request with no candidate is Unknown.
func TestPaddingKeepsTail(t *testing.T) {
	m := NewMatcher(loadSigs(t, markerSigs))
	pad := strings.Repeat("a", MaxNormalized+2000)
	for name, query := range map[string]string{
		"one long value":          "k=" + pad + "marker-one",
		"values before it":        "p1=" + pad + "&p2=" + pad + "&p3=" + pad + "&k=marker-one",
		"the whole query is long": strings.Repeat("p=a&", MaxParamsText/4) + "k=marker-one",
	} {
		q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: query})
		if r := m.Match(q); !q.Cut || len(r.Hits) == 0 {
			t.Errorf("%s: cut %v, hits %+v: the value after the padding was lost", name, q.Cut, r.Hits)
		}
	}
	if got := headTail("abcdefghij", 8); len(got) != 8 || !strings.HasPrefix(got, "abcde") || !strings.HasSuffix(got, "ij") {
		t.Errorf("headTail %q", got)
	}
	// Lower-casing can lengthen a text (U+023A is 2 bytes, its lower case 3): cut again.
	q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: "k=" + strings.Repeat("Ⱥ", MaxNormalized/2-10)})
	if v := q.Params["k"][0]; len(v) > MaxNormalized || !q.Cut {
		t.Errorf("lower-cased value of %d bytes (bound %d), cut %v", len(v), MaxNormalized, q.Cut)
	}
	j := NewJudge(Build(nil, nil), nil)
	if g := j.Judge(MatchResult{Request: Request{Cut: true}}); !g.Unknown {
		t.Errorf("cut, no candidate: %+v, want unknown", g)
	}
	if g := j.Judge(MatchResult{Request: Request{}}); g.Unknown {
		t.Errorf("not cut: %+v", g)
	}
}

// Review 2, N-B: patterns that compiled but never matched; a one-segment
// placeholder does not take two.
func TestRouteRegexpForms2(t *testing.T) {
	for pattern, paths := range map[string][2][]string{
		"/users/:id?":       {{"/users", "/users/5", "/api/users/5/"}, {"/users/5/x"}},
		"/user/:id(\\d+)":   {{"/user/5"}, {"/user", "/user/5/x"}},
		"^article/\\d+/$":   {{"/article/12/", "/blog/article/12"}, {"/article/x/"}},
		"^files/.*$":        {{"/files/a/b"}, {"/other/a"}},
		"/users/{id}":       {{"/users/5"}, {"/users/a/b"}},
		"report/<str:name>": {{"/report/x"}, {"/report/a/b"}},
		"/api/:id/edit":     {{"/api/7/edit"}, {"/api/7/8/edit"}},
	} {
		re, _ := routeRegexp(pattern)
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

// Review 2, N-C: the root route's mount prefix is not known: L1 only on
// the root, its class's hits elsewhere unanchored. S: a signature's GET
// route takes HEAD.
func TestRootRouteAndHead(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	root := []CodeSink{{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 1,
		Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/", File: "a.js", Line: 1}}}}
	j := NewJudge(Build(root, nil), ss)
	g := j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/api/", Query: "id=marker-one"})))
	if len(g.Candidates) != 0 || len(g.Unanchored) != 1 || g.Unanchored[0].Signature != "class-marker" {
		t.Errorf("root route, request under a mount prefix: %+v", g)
	}
	if g = j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/"}))); len(g.Candidates) != 1 {
		t.Errorf("the root itself: %+v", g)
	}
	m := NewMatcher(loadSigs(t, `
[[signature]]
id = "get-route"
title = "t"
class = "path"
source = "shentu"
license = "Apache-2.0"
[[signature.route]]
methods = ["GET"]
path = "/marker/route"
`))
	if r := m.Match(Normalize(AccessRecord{Method: "HEAD", Path: "/marker/route"})); len(r.Hits) != 1 {
		t.Errorf("HEAD to a signature's GET route: %+v", r.Hits)
	}
	if r := m.Match(Normalize(AccessRecord{Method: "POST", Path: "/marker/route"})); len(r.Hits) != 0 {
		t.Errorf("POST to a GET route: %+v", r.Hits)
	}
}

// Review 3 of #87, N-D: a cut text's start and end are matched apart: an
// expression never joins them across the cut; a cut mark the request
// sent itself is a space.
func TestCutSeamNotMatched(t *testing.T) {
	m := NewMatcher(loadSigs(t, `
[[signature]]
id = "two-markers"
title = "t"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
regex = 'marker-a.*marker-b|marker-a[^q]+marker-b'
`))
	pad := strings.Repeat("z", 2*MaxNormalized)
	for name, query := range map[string]string{
		"one value":      "k=marker-a" + pad + "marker-b",
		"the parameters": "k=marker-a" + pad + "&p2=" + pad + "&p3=" + pad + "&j=marker-b",
	} {
		q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: query})
		if r := m.Match(q); !q.Cut || len(r.Hits) != 0 {
			t.Errorf("%s: cut %v, hits %+v: matched across the cut", name, q.Cut, r.Hits)
		}
	}
	if r := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "k=marker-a" + strings.Repeat("z", 100) + "marker-b"})); len(r.Hits) != 1 {
		t.Errorf("not cut: %+v", r.Hits)
	}
	if q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: "k=a%1fb"}); q.Params["k"][0] != "a\uFFFDb" || !q.Encoded {
		t.Errorf("a sent cut mark: %q, encoded %v (want said as evasion)", q.Params["k"][0], q.Encoded)
	}
	if ex := excerptAt("ab"+cutMark+"cd", 0, 2); strings.Contains(ex, cutMark) || !strings.Contains(ex, "…") {
		t.Errorf("excerpt %q", ex)
	}
}

// Review 3, N-E: expressions are taken whole and loose; a route starting
// with a placeholder is anchored and loose, as the root.
func TestRouteRegexpForms3(t *testing.T) {
	for pattern, c := range map[string]struct {
		yes, no []string
		loose   bool
	}{
		"article/\\d+/":         {[]string{"/article/12/", "/article/12", "/blog/article/12"}, []string{"/article/x/"}, true},
		"^foo/$|^bar/$":         {[]string{"/foo/", "/bar/", "/app/foo/"}, []string{"/baz/", "/foo/x/"}, true},
		"/user/:id(\\d+(?:x)?)": {[]string{"/user/5"}, []string{"/user/5/6"}, false},
		"/:id?":                 {[]string{"/", "/x"}, []string{"/a/x"}, true},
		"/{slug}":               {[]string{"/x"}, []string{"/a/x"}, true},
		"/":                     {[]string{"/"}, []string{"/a"}, true},
		"/users/{id}":           {[]string{"/api/users/5"}, []string{"/users/5/6"}, false},
	} {
		re, loose := routeRegexp(pattern)
		if re == nil || loose != c.loose {
			t.Errorf("%s: %v loose %v, want loose %v", pattern, re, loose, c.loose)
			continue
		}
		for _, p := range c.yes {
			if !re.MatchString(p) {
				t.Errorf("%s should match %q (%s)", pattern, p, re)
			}
		}
		for _, p := range c.no {
			if re.MatchString(p) {
				t.Errorf("%s should not match %q (%s)", pattern, p, re)
			}
		}
	}
}

// Review 3: Unknown is "cut, and no L2"; it says what was cut and what
// the cut may hide.
func TestUnknownSaysWhat(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	sinks := []CodeSink{
		{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 1,
			Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/marker/ping", File: "a.js", Line: 1}}},
		{Rule: "php-path", CWE: "CWE-22", Severity: "warning", Path: "b.php", Line: 2},
	}
	j := NewJudge(Build(sinks, nil), ss)
	pad := strings.Repeat("z", MaxNormalized+100)
	g := j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/marker/ping", Query: "k=" + pad})))
	if !g.Unknown || len(g.Candidates) != 1 || strings.Join(g.HiddenSinks, ",") != "code:js-sqli:a.js:1,code:php-path:b.php:2" ||
		strings.Join(g.HiddenClasses, ",") != "path,sqli" || len(g.CutParts) != 1 || g.CutParts[0].Part != "param" || g.CutParts[0].Param != "k" {
		t.Errorf("cut, L1 only: %+v", g)
	}
	g = j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/marker/ping", Query: "k=" + pad + "&j=marker-one"})))
	if !g.Cut || g.Unknown || len(g.HiddenSinks) != 0 {
		t.Errorf("cut, with a candidate at L2: %+v", g)
	}
}

// Review 3, S: an ecosystem's case does not matter.
func TestEcosystemCase(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	g := NewJudge(Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "PACKAGIST", Package: "MARKER/PKG-CORE", Version: "1.0", ID: "CVE-2099-0007"}}), ss).
		Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	if len(g.Candidates) != 1 || g.Candidates[0].VersionUnknown {
		t.Errorf("PACKAGIST, MARKER/PKG-CORE: %+v", g)
	}
}

// Review 4 of #87, N-F: a path cut may join far parts into a route: L1 at
// most, the hit unanchored, the judgment Unknown.
func TestPathCutRouteL1(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	sinks := []CodeSink{{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: 1,
		Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/marker/end", File: "a.js", Line: 1}}}}
	j := NewJudge(Build(sinks, nil), ss)
	path := "/" + strings.Repeat("z", 2*MaxNormalized) + "/marker/end"
	g := j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: path, Query: "id=marker-one"})))
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelRoute || !g.Unknown || len(g.Unanchored) != 1 {
		t.Errorf("path cut, route reached: %+v", g)
	}
	g = j.Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/marker/end", Query: "id=marker-one"})))
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || g.Unknown {
		t.Errorf("not cut: %+v", g)
	}
}

// Review 4, N-G: an expression starting with / and holding . (Express's
// /files/(.*), WordPress's (?P<p>.+)); Express's ? is an expression.
func TestRouteRegexpForms4(t *testing.T) {
	for pattern, c := range map[string]struct{ yes, no []string }{
		"/files/(.*)":              {[]string{"/files/a/b", "/app/files/a"}, []string{"/other/a"}},
		"/wp-json/ns/v1/(?P<p>.+)": {[]string{"/wp-json/ns/v1/x", "/blog/wp-json/ns/v1/x/y"}, []string{"/wp-json/ns/v2/x"}},
		"/ab?cd":                   {[]string{"/acd", "/abcd"}, []string{"/abbcd"}},
	} {
		re, loose := routeRegexp(pattern)
		if re == nil || !loose {
			t.Errorf("%s: %v loose %v", pattern, re, loose)
			continue
		}
		for _, p := range c.yes {
			if !re.MatchString(p) {
				t.Errorf("%s should match %q (%s)", pattern, p, re)
			}
		}
		for _, p := range c.no {
			if re.MatchString(p) {
				t.Errorf("%s should not match %q (%s)", pattern, p, re)
			}
		}
	}
}

// Review 4: HiddenSinks lists the sinks of no known route too, at most
// MaxHidden, and says how many more.
func TestHiddenSinksMore(t *testing.T) {
	var sinks []CodeSink
	for i := 0; i < MaxHidden+4; i++ {
		sinks = append(sinks, CodeSink{Rule: "php-path", CWE: "CWE-22", Severity: "warning", Path: "b.php", Line: i + 1})
	}
	j := NewJudge(Build(sinks, nil), nil)
	g := j.Judge(MatchResult{Request: Request{Cut: true}})
	if !g.Unknown || len(g.HiddenSinks) != MaxHidden || g.HiddenSinksMore != 4 || strings.Join(g.HiddenClasses, ",") != "path" {
		t.Errorf("%d sinks of no route: %d listed, %d more, classes %v", len(sinks), len(g.HiddenSinks), g.HiddenSinksMore, g.HiddenClasses)
	}
}
