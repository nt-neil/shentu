package detect

import (
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

const judgeSigs = `
[[signature]]
id = "c-sqli"
title = "class sqli"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
regex = '\bunion\b\s+select\b'

[[signature]]
id = "c-cmdi"
title = "class cmdi"
class = "cmdi"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
contains = [";id", "$(id)"]

[[signature]]
id = "cve-guzzle"
title = "a CVE of guzzle"
class = "ssrf"
cves = ["CVE-2022-0002"]
source = "shentu"
license = "Apache-2.0"
[[signature.applies_to]]
ecosystem = "Packagist"
package = "guzzlehttp/guzzle"
versions = "<7.4.5"
[[signature.match]]
part = "param"
param = "url"
contains = ["169.254.169.254"]

[[signature]]
id = "cve-absent"
title = "a CVE this host has not"
class = "path"
cves = ["CVE-2099-0001"]
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
contains = ["../"]
`

func judgeSurface() Surface {
	ping := engine.RouteRef{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/ping/:host", Handler: "ping", File: "a.js", Line: 5}
	return Build([]CodeSink{
		{Rule: "js-cmdi", CWE: "CWE-78", Severity: "critical", Path: "a.js", Line: 3, Routes: []engine.RouteRef{ping}},
		{Rule: "php-sqli", CWE: "CWE-89", Severity: "warning", Path: "b.php", Line: 9}, // no route
	}, []PackageVuln{
		{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Version: "7.0.0", ID: "GHSA-xxxx", CVE: "CVE-2022-0002"},
	})
}

func judge(t *testing.T, r AccessRecord) Judgment {
	t.Helper()
	ss := loadSigs(t, judgeSigs)
	j := NewJudge(judgeSurface(), ss)
	return j.Judge(NewMatcher(ss).Match(Normalize(r)))
}

func TestJudge(t *testing.T) {
	// The route alone: L1.
	g := judge(t, AccessRecord{Method: "GET", Path: "/api/ping/example.com"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelRoute || g.Candidates[0].Route == nil || g.Candidates[0].Entry != "code:js-cmdi:a.js:3" {
		t.Errorf("route only: %+v", g)
	}
	// The route with the sink's class: L2.
	g = judge(t, AccessRecord{Method: "GET", Path: "/ping/x", Query: "h=a;id"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || len(g.Candidates[0].Hits) != 1 {
		t.Errorf("route and payload: %+v", g)
	}
	// The route with another class: L1, and the hit is noise.
	g = judge(t, AccessRecord{Method: "GET", Path: "/ping/x", Query: "h=1 union select 2"})
	if len(g.Candidates) != 1 || g.Candidates[0].Level != LevelRoute {
		t.Errorf("route, other class: %+v", g)
	}
	// Another method than the route's: nothing.
	if g = judge(t, AccessRecord{Method: "POST", Path: "/ping/x"}); len(g.Candidates) != 0 {
		t.Errorf("POST to a GET route: %+v", g)
	}
	// A class with a sink but no known route: unanchored, not a candidate.
	g = judge(t, AccessRecord{Method: "GET", Path: "/b.php", Query: "q=1 union select 2"})
	if len(g.Candidates) != 0 || len(g.Unanchored) != 1 || len(g.Noise) != 0 {
		t.Errorf("no_route sink: %+v", g)
	}
	// A package's CVE, installed version in range: L2.
	g = judge(t, AccessRecord{Method: "GET", Path: "/fetch", Query: "url=http://169.254.169.254/latest"})
	if len(g.Candidates) != 1 || g.Candidates[0].Entry != "pkg:CVE-2022-0002:guzzlehttp/guzzle@7.0.0#/srv/composer.lock" || g.Candidates[0].Level != LevelPayload {
		t.Errorf("package CVE: %+v", g)
	}
	// A CVE this host has not: noise, never a candidate.
	g = judge(t, AccessRecord{Method: "GET", Path: "/x", Query: "f=../../a"})
	if len(g.Candidates) != 0 || len(g.Noise) != 1 || g.Noise[0].Signature != "cve-absent" {
		t.Errorf("absent CVE: %+v", g)
	}
}

// The installed version out of the signature's range: not a candidate.
func TestJudgeVersionRange(t *testing.T) {
	ss := loadSigs(t, judgeSigs)
	s := Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Version: "7.5.0", ID: "CVE-2022-0002"}})
	g := NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "url=169.254.169.254"})))
	if len(g.Candidates) != 0 || len(g.Noise) != 1 {
		t.Errorf("7.5.0, fixed: %+v", g)
	}
	s = Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Version: "dev-main", ID: "CVE-2022-0002"}})
	g = NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "url=169.254.169.254"})))
	if len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("a version not compared: %+v", g)
	}
}

func TestRouteRegexp(t *testing.T) {
	for pattern, paths := range map[string][2][]string{
		"/users/{id}":                   {{"/users/5", "/api/users/5", "/users/5/"}, {"/users", "/users/5/x"}},
		"/run/<cmd>":                    {{"/run/ls"}, {"/run/"}},
		"/api/:id/edit":                 {{"/v1/api/7/edit"}, {"/api/7"}},
		"/wp-json/shop/v1/(?P<id>\\d+)": {{"/wp-json/shop/v1/12"}, {"/wp-json/shop/v1/x"}},
	} {
		re := routeRegexp(pattern)
		if re == nil {
			t.Errorf("%s: no expression", pattern)
			continue
		}
		for _, p := range paths[0] {
			if !re.MatchString(p) {
				t.Errorf("%s should match %s", pattern, p)
			}
		}
		for _, p := range paths[1] {
			if re.MatchString(p) {
				t.Errorf("%s should not match %s", pattern, p)
			}
		}
	}
	if routeRegexp("") != nil || routeRegexp("box") != nil {
		t.Error("a hook or a non-path pattern made a route")
	}
}
