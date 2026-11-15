package detect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

func TestBuildSurface(t *testing.T) {
	get := engine.RouteRef{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/ping", Handler: "ping", File: "a.js", Line: 5}
	post := get
	post.Method, post.Pattern, post.Line = "post", "/api/ping", 6
	code := []CodeSink{
		{Rule: "js-cmdi", CWE: "CWE-78", Severity: "critical", Path: "a.js", Line: 3, Routes: []engine.RouteRef{get}},
		{Rule: "js-cmdi", CWE: "CWE-78", Severity: "critical", Path: "a.js", Line: 3, Routes: []engine.RouteRef{post, get}},
		{Rule: "php-sqli", CWE: "CWE-89", Severity: "warning", Path: "b.php", Line: 9},
		{Rule: "", Path: "c.php"}, // no rule: left out
	}
	pkgs := []PackageVuln{
		{Source: "os", Ecosystem: "Debian", Package: "openssl", Version: "3.0.1", ID: "CVE-2024-0001"},
		{Source: "os", Ecosystem: "Debian", Package: "openssl", Version: "3.0.1", ID: "CVE-2024-0001", KEV: true, KEVSince: "2024-05-01"},
		{Source: "/srv/app/composer.lock", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Version: "7.0.0", ID: "GHSA-xxxx", CVE: "CVE-2022-0002"},
		{Source: "/srv/b/composer.lock", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Version: "7.0.0", ID: "GHSA-xxxx"},
	}
	s := Build(code, pkgs)
	if len(s.Entries) != 5 {
		t.Fatalf("%d entries, want 5: %+v", len(s.Entries), s.Entries)
	}
	if e := s.Entries[0]; e.ID != "pkg:CVE-2024-0001:openssl@3.0.1" || !e.KEV || e.KEVSince != "2024-05-01" || e.CVE != "CVE-2024-0001" {
		t.Errorf("first entry %+v, want the KEV one first and merged", e)
	}
	byID := map[string]Entry{}
	for _, e := range s.Entries {
		byID[e.ID] = e
	}
	c := byID["code:js-cmdi:a.js:3"]
	if len(c.Routes) != 2 || c.Coverage != CoverRoutes || c.Payload != "cmdi" {
		t.Errorf("merged sink %+v: want 2 routes, coverage routes, payload cmdi", c)
	}
	if b := byID["code:php-sqli:b.php:9"]; b.Coverage != CoverNoRoute || b.Payload != "sqli" || b.Routes != nil {
		t.Errorf("sink without routes %+v", b)
	}
	for _, id := range []string{"pkg:CVE-2022-0002:guzzlehttp/guzzle@7.0.0#/srv/app/composer.lock", "pkg:GHSA-xxxx:guzzlehttp/guzzle@7.0.0#/srv/b/composer.lock"} {
		if e, ok := byID[id]; !ok || e.Coverage != CoverSignature {
			t.Errorf("%s: %+v (present %v), want coverage needs_signature", id, e, ok)
		}
	}
	if len(s.Caveats) != 3 || s.Caveats[0] != RoutesMeaning || s.Caveats[1] != NoRoutesMeaning || s.Caveats[2] != PatternMeaning {
		t.Errorf("caveats %v", s.Caveats)
	}
}

func TestBuildSurfaceEmptyAndCapped(t *testing.T) {
	b, _ := json.Marshal(Build(nil, nil))
	if !strings.Contains(string(b), `"entries":[]`) {
		t.Errorf("empty surface JSON %s: want an empty list, not null", b)
	}
	var code []CodeSink
	for i := 0; i < MaxEntries+7; i++ {
		code = append(code, CodeSink{Rule: "r", Path: "a.php", Line: i + 1})
	}
	kev := PackageVuln{Package: "p", ID: "CVE-1", KEV: true}
	s := Build(code, []PackageVuln{kev})
	if len(s.Entries) != MaxEntries || s.TruncatedCode != 8 || s.TruncatedPackages != 0 {
		t.Errorf("%d entries, %d+%d truncated; want %d and 8+0", len(s.Entries), s.TruncatedCode, s.TruncatedPackages, MaxEntries)
	}
	if !s.Entries[0].KEV {
		t.Error("the KEV entry was cut")
	}
}

func TestPayloadClass(t *testing.T) {
	for cwe, want := range map[string]string{"CWE-89": "sqli", " cwe-78 ": "cmdi", "CWE-22": "path", "CWE-1": "other", "": "other"} {
		if got := PayloadClass(cwe); got != want {
			t.Errorf("PayloadClass(%q) = %q, want %q", cwe, got, want)
		}
	}
}

// N-1: a sink whose only routes are hooks (a shortcode: no URL) is not one
// requests can be matched to.
func TestBuildSurfaceHookOnly(t *testing.T) {
	hook := engine.RouteRef{Model: "wp-shortcode", Framework: "wordpress", Handler: "box", File: "a.php", Line: 2}
	rest := engine.RouteRef{Model: "wp-rest-route", Framework: "wordpress", Pattern: "/wp-json/shop/v1/item", Handler: "box", File: "a.php", Line: 3}
	s := Build([]CodeSink{
		{Rule: "php-sqli", Path: "a.php", Line: 5, Routes: []engine.RouteRef{hook}},
		{Rule: "php-sqli", Path: "a.php", Line: 9, Routes: []engine.RouteRef{hook, rest}, RoutesTruncated: true},
	}, nil)
	byID := map[string]Entry{}
	for _, e := range s.Entries {
		byID[e.ID] = e
	}
	if e := byID["code:php-sqli:a.php:5"]; e.Coverage != CoverNoRoute || len(e.Routes) != 1 {
		t.Errorf("hook only: %+v, want no_route with the hook kept", e)
	}
	if e := byID["code:php-sqli:a.php:9"]; e.Coverage != CoverRoutes || !e.RoutesTruncated {
		t.Errorf("hook and REST route: %+v, want routes and routes_truncated", e)
	}
}

// N-5: past MaxEntries the cut keeps KEV, then the more severe, whatever
// their kind; the counts say which kind lost how many.
func TestBuildSurfaceCutBySeverity(t *testing.T) {
	var code []CodeSink
	for i := 0; i < MaxEntries; i++ {
		code = append(code, CodeSink{Rule: "r", Severity: "warning", Path: "a.php", Line: i + 1})
	}
	pkgs := []PackageVuln{
		{Package: "p", Version: "1", ID: "CVE-1", Severity: "CRITICAL"},
		{Package: "q", Version: "1", ID: "CVE-2", Severity: "high"},
		{Package: "r", Version: "1", ID: "CVE-3", Severity: "low"},
		{Package: "s", Version: "1", ID: "CVE-4"},
	}
	s := Build(code, pkgs)
	if len(s.Entries) != MaxEntries || s.TruncatedCode != 2 || s.TruncatedPackages != 2 {
		t.Fatalf("%d entries, %d code and %d packages cut; want %d, 2, 2", len(s.Entries), s.TruncatedCode, s.TruncatedPackages, MaxEntries)
	}
	if s.Entries[0].ID != "pkg:CVE-1:p@1" || s.Entries[1].ID != "pkg:CVE-2:q@1" {
		t.Errorf("first entries %s, %s: want the critical and the high package", s.Entries[0].ID, s.Entries[1].ID)
	}
}

// S-2, S-3: two versions of one package are two entries; a GHSA id and the
// CVE it is known as are one, KEV.
func TestBuildSurfacePackageIdentity(t *testing.T) {
	s := Build(nil, []PackageVuln{
		{Source: "/srv/package-lock.json", Package: "lodash", Version: "4.17.15", ID: "CVE-2021-23337"},
		{Source: "/srv/package-lock.json", Package: "lodash", Version: "4.17.20", ID: "CVE-2021-23337"},
		{Source: "/srv/package-lock.json", Package: "lodash", Version: "4.17.15", ID: "GHSA-35jh-r3h4-6jhm", CVE: "CVE-2021-23337", KEV: true, KEVSince: "2024-01-01"},
	})
	if len(s.Entries) != 2 {
		t.Fatalf("%d entries, want 2: %+v", len(s.Entries), s.Entries)
	}
	e := s.Entries[0]
	if e.ID != "pkg:CVE-2021-23337:lodash@4.17.15#/srv/package-lock.json" || !e.KEV || e.KEVSince != "2024-01-01" ||
		e.Advisory != "CVE-2021-23337" || len(e.Aliases) != 1 || e.Aliases[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("merged entry %+v", e)
	}
	if s.Entries[1].Version != "4.17.20" || s.Entries[1].KEV {
		t.Errorf("other version %+v", s.Entries[1])
	}
}
