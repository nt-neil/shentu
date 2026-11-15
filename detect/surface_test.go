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
	if e := s.Entries[0]; e.ID != "pkg:CVE-2024-0001:openssl" || !e.KEV || e.KEVSince != "2024-05-01" || e.CVE != "CVE-2024-0001" {
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
	for _, id := range []string{"pkg:GHSA-xxxx:guzzlehttp/guzzle@/srv/app/composer.lock", "pkg:GHSA-xxxx:guzzlehttp/guzzle@/srv/b/composer.lock"} {
		if e, ok := byID[id]; !ok || e.Coverage != CoverSignature {
			t.Errorf("%s: %+v (present %v), want coverage needs_signature", id, e, ok)
		}
	}
	if len(s.Caveats) != 2 || s.Caveats[0] != RoutesMeaning || s.Caveats[1] != NoRoutesMeaning {
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
	if len(s.Entries) != MaxEntries || s.Truncated != 8 {
		t.Errorf("%d entries, %d truncated; want %d and 8", len(s.Entries), s.Truncated, MaxEntries)
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
