package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

func TestSurfaceInputs(t *testing.T) {
	r := engine.RouteRef{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/x", File: "a.js", Line: 2}
	code := SurfaceCode([]CodeFinding{
		{Kind: "injection", Rule: "js-cmdi", CWE: "CWE-78", Severity: "critical", Path: "a.js", Line: 3, Routes: []engine.RouteRef{r}, RoutesTruncated: true},
		{Kind: "webshell", Path: "b.php"},
	})
	if len(code) != 1 || code[0].Rule != "js-cmdi" || len(code[0].Routes) != 1 || !code[0].RoutesTruncated {
		t.Errorf("code sinks %+v", code)
	}
	apps := SurfaceApps([]AppResult{{Path: "/srv/composer.lock", Ecosystem: "Packagist",
		Affected:  []AppHit{{Package: "a/b", Version: "1.0", IDs: []string{"GHSA-1", "GHSA-2"}}},
		Exploited: []Exploit{{Package: "a/b", ID: "GHSA-2", CVE: "CVE-2024-9", Added: "2024-01-02"}}}})
	if len(apps) != 2 || apps[0].KEV || !apps[1].KEV || apps[1].CVE != "CVE-2024-9" || apps[1].Source != "/srv/composer.lock" {
		t.Errorf("app vulns %+v", apps)
	}
}

// N-3: the routes go to detect, not into the JSON the model reads.
func TestCodeFindingJSONNoRoutes(t *testing.T) {
	r := engine.RouteRef{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/x", File: "a.js", Line: 2}
	b, err := json.Marshal(CodeAudit{Findings: []CodeFinding{{Kind: "injection", Rule: "js-cmdi", Path: "a.js", Line: 3,
		Routes: []engine.RouteRef{r}, RoutesTruncated: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "routes") || strings.Contains(string(b), "express-handler") {
		t.Errorf("code audit JSON carries routes: %s", b)
	}
}

// N-4: an exploited advisory past the five kept per package (or a package
// past the twenty kept) is still on the surface, KEV.
func TestSurfaceAppsExploitedPastCut(t *testing.T) {
	apps := SurfaceApps([]AppResult{{Path: "/srv/package-lock.json", Ecosystem: "npm",
		Affected: []AppHit{{Package: "lodash", Version: "4.17.15", IDs: []string{"GHSA-1", "GHSA-2", "GHSA-3", "GHSA-4", "GHSA-5"}}},
		Exploited: []Exploit{
			{Package: "lodash", Version: "4.17.15", ID: "GHSA-2", CVE: "CVE-2", Added: "2024-01-01"},
			{Package: "lodash", Version: "4.17.15", ID: "GHSA-7", CVE: "CVE-7", Added: "2024-02-02"},
			{Package: "gone", Version: "1.0.0", ID: "CVE-2023-1", CVE: "CVE-2023-1", Added: "2024-03-03"},
		}}})
	if len(apps) != 7 {
		t.Fatalf("%d entries, want 7: %+v", len(apps), apps)
	}
	kev := 0
	for _, a := range apps {
		if a.KEV {
			kev++
		}
	}
	if x := apps[5]; x.ID != "GHSA-7" || !x.KEV || x.Version != "4.17.15" || x.KEVSince != "2024-02-02" || x.Source != "/srv/package-lock.json" {
		t.Errorf("sixth %+v, want GHSA-7 restored as KEV", x)
	}
	if x := apps[6]; x.Package != "gone" || !x.KEV {
		t.Errorf("seventh %+v, want the package Affected left out", x)
	}
	if kev != 3 {
		t.Errorf("%d KEV entries, want 3 (GHSA-2 once)", kev)
	}
}
