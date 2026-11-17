package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect"
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
		Exploited: []Exploit{{Package: "a/b", Version: "1.0", ID: "GHSA-2", CVE: "CVE-2024-9", Added: "2024-01-02"}}}})
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

// N-R1: two versions of one package in one lock file, both exploited: both
// are KEV.
func TestSurfaceAppsTwoVersionsKEV(t *testing.T) {
	apps := SurfaceApps([]AppResult{{Path: "/srv/package-lock.json", Ecosystem: "npm",
		Affected: []AppHit{
			{Package: "lodash", Version: "4.17.10", IDs: []string{"GHSA-p6mc-m468-83gw"}},
			{Package: "lodash", Version: "4.17.4", IDs: []string{"GHSA-p6mc-m468-83gw"}},
		},
		Exploited: []Exploit{
			{Package: "lodash", Version: "4.17.10", ID: "GHSA-p6mc-m468-83gw", CVE: "CVE-2020-8203", Added: "2024-01-01"},
			{Package: "lodash", Version: "4.17.4", ID: "GHSA-p6mc-m468-83gw", CVE: "CVE-2020-8203", Added: "2024-01-01"},
		}}})
	if len(apps) != 2 {
		t.Fatalf("%d entries, want 2: %+v", len(apps), apps)
	}
	for _, a := range apps {
		if !a.KEV || a.CVE != "CVE-2020-8203" {
			t.Errorf("%s %s: %+v, want kev", a.Package, a.Version, a)
		}
	}
}

// S-C: lock files' dependencies carry no severity.
func TestSurfaceAppsNoSeverity(t *testing.T) {
	apps := SurfaceApps([]AppResult{{Path: "/srv/composer.lock", Affected: []AppHit{{Package: "a/b", Version: "1", IDs: []string{"GHSA-1"}}}}})
	if len(apps) != 1 || apps[0].Severity != "" {
		t.Errorf("%+v: want one entry, no severity", apps)
	}
}

// S-B: a GHSA id and a PYSEC id OSV said are the same CVE are one entry of
// the surface; an id with no CVE stays apart. The CVEs never reach the
// JSON the model reads.
func TestSurfaceAppsAliases(t *testing.T) {
	r := AppResult{Path: "/srv/app/requirements.txt", Ecosystem: "PyPI",
		Affected: []AppHit{{Package: "django", Version: "3.2.0", IDs: []string{"GHSA-aaaa", "PYSEC-2021-1", "PYSEC-2021-9"}}},
		cves:     map[string][]string{"GHSA-aaaa": {"CVE-2021-33203"}, "PYSEC-2021-1": {"CVE-2021-33571", "CVE-2021-33203"}}}
	apps := SurfaceApps([]AppResult{r})
	if len(apps) != 3 || apps[0].CVE != "CVE-2021-33203" || apps[1].CVE != "CVE-2021-33203" || apps[2].CVE != "" {
		t.Fatalf("%+v", apps)
	}
	s := detect.Build(nil, apps)
	if len(s.Entries) != 2 {
		t.Fatalf("%d entries, want 2: %+v", len(s.Entries), s.Entries)
	}
	var merged detect.Entry
	for _, e := range s.Entries {
		if e.CVE == "CVE-2021-33203" {
			merged = e
		}
	}
	// The advisory's other CVE is an alias too (review 1 of #87): a
	// signature written for CVE-2021-33571 finds this entry.
	if merged.Advisory != "GHSA-aaaa" || strings.Join(merged.Aliases, ",") != "PYSEC-2021-1,CVE-2021-33571" {
		t.Errorf("merged entry %+v", merged)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "CVE-2021-33571") {
		t.Errorf("aliases in the model's JSON: %s", b)
	}
}

// #84 S: an advisory with several CVEs, KEV through the higher one, and
// another id of the same vulnerability: one entry, KEV.
func TestSurfaceAppsKEVSameCVERule(t *testing.T) {
	r := AppResult{Path: "/srv/requirements.txt", Ecosystem: "PyPI",
		Affected:  []AppHit{{Package: "django", Version: "3.2.0", IDs: []string{"GHSA-kev", "PYSEC-1"}}},
		Exploited: []Exploit{{Package: "django", Version: "3.2.0", ID: "GHSA-kev", CVE: "CVE-2021-0002", Added: "2024-01-01"}},
		cves:      map[string][]string{"GHSA-kev": {"CVE-2021-0001", "CVE-2021-0002"}, "PYSEC-1": {"CVE-2021-0001"}}}
	s := detect.Build(nil, SurfaceApps([]AppResult{r}))
	if len(s.Entries) != 1 || !s.Entries[0].KEV || s.Entries[0].CVE != "CVE-2021-0001" || s.Entries[0].KEVCVE != "CVE-2021-0002" {
		t.Errorf("%+v: want one KEV entry", s.Entries)
	}
}
