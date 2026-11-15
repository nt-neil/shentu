package tools

import (
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

func TestSurfaceInputs(t *testing.T) {
	r := engine.RouteRef{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/x", File: "a.js", Line: 2}
	code := SurfaceCode([]CodeFinding{
		{Kind: "injection", Rule: "js-cmdi", CWE: "CWE-78", Severity: "critical", Path: "a.js", Line: 3, Routes: []engine.RouteRef{r}},
		{Kind: "webshell", Path: "b.php"},
	})
	if len(code) != 1 || code[0].Rule != "js-cmdi" || len(code[0].Routes) != 1 {
		t.Errorf("code sinks %+v", code)
	}
	apps := SurfaceApps([]AppResult{{Path: "/srv/composer.lock", Ecosystem: "Packagist",
		Affected:  []AppHit{{Package: "a/b", Version: "1.0", IDs: []string{"GHSA-1", "GHSA-2"}}},
		Exploited: []Exploit{{Package: "a/b", ID: "GHSA-2", CVE: "CVE-2024-9", Added: "2024-01-02"}}}})
	if len(apps) != 2 || apps[0].KEV || !apps[1].KEV || apps[1].CVE != "CVE-2024-9" || apps[1].Source != "/srv/composer.lock" {
		t.Errorf("app vulns %+v", apps)
	}
}
