package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// suryHost is a made-up Debian 12 with sury's php8.3-fpm (example.test).
type suryHost struct {
	files map[string]string
	cmds  map[string]string
}

func (suryHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }
func (h suryHost) ReadFile(p string) ([]byte, error) {
	if s, ok := h.files[p]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}
func (h suryHost) ReadDir(p string) ([]string, error) {
	seen := map[string]bool{}
	for k := range h.files {
		if rest, ok := strings.CutPrefix(k, strings.TrimSuffix(p, "/")+"/"); ok {
			n, _, _ := strings.Cut(rest, "/")
			seen[n] = true
		}
	}
	if len(seen) == 0 {
		return nil, os.ErrNotExist
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
func (suryHost) Readlink(string) (string, error) { return "", os.ErrNotExist }
func (h suryHost) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if s, ok := h.cmds[strings.Join(argv, " ")]; ok {
		return hostenv.CmdResult{Stdout: []byte(s)}, nil
	}
	return hostenv.CmdResult{}, os.ErrNotExist
}

// kevOnly answers OSV with nothing and CISA's KEV catalog with one CVE.
type kevOnly struct{ cve string }

func (k kevOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"vulnerabilities":[]}`
	switch {
	case strings.Contains(r.URL.Path, "known_exploited"):
		body = `{"vulnerabilities":[{"cveID":"` + k.cve + `","vulnerabilityName":"Example PHP-FPM flaw","dateAdded":"2026-11-20"}]}`
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		var q struct{ Queries []any }
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		for i := range res {
			res[i] = map[string]any{}
		}
		b, _ := json.Marshal(map[string]any{"results": res})
		body = string(b)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// N-225-1: a KEV CVE of sury's php8.3-fpm, found by the upstream compare,
// is a critical KEV finding of the daily patrol, as OSV's are; on 20ddab0
// it reached the surface only, and the summary said 0 affected packages.
func TestPatrolKEVOfUpstreamPHP(t *testing.T) {
	lists := hostenv.AptListsDir + "/packages.example-php.test_php_dists_bookworm"
	t.Cleanup(tools.SetHostSourceForTest(suryHost{files: map[string]string{
		"/etc/os-release":        "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
		lists + "_InRelease":     "Origin: deb.sury.org\nLabel: PHP\n",
		lists + "_main_Packages": "Package: php8.3-fpm\nVersion: 8.3.9-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1\n",
	}, cmds: map[string]string{
		strings.Join([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, " "): "bash\t\t5.2.15-2+b7\tarm64\tii \n" +
			"php8.3-fpm\tphp8.3\t8.3.9-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1\tarm64\tii \n",
	}}))
	r, _, err := tools.PackageVulnsSurface(context.Background(), &http.Client{Transport: kevOnly{"CVE-2026-129291"}})
	if err != nil {
		t.Fatal(err)
	}
	var kev *finding
	for _, f := range osKEVFindings(r) {
		if f.Key == "kev:php8.3-fpm:CVE-2026-129291" {
			kev = &f
		}
	}
	if kev == nil || kev.Severity != "critical" {
		t.Errorf("no KEV finding for sury's php8.3-fpm: %v (actively_exploited %v)", kev, r["actively_exploited"])
	}
	if n, _ := r["affected_packages"].(int); n != 1 {
		t.Errorf("affected_packages %v, want 1", r["affected_packages"])
	}
	if n, _ := r["total_vulns"].(int); n == 0 {
		t.Errorf("total_vulns 0 with upstream-affected CVEs")
	}
}
