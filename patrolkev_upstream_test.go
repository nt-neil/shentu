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

// kevOnly answers CISA's KEV catalog with one CVE, and OSV with osv's
// advisory ids per queried package name (their aliases in alias).
type kevOnly struct {
	cve   string
	osv   map[string]string // package name -> advisory id
	alias map[string]string // advisory id -> its CVE
}

func (k kevOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"vulnerabilities":[]}`
	switch {
	case strings.Contains(r.URL.Path, "known_exploited"):
		body = `{"vulnerabilities":[{"cveID":"` + k.cve + `","vulnerabilityName":"Example PHP-FPM flaw","dateAdded":"2026-11-20"}]}`
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		var q struct {
			Queries []struct {
				Package struct{ Name string }
			}
		}
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		for i, x := range q.Queries {
			res[i] = map[string]any{}
			if id, ok := k.osv[x.Package.Name]; ok {
				res[i]["vulns"] = []map[string]string{{"id": id}}
			}
		}
		b, _ := json.Marshal(map[string]any{"results": res})
		body = string(b)
	case strings.Contains(r.URL.Path, "/vulns/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		body = `{"id":"` + id + `","aliases":["` + k.alias[id] + `"]}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// suryDebian is a made-up Debian 12 with these sury packages ("name source version").
func suryDebian(pkgs ...string) suryHost {
	lists := hostenv.AptListsDir + "/packages.example-php.test_php_dists_bookworm"
	dpkg, index := "bash\t\t5.2.15-2+b7\tarm64\tii \n", ""
	for _, p := range pkgs {
		f := strings.Fields(p)
		v := f[2] + "-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1"
		dpkg += f[0] + "\t" + f[1] + "\t" + v + "\tarm64\tii \n"
		index += "Package: " + f[0] + "\nVersion: " + v + "\n\n"
	}
	return suryHost{files: map[string]string{
		"/etc/os-release":        "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
		lists + "_InRelease":     "Origin: deb.sury.org\nLabel: PHP\n",
		lists + "_main_Packages": index,
	}, cmds: map[string]string{
		strings.Join([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, " "): dpkg,
	}}
}

// upstreamAffected is each source's affected CVEs in third_party_upstream.
func upstreamAffected(t *testing.T, r map[string]any) map[string]map[string]bool {
	b, _ := json.Marshal(r["third_party_upstream"])
	var hits []struct {
		Source   string
		Affected []string
	}
	if err := json.Unmarshal(b, &hits); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	for _, h := range hits {
		for _, c := range h.Affected {
			if out[h.Source] == nil {
				out[h.Source] = map[string]bool{}
			}
			out[h.Source][c] = true
		}
	}
	return out
}

func kevKeys(r map[string]any) map[string]finding {
	out := map[string]finding{}
	for _, f := range osKEVFindings(r) {
		out[f.Key] = f
	}
	return out
}

// N-225-1: a KEV CVE of sury's php8.3-fpm, found by the upstream compare,
// is a critical KEV finding of the daily patrol, as OSV's are; on 20ddab0
// it reached the surface only, and the summary said 0 affected packages.
// N-225-2: counted, and alerted, once per source package and CVE: OSV's
// DSA for php8.3 (its alias the KEV CVE) and the upstream compare's
// php8.3-fpm and php8.3-cli are one package, the CVE once, one finding
// naming the binaries; on b2c1297 they were 3 packages, the CVE twice,
// two findings.
func TestPatrolKEVOfUpstreamPHP(t *testing.T) {
	const cve = "CVE-2026-129291"
	t.Cleanup(tools.SetHostSourceForTest(suryDebian("php8.3-fpm php8.3 8.3.9", "php8.3-cli php8.3 8.3.9")))
	hc := &http.Client{Transport: kevOnly{cve: cve, osv: map[string]string{"php8.3": "DSA-9999-1"}, alias: map[string]string{"DSA-9999-1": cve}}}
	r, _, err := tools.PackageVulnsSurface(context.Background(), hc)
	if err != nil {
		t.Fatal(err)
	}
	kev := kevKeys(r)
	f, ok := kev["kev:php8.3:"+cve]
	if len(kev) != 1 || !ok || f.Severity != "critical" || !strings.Contains(f.Summary, "php8.3-fpm") {
		t.Errorf("one KEV finding for php8.3 naming php8.3-fpm: %v", kev)
	}
	up := upstreamAffected(t, r)["php8.3"]
	if !up[cve] || len(up) < 2 {
		t.Fatalf("upstream compare of php8.3: %v", up)
	}
	// OSV's one advisory (the KEV CVE) and upstream's CVEs, that one not again.
	if n, _ := r["total_vulns"].(int); n != 1+len(up)-1 {
		t.Errorf("total_vulns %v, want %d", r["total_vulns"], len(up))
	}
	if n, _ := r["affected_packages"].(int); n != 1 {
		t.Errorf("affected_packages %v, want 1", r["affected_packages"])
	}

	// Two source packages with the same CVE are two packages, two findings.
	t.Cleanup(tools.SetHostSourceForTest(suryDebian("php8.3-fpm php8.3 8.3.9", "php8.4-fpm php8.4 8.4.1")))
	r, _, err = tools.PackageVulnsSurface(context.Background(), &http.Client{Transport: kevOnly{cve: cve}})
	if err != nil {
		t.Fatal(err)
	}
	kev = kevKeys(r)
	if _, ok := kev["kev:php8.3:"+cve]; !ok || len(kev) != 2 {
		t.Errorf("a finding each for php8.3 and php8.4: %v", kev)
	}
	if _, ok := kev["kev:php8.4:"+cve]; !ok {
		t.Errorf("a finding each for php8.3 and php8.4: %v", kev)
	}
	all := upstreamAffected(t, r)
	if n, _ := r["total_vulns"].(int); n != len(all["php8.3"])+len(all["php8.4"]) {
		t.Errorf("total_vulns %v, want %d+%d", r["total_vulns"], len(all["php8.3"]), len(all["php8.4"]))
	}
	if n, _ := r["affected_packages"].(int); n != 2 {
		t.Errorf("affected_packages %v, want 2", r["affected_packages"])
	}
}
