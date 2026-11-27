package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// ubuntuHost is an Ubuntu 24.04 host with the dpkg lines given.
func ubuntuHost(dpkg string) dirHost {
	return dirHost{scriptHost{memHost: memHost{
		"/etc/os-release": "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.3 LTS (Noble Numbat)\"\nID=ubuntu\nID_LIKE=debian\n",
	}, cmds: map[string]hostenv.CmdResult{
		strings.Join([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, " "): {Stdout: []byte(dpkg)},
	}}}
}

// pagedOSV is OSV as it answers: at most a page of advisories a query, the
// rest behind next_page_token. Made-up advisories (CVE-2099-...).
//   - linux: two pages; the second only when asked with the first's token.
//   - openssl: a USN whose aliases name a CVE of this release
//     (UBUNTU-CVE-2099-0010 is listed too) and one of another release only.
//   - deeppkg: a token on every page, past osvMaxPages.
type pagedOSV struct {
	asked   *[]string
	kevDown bool // the KEV list unavailable
	many    int  // openssl has this many more advisories before its USN (past matchKEV's 300)
}

func (o pagedOSV) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{}`
	switch {
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		var q struct {
			Queries []struct {
				Package   struct{ Name string } `json:"package"`
				PageToken string                `json:"page_token"`
			} `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		for i, x := range q.Queries {
			*o.asked = append(*o.asked, x.Package.Name+"@"+x.PageToken)
			vulns := func(ids ...string) []map[string]string {
				var v []map[string]string
				for _, id := range ids {
					v = append(v, map[string]string{"id": id})
				}
				return v
			}
			switch x.Package.Name + "@" + x.PageToken {
			case "linux@":
				res[i] = map[string]any{"vulns": vulns("UBUNTU-CVE-2099-0001", "UBUNTU-CVE-2099-0002"), "next_page_token": "linux-p2"}
			case "linux@linux-p2":
				res[i] = map[string]any{"vulns": vulns("UBUNTU-CVE-2099-0003")}
			case "openssl@":
				var ids []string
				for n := 0; n < o.many; n++ {
					ids = append(ids, fmt.Sprintf("UBUNTU-CVE-2099-%04d", 1000+n))
				}
				res[i] = map[string]any{"vulns": vulns(append(ids, "USN-9999-1", "UBUNTU-CVE-2099-0010")...)}
			case "onlyusn@": // OSV lists the USN alone: nothing to tell its CVEs' release by
				res[i] = map[string]any{"vulns": vulns("USN-9998-1")}
			case "php8.3@": // a third-party PHP (sury) on Ubuntu: upstream compared too
				res[i] = map[string]any{"vulns": vulns("USN-9100-1", "UBUNTU-CVE-2026-129496")}
			default:
				if x.Package.Name == "deeppkg" {
					n := len(x.PageToken)
					res[i] = map[string]any{"vulns": vulns(fmt.Sprintf("UBUNTU-CVE-2099-%04d", 100+n)), "next_page_token": x.PageToken + "x"}
				} else {
					res[i] = map[string]any{}
				}
			}
		}
		b, _ := json.Marshal(map[string]any{"results": res})
		body = string(b)
	case strings.HasSuffix(r.URL.Path, "/vulns/USN-9999-1"):
		body = `{"id":"USN-9999-1","aliases":["CVE-2099-0010","CVE-2099-0011"]}`
	case strings.HasSuffix(r.URL.Path, "/vulns/USN-9998-1"):
		body = `{"id":"USN-9998-1","aliases":["CVE-2099-0011"]}`
	case strings.HasSuffix(r.URL.Path, "/vulns/USN-9100-1"): // 129291: another release's only
		body = `{"id":"USN-9100-1","aliases":["CVE-2026-129291","CVE-2026-129496"]}`
	case strings.Contains(r.URL.Host, "kev.example.test") && o.kevDown:
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	case strings.Contains(r.URL.Host, "kev.example.test"):
		body = `{"vulnerabilities":[{"cveID":"CVE-2099-0010","vulnerabilityName":"made-up, this release"},{"cveID":"CVE-2099-0011","vulnerabilityName":"made-up, another release only"}]}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func pagedRun(t *testing.T, dpkg string) (map[string]any, []string) {
	t.Helper()
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	var asked []string
	withHost(t, ubuntuHost(dpkg))
	out, err := PackageVulns(context.Background(), &http.Client{Transport: pagedOSV{asked: &asked}}, "")
	if err != nil {
		t.Fatal(err)
	}
	return out, asked
}

// I-1: OSV's next_page_token is followed: the kernel's advisories past the
// first page are read (on aca2b8b the first 1000 only, nothing said).
func TestPackageVulnsOSVPages(t *testing.T) {
	out, asked := pagedRun(t, "linux-image-6.8.0-1-generic\tlinux\t6.8.0-1.1\tarm64\tii \n")
	if !slices.Contains(asked, "linux@linux-p2") {
		t.Errorf("the second page not asked: %q", asked)
	}
	if out["total_vulns"] != 3 {
		t.Errorf("total_vulns %v, want 3 (both pages): %v", out["total_vulns"], out)
	}
	if _, ok := out["partial"]; ok {
		t.Errorf("partial for a list read to its end: %v", out["partial"])
	}
}

// Past osvMaxPages the rest is said not checked, never quietly cut.
func TestPackageVulnsOSVPagesCapped(t *testing.T) {
	out, asked := pagedRun(t, "deeppkg\t\t1.0-1\tarm64\tii \n")
	n := 0
	for _, a := range asked {
		if strings.HasPrefix(a, "deeppkg@") {
			n++
		}
	}
	if n != osvMaxPages || out["total_vulns"] != osvMaxPages {
		t.Errorf("pages asked %d, total %v, want %d", n, out["total_vulns"], osvMaxPages)
	}
	if p, _ := out["partial"].(string); !strings.Contains(p, fmt.Sprintf("OSV listed more than %d pages of advisories for deeppkg: the rest not checked", osvMaxPages)) {
		t.Errorf("partial %q", p)
	}
}

// I-7: a USN's aliases name CVEs of other releases; only those OSV lists for
// this package on this release count. CVE-2099-0011 (another release only)
// is on KEV and must not be marked exploited here: a false KEV alert.
func TestPackageVulnsUSNOtherRelease(t *testing.T) {
	out, _ := pagedRun(t, "libssl3t64\topenssl\t3.0.13-0ubuntu3.1\tarm64\tii \n")
	b, _ := json.Marshal(out["actively_exploited"])
	if strings.Contains(string(b), "CVE-2099-0011") {
		t.Errorf("a CVE of another release marked exploited: %s", b)
	}
	if !strings.Contains(string(b), "CVE-2099-0010") {
		t.Errorf("this release's exploited CVE not marked: %s", b)
	}
	_, surface, err := packageVulnsAll(context.Background(), &http.Client{Transport: pagedOSV{asked: new([]string)}}, surfaceDetail)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range surface {
		if v.ID == "USN-9999-1" && (slices.Contains(v.CVEs, "CVE-2099-0011") || !slices.Contains(v.CVEs, "CVE-2099-0010")) {
			t.Errorf("the USN's CVEs on the surface: %q", v.CVEs)
		}
	}
}

// usnSurface is the surface's CVEs of USN-9999-1 with o answering.
func usnSurface(t *testing.T, o pagedOSV) []string {
	t.Helper()
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	withHost(t, ubuntuHost("libssl3t64\topenssl\t3.0.13-0ubuntu3.1\tarm64\tii \n"))
	_, surface, err := packageVulnsAll(context.Background(), &http.Client{Transport: o}, surfaceDetail)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range surface {
		if v.ID == "USN-9999-1" {
			return v.CVEs
		}
	}
	t.Fatalf("USN-9999-1 not on the surface")
	return nil
}

// N-258-1: when the KEV check did not look the USN up (the list
// unavailable, or past 300 advisories of the package), the surface's
// lookup keeps this release's CVEs only, as the KEV check does.
func TestPackageVulnsUSNSurfaceUnlooked(t *testing.T) {
	for name, o := range map[string]pagedOSV{
		"KEV unavailable":  {asked: new([]string), kevDown: true},
		"past 300 for KEV": {asked: new([]string), many: 301},
	} {
		if got := usnSurface(t, o); !slices.Equal(got, []string{"CVE-2099-0010"}) {
			t.Errorf("%s: the USN's CVEs on the surface %q, want this release's only", name, got)
		}
	}
}

// S-258-1: a USN whose package has no CVE-named advisory to tell by: its
// CVEs are neither kept (another release's KEV CVE would be marked) nor
// dropped quietly: the USN is counted in kev_unchecked and named.
func TestPackageVulnsUSNUnsure(t *testing.T) {
	out, _ := pagedRun(t, "onlyusn\t\t1.0-1\tarm64\tii \n")
	b, _ := json.Marshal(out["actively_exploited"])
	if strings.Contains(string(b), "CVE-2099-0011") {
		t.Errorf("an unsure USN's CVE marked exploited: %s", b)
	}
	if out["kev_unchecked"] != 1 || !strings.Contains(fmt.Sprint(out["kev"]), "for USN-9998-1, whether its CVEs apply to this release could not be told") {
		t.Errorf("kev_unchecked %v, kev %q", out["kev_unchecked"], out["kev"])
	}
}

// The upstream de-duplication (osvHas) keeps this release's CVEs of a USN
// only: php.net's CVE-2026-129291, which the USN names for another release,
// is counted from upstream, not taken for OSV's (the review's case: 13,
// and 12 without the filter).
func TestPackageVulnsUSNUpstreamDedupe(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	sury := "+ubuntu24.04.1+deb.sury.org+1"
	withHost(t, ubuntuHost("php8.3-fpm\tphp8.3\t8.3.9-1"+sury+"\tarm64\tii \n"))
	out, err := PackageVulns(context.Background(), &http.Client{Transport: pagedOSV{asked: new([]string)}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if out["total_vulns"] != 13 {
		t.Errorf("total_vulns %v, want 13 (OSV's 2, php.net's 11 with 129291): %v", out["total_vulns"], out)
	}
}

// I-8: the overview tells the advisories a fix is known to be out for (an
// update notice, USN-) from the rest, which are unconfirmed, never "no fix".
func TestPackageVulnsFixSplit(t *testing.T) {
	out, _ := pagedRun(t, "openssl\t\t3.0.13-0ubuntu3\tarm64\tii \nlinux-image-6.8.0-1-generic\tlinux\t6.8.0-1.1\tarm64\tii \n")
	if out["total_vulns"] != 5 || out["fix_available"] != 1 || out["fix_unconfirmed"] != 4 {
		t.Errorf("total %v, fix_available %v, fix_unconfirmed %v; want 5, 1 (USN-9999-1), 4: %v", out["total_vulns"], out["fix_available"], out["fix_unconfirmed"], out)
	}
	if n, _ := out["fix_note"].(string); !strings.Contains(n, "unconfirmed does not mean there is no fix") {
		t.Errorf("fix_note %q", n)
	}
	b, _ := json.Marshal(out["affected"])
	for _, want := range []string{`"package":"openssl","version":"3.0.13-0ubuntu3","vulns":2,"sample_ids":["USN-9999-1","UBUNTU-CVE-2099-0010"],"actively_exploited":1,"fix_available":1`, `"package":"linux","version":"6.8.0-1.1","vulns":3,"sample_ids":["UBUNTU-CVE-2099-0001","UBUNTU-CVE-2099-0002","UBUNTU-CVE-2099-0003"],"fix_available":0`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("affected %s, want %s", b, want)
		}
	}
	none, _ := pagedRun(t, "zlib\t\t1.3-1\tarm64\tii \n")
	if _, ok := none["fix_unconfirmed"]; ok {
		t.Errorf("fix counts with nothing found: %v", none)
	}
}

// php.net's entries name the fixed release: counted as a fix out, as the
// USN is; OSV's UBUNTU-CVE- stays unconfirmed.
func TestPackageVulnsFixSplitUpstream(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	withHost(t, ubuntuHost("php8.3-fpm\tphp8.3\t8.3.9-1+ubuntu24.04.1+deb.sury.org+1\tarm64\tii \n"))
	out, err := PackageVulns(context.Background(), &http.Client{Transport: pagedOSV{asked: new([]string)}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if out["total_vulns"] != 13 || out["fix_available"] != 12 || out["fix_unconfirmed"] != 1 {
		t.Errorf("total %v, fix_available %v, fix_unconfirmed %v; want 13, 12, 1", out["total_vulns"], out["fix_available"], out["fix_unconfirmed"])
	}
}
