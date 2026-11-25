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
type pagedOSV struct{ asked *[]string }

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
				res[i] = map[string]any{"vulns": vulns("USN-9999-1", "UBUNTU-CVE-2099-0010")}
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
	out, err := PackageVulns(context.Background(), &http.Client{Transport: pagedOSV{&asked}}, "")
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
	_, surface, err := packageVulnsAll(context.Background(), &http.Client{Transport: pagedOSV{new([]string)}}, surfaceDetail)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range surface {
		if v.ID == "USN-9999-1" && (slices.Contains(v.CVEs, "CVE-2099-0011") || !slices.Contains(v.CVEs, "CVE-2099-0010")) {
			t.Errorf("the USN's CVEs on the surface: %q", v.CVEs)
		}
	}
}
