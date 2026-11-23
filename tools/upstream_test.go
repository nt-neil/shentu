package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// kevFeeds is emptyFeeds with one CVE in the KEV catalog.
type kevFeeds struct{ cve string }

func (k kevFeeds) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Host, "kev.example.test") {
		body := `{"vulnerabilities":[{"cveID":"` + k.cve + `","vulnerabilityName":"Example","dateAdded":"2026-11-20"}]}`
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
	return emptyFeeds{}.RoundTrip(r)
}

func gz(t *testing.T, s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// PR-B: third-party PHP and nginx are compared with php.net's and
// nginx.org's advisories and go into the surface; the rest of the third
// party, and what cannot be compared, stays "not checked", with why.
func TestPackageVulnsUpstream(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	hc := &http.Client{Transport: kevFeeds{"CVE-2026-129291"}}
	sury := "+0~20240705.1+debian12~1.gbp1+deb.sury.org+1"
	withHost(t, dirHost{scriptHost{memHost: memHost{
		"/etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
		"/usr/share/doc/php8.3-cli/changelog.Debian.gz": gz(t, "php8.3 (8.3.9-1) unstable; urgency=high\n  * Fix CVE-2026-129496\n"),
	}, cmds: map[string]hostenv.CmdResult{
		strings.Join([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, " "): {Stdout: []byte(
			"bash\t\t5.2.15-2+b7\tarm64\tii \n" +
				"php8.3-fpm\tphp8.3\t8.3.9-1" + sury + "\tarm64\tii \n" +
				"php8.3-cli\tphp8.3\t8.3.9-1" + sury + "\tarm64\tii \n" +
				"php8.3-mysql\tphp8.3\t8.3.9-1" + sury + "\tarm64\tii \n" +
				"php7.4-fpm\tphp7.4\t7.4.33-1+deb.sury.org+1\tarm64\tii \n" +
				"nginx\t\t1.31.2-1~bookworm\tarm64\tii \n")},
	}}})
	out, surface, err := packageVulnsAll(context.Background(), hc, surfaceDetail)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	type hitJSON struct { // as the output names them (not upstreamHit: this runs on the base too)
		Package, Upstream, Fixed string
		Affected, Backported     []string
	}
	var got struct {
		Upstream  []hitJSON `json:"third_party_upstream"`
		Unchecked []struct {
			Package, Why string
		} `json:"third_party_unchecked"`
	}
	json.Unmarshal(b, &got)
	hit := map[string]hitJSON{}
	for _, h := range got.Upstream {
		hit[h.Package] = h
	}
	fpm, cli, ngx := hit["php8.3-fpm"], hit["php8.3-cli"], hit["nginx"]
	if fpm.Fixed != "8.3.37" || !slices.Contains(fpm.Affected, "CVE-2026-129291") || !slices.Contains(fpm.Affected, "CVE-2026-129496") ||
		slices.Contains(fpm.Affected, "CVE-2026-129538") {
		t.Errorf("php8.3-fpm: %+v", fpm)
	}
	if slices.Contains(cli.Affected, "CVE-2026-129291") || slices.Contains(cli.Affected, "CVE-2026-129496") ||
		!slices.Contains(cli.Backported, "CVE-2026-129496") || len(cli.Affected) == 0 {
		t.Errorf("php8.3-cli (FPM's not its; 129496 backported): %+v", cli)
	}
	if ngx.Upstream != "nginx" || ngx.Fixed != "1.31.9" || len(ngx.Affected) == 0 {
		t.Errorf("nginx.org's nginx: %+v", ngx)
	}
	why := map[string]string{}
	for _, u := range got.Unchecked {
		why[u.Package] = u.Why
	}
	if w, ok := why["php7.4-fpm"]; !ok || !strings.Contains(w, "no longer fixes") {
		t.Errorf("PHP 7.4 is not \"no vulnerabilities\": %q %v", w, ok)
	}
	if _, ok := why["php8.3-mysql"]; !ok {
		t.Errorf("an extension is not compared, still not checked: %v", why)
	}
	for _, p := range []string{"php8.3-fpm", "php8.3-cli", "nginx"} {
		if _, ok := why[p]; ok {
			t.Errorf("%s compared, yet listed as not checked", p)
		}
	}
	var ups []detect.PackageVuln
	for _, v := range surface {
		if strings.HasPrefix(v.Ecosystem, "upstream:") {
			ups = append(ups, v)
		}
	}
	find := func(pkg, id string) *detect.PackageVuln {
		for i := range ups {
			if ups[i].Package == pkg && ups[i].ID == id {
				return &ups[i]
			}
		}
		return nil
	}
	if v := find("php8.3-fpm", "CVE-2026-129291"); v == nil || v.Ecosystem != "upstream:php" || v.CVE != v.ID || v.Fixed != "8.3.37" || !v.KEV {
		t.Errorf("surface php8.3-fpm 129291 (KEV): %+v", v)
	}
	if v := find("php8.3-fpm", "CVE-2026-129496"); v == nil || v.KEV {
		t.Errorf("surface php8.3-fpm 129496 (not KEV): %+v", v)
	}
	if find("php8.3-cli", "CVE-2026-129496") != nil {
		t.Errorf("a backported CVE in the surface")
	}
	if v := find("nginx", "CVE-2026-123007"); v == nil || v.Ecosystem != "upstream:nginx" {
		t.Errorf("surface nginx: %+v", v)
	}
	if find("php7.4-fpm", "CVE-2026-129496") != nil || find("php8.3-mysql", "CVE-2026-129496") != nil {
		t.Errorf("not compared, yet in the surface: %+v", ups)
	}
}
