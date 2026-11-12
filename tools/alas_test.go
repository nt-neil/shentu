package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// An Amazon Linux 2023 host with an old openssl and a current bash, against
// a fake repository: openssl is affected by the ALAS (and through its CVE,
// by KEV); bash's advisory is older than what is installed.
func TestPackageVulnsAmazonLinux(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`<?xml version="1.0" ?><updates>
<update type="security"><id>ALAS2023-2025-100</id><severity>Critical</severity><references><reference id="CVE-2099-0001" type="cve"/></references>
<pkglist><collection><package name="openssl" version="3.0.8" release="1.amzn2023.0.18" epoch="1" arch="aarch64"/></collection></pkglist></update>
<update type="security"><id>ALAS2023-2023-007</id><severity>Low</severity><references><reference id="CVE-2023-0002" type="cve"/></references>
<pkglist><collection><package name="bash" version="5.2.15" release="1.amzn2023.0.1" epoch="0" arch="aarch64"/></collection></pkglist></update>
</updates>`))
	zw.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mirror.list":
			w.Write([]byte(srv.URL + "/repo/\n"))
		case "/repo/repodata/repomd.xml":
			w.Write([]byte(`<repomd><data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>`))
		case "/repo/repodata/updateinfo.xml.gz":
			w.Write(gz.Bytes())
		case "/kev":
			json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []map[string]string{{"cveID": "CVE-2099-0001", "vulnerabilityName": "test", "dateAdded": "2099-01-01"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldMirror, oldKEV, oldPrefixes := alasMirrorList, kevURL, mirrorPrefixes
	defer func() { alasMirrorList, kevURL, mirrorPrefixes = oldMirror, oldKEV, oldPrefixes }()
	mirrorPrefixes = []string{srv.URL + "/"}
	alasMirrorList = func(release, arch string) string {
		if release != "2023" || arch != hostenv.RPMArch(hostSource().Info().GOARCH) {
			t.Errorf("mirror for %s %s", release, arch)
		}
		return srv.URL + "/mirror.list"
	}
	kevURL = srv.URL + "/kev"
	withHost(t, scriptHost{memHost: memHost{
		"/etc/os-release": "NAME=\"Amazon Linux\"\nID=\"amzn\"\nVERSION_ID=\"2023\"\nPRETTY_NAME=\"Amazon Linux 2023\"\n",
	}, cmds: map[string]hostenv.CmdResult{strings.Join([]string{"/usr/bin/rpm", "-qa", "--qf", hostenv.RpmQueryFormat}, " "): {
		Stdout: []byte("openssl\t1:3.0.8-1.amzn2023.0.11\taarch64\nbash\t0:5.2.15-1.amzn2023.0.2\taarch64\n")}}})
	out, err := PackageVulns(context.Background(), srv.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	s := string(b)
	for _, want := range []string{`"ecosystem":"Amazon Linux 2023"`, `"packages_checked":2`, `"affected_packages":1`, `"upgrade_command":"dnf upgrade --security"`, `ALAS2023-2025-100`, `CVE-2099-0001`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, "ALAS2023-2023-007") {
		t.Errorf("an advisory older than the installed bash counted: %s", s)
	}
	d, err := PackageVulns(context.Background(), srv.Client(), "openssl")
	if b, _ := json.Marshal(d); err != nil || !strings.Contains(string(b), `"fixed_version":"1:3.0.8-1.amzn2023.0.18"`) {
		t.Errorf("detail %s %v", b, err)
	}
}
