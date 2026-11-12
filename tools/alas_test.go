package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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
	oldMirror, oldKEV, oldPrefixes, oldCache := alasMirrorList, kevURL, mirrorPrefixes, alasCacheDir
	defer func() {
		alasMirrorList, kevURL, mirrorPrefixes, alasCacheDir = oldMirror, oldKEV, oldPrefixes, oldCache
	}()
	cache := t.TempDir()
	alasCacheDir = func() string { return cache }
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

// N15: Amazon Linux 2 reads the extras topics it enables too; every
// installed kernel is compared, a fix counts for its own architecture, and
// updateinfo is kept in the cache (downloaded once).
func TestALASExtrasVersionsArch(t *testing.T) {
	gzXML := func(x string) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(x))
		zw.Close()
		return b.Bytes()
	}
	core := gzXML(`<updates><update type="security"><id>ALAS2-2025-1</id><pkglist><collection>
<package name="openssl" version="1.0.2k" release="19.amzn2.0.20" epoch="1" arch="x86_64"/></collection></pkglist></update></updates>`)
	kernel := gzXML(`<updates><update type="security"><id>ALAS2KERNEL-5.10-2025-9</id><pkglist><collection>
<package name="kernel" version="5.10.200" release="1.amzn2" epoch="0" arch="aarch64"/></collection></pkglist></update></updates>`)
	downloads := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/core/mirror.list":
			w.Write([]byte(srv.URL + "/core/repo/\n"))
		case "/kernel-5.10/mirror.list":
			w.Write([]byte(srv.URL + "/kernel-5.10/repo/\n"))
		case "/core/repo/repodata/repomd.xml", "/kernel-5.10/repo/repodata/repomd.xml":
			w.Write([]byte(`<repomd><data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>`))
		case "/core/repo/repodata/updateinfo.xml.gz":
			downloads++
			w.Write(core)
		case "/kernel-5.10/repo/repodata/updateinfo.xml.gz":
			downloads++
			w.Write(kernel)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldM, oldE, oldP, oldC := alasMirrorList, alasExtrasMirrorList, mirrorPrefixes, alasCacheDir
	defer func() { alasMirrorList, alasExtrasMirrorList, mirrorPrefixes, alasCacheDir = oldM, oldE, oldP, oldC }()
	cache := t.TempDir()
	alasCacheDir = func() string { return cache }
	mirrorPrefixes = []string{srv.URL + "/"}
	alasMirrorList = func(string, string) string { return srv.URL + "/core/mirror.list" }
	alasExtrasMirrorList = func(topic, _ string) string { return srv.URL + "/" + topic + "/mirror.list" }
	feed := hostenv.PatchFeed{Kind: "alas", Release: "2", Repos: []string{"kernel-5.10"}}
	items := []hostenv.Package{
		{Name: "kernel", Version: "0:5.10.199-1.amzn2", Arch: "aarch64"},
		{Name: "kernel", Version: "0:5.10.201-1.amzn2", Arch: "aarch64"},
		{Name: "openssl", Version: "1:1.0.2k-19.amzn2.0.19", Arch: "aarch64"}, // the fix is for x86_64 only
	}
	for run := 0; run < 2; run++ {
		hits, _, _, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 || hits[0].Package != "kernel" || hits[0].Version != "0:5.10.199-1.amzn2" {
			t.Errorf("run %d: %+v", run, hits)
		}
	}
	if downloads != 2 {
		t.Errorf("updateinfo downloaded %d times, want 2 (once per repository)", downloads)
	}
}

// N15: Amazon Linux 1 has no feed: cannot tell, never "nothing found".
func TestPackageVulnsAmazonLinux1(t *testing.T) {
	withHost(t, memHost{"/etc/os-release": "NAME=\"Amazon Linux AMI\"\nID=\"amzn\"\nVERSION_ID=\"2018.03\"\n"})
	out, err := PackageVulns(context.Background(), http.DefaultClient, "")
	if err == nil || !strings.Contains(err.Error(), "cannot tell") || out != nil {
		t.Errorf("Amazon Linux 1: %v %v", out, err)
	}
}

// fakeALAS serves core and topics; each topic's updateinfo is the gzipped
// XML given, and repomd carries its sha256 unless noSum.
func fakeALAS(t *testing.T, topics map[string]string, noSum bool) (*httptest.Server, *int) {
	files := map[string][]byte{}
	for topic, x := range topics {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(x))
		zw.Close()
		files[topic] = b.Bytes()
	}
	downloads := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		body, ok := files[parts[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "mirror.list":
			w.Write([]byte(srv.URL + "/" + parts[0] + "/repo/\n"))
		case "repo/repodata/repomd.xml":
			sum := sha256.Sum256(body)
			ck := `<checksum type="sha256">` + hex.EncodeToString(sum[:]) + `</checksum>`
			if noSum {
				ck = ""
			}
			w.Write([]byte(`<repomd><data type="updateinfo">` + ck + `<location href="repodata/updateinfo.xml.gz"/></data></repomd>`))
		case "repo/repodata/updateinfo.xml.gz":
			downloads++
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	oldM, oldE, oldP, oldC := alasMirrorList, alasExtrasMirrorList, mirrorPrefixes, alasCacheDir
	t.Cleanup(func() { alasMirrorList, alasExtrasMirrorList, mirrorPrefixes, alasCacheDir = oldM, oldE, oldP, oldC })
	cache := t.TempDir()
	alasCacheDir = func() string { return cache }
	mirrorPrefixes = []string{srv.URL + "/"}
	alasMirrorList = func(string, string) string { return srv.URL + "/core/mirror.list" }
	alasExtrasMirrorList = func(topic, _ string) string { return srv.URL + "/" + topic + "/mirror.list" }
	return srv, &downloads
}

const kernelFix = `<updates><update type="security"><id>ALAS2KERNEL-5.10-2025-9</id><pkglist><collection>
<package name="kernel" version="5.10.200" release="1.amzn2" epoch="0" arch="aarch64"/></collection></pkglist></update></updates>`

// N2-3: a cached updateinfo that does not match repomd's checksum (cut
// short) is fetched again.
func TestALASCacheChecksum(t *testing.T) {
	srv, downloads := fakeALAS(t, map[string]string{"core": "<updates/>", "kernel-5.10": kernelFix}, false)
	feed := hostenv.PatchFeed{Kind: "alas", Release: "2", Repos: []string{"kernel-5.10"}}
	items := []hostenv.Package{{Name: "kernel", Version: "0:5.10.199-1.amzn2", Arch: "aarch64"}}
	if hits, _, _, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items); err != nil || len(hits) != 1 {
		t.Fatalf("first run: %+v %v", hits, err)
	}
	cached, _ := filepath.Glob(filepath.Join(alasCacheDir(), "alas-*.gz"))
	if len(cached) != 2 {
		t.Fatalf("cache %v", cached)
	}
	for _, f := range cached {
		b, _ := os.ReadFile(f)
		os.WriteFile(f, b[:len(b)/2], 0o600) // cut short
	}
	before := *downloads
	if hits, _, _, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items); err != nil || len(hits) != 1 {
		t.Errorf("after a damaged cache: %+v %v", hits, err)
	}
	if *downloads-before != 2 {
		t.Errorf("damaged cache files fetched %d times, want 2", *downloads-before)
	}
}

// N2-4: one topic failing (404) keeps the core's and the other topics'
// results, and says which topic was not checked.
func TestALASTopicFails(t *testing.T) {
	srv, _ := fakeALAS(t, map[string]string{"core": "<updates/>", "kernel-5.10": kernelFix}, false)
	feed := hostenv.PatchFeed{Kind: "alas", Release: "2", Repos: []string{"gone", "kernel-5.10"}}
	items := []hostenv.Package{{Name: "kernel", Version: "0:5.10.199-1.amzn2", Arch: "aarch64"}}
	hits, _, failed, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items)
	if err != nil || len(hits) != 1 || len(failed) != 1 || !strings.Contains(failed[0], "extras topic gone") {
		t.Errorf("hits %+v failed %v err %v", hits, failed, err)
	}
}

// N-D2: a package list that parses to nothing is "cannot tell", not "no vulnerabilities".
func TestPackageVulnsNoPackages(t *testing.T) {
	withHost(t, memHost{"/etc/os-release": "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.2\n", "/lib/apk/db/installed": "\n"})
	out, err := PackageVulns(context.Background(), http.DefaultClient, "")
	if err == nil || !strings.Contains(err.Error(), "no installed packages") || out != nil {
		t.Errorf("no packages: %v %v", out, err)
	}
}

// N-D4: the updateinfo href and its checksum come from the one
// <data type="updateinfo"> entry. testdata/al2023-repomd.xml is the AL2023
// core repository's repomd.xml as served on 2026-11-13; another entry naming
// an updateinfo file (here a zchunk one) is put before it.
func TestALASRepomdOneEntry(t *testing.T) {
	real, err := os.ReadFile("testdata/al2023-repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(kernelFix))
	zw.Close()
	sum := sha256.Sum256(gz.Bytes())
	repomd := regexp.MustCompile(`(<data type="updateinfo">\s*<checksum type="sha256">)[0-9a-f]{64}`).
		ReplaceAll(real, []byte("${1}"+hex.EncodeToString(sum[:])))
	decoy := `<data type="updateinfo_zck"><checksum type="sha256">` + strings.Repeat("0", 64) +
		`</checksum><location href="repodata/updateinfo.xml.zck"/></data>`
	repomd = bytes.Replace(repomd, []byte(`<data type="updateinfo">`), []byte(decoy+`<data type="updateinfo">`), 1)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mirror.list":
			w.Write([]byte(srv.URL + "/repo/\n"))
		case "/repo/repodata/repomd.xml":
			w.Write(repomd)
		case "/repo/repodata/updateinfo.xml.gz":
			w.Write(gz.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldP, oldC := mirrorPrefixes, alasCacheDir
	t.Cleanup(func() { mirrorPrefixes, alasCacheDir = oldP, oldC })
	cache := t.TempDir()
	alasCacheDir = func() string { return cache }
	mirrorPrefixes = []string{srv.URL + "/"}
	rc, _, err := updateinfo(context.Background(), srv.Client(), srv.URL+"/mirror.list")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if b, _ := io.ReadAll(rc); string(b) != kernelFix {
		t.Errorf("read %q", b)
	}
}

// A cached updateinfo that does not parse, with no checksum in repomd to
// catch it, is dropped and said, so the next run fetches it again.
func TestALASUnparsableCacheDropped(t *testing.T) {
	srv, downloads := fakeALAS(t, map[string]string{"core": "<updates/>", "kernel-5.10": kernelFix}, true)
	feed := hostenv.PatchFeed{Kind: "alas", Release: "2", Repos: []string{"kernel-5.10"}}
	items := []hostenv.Package{{Name: "kernel", Version: "0:5.10.199-1.amzn2", Arch: "aarch64"}}
	if _, _, _, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items); err != nil {
		t.Fatal(err)
	}
	cached, _ := filepath.Glob(filepath.Join(alasCacheDir(), "alas-*.gz"))
	for _, f := range cached {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte("<updates><update")) // damaged, still gzip
		zw.Close()
		os.WriteFile(f, b.Bytes(), 0o600)
	}
	_, _, failed, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items)
	if err == nil || !strings.Contains(err.Error(), "cached copy dropped") {
		t.Errorf("core: err %v failed %v", err, failed)
	}
	if left, _ := filepath.Glob(filepath.Join(alasCacheDir(), "alas-*.gz")); len(left) != 1 {
		t.Errorf("cache after: %v", left) // core dropped (it stops the run); the topic was not reached
	}
	// Next run: core fetched again; the topic's damaged copy is found now,
	// dropped and listed as not checked (partial).
	if _, _, failed, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items); err != nil || len(failed) != 1 || !strings.Contains(failed[0], "cached copy dropped") {
		t.Errorf("topic: err %v failed %v", err, failed)
	}
	before := *downloads
	if hits, _, failed, err := alasAffected(context.Background(), srv.Client(), feed, "aarch64", items); err != nil || len(hits) != 1 || len(failed) != 0 || *downloads == before {
		t.Errorf("after: %+v %v %v, downloads %d->%d", hits, failed, err, before, *downloads)
	}
}
