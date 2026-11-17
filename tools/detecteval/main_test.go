package main

// These tests use made-up templates of Nuclei's shape with placeholder
// values (a=abc): they check the mechanics, and hold no attack string.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type entry struct {
	name, body string
	flag       byte
}

func tarball(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.flag, Size: int64(len(e.body))}
		if e.flag == tar.TypeSymlink {
			h.Linkname, h.Size = "../outside-x", 0
		}
		if e.flag == tar.TypeDir {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestReadTarTakesOnlyHTTPYAML(t *testing.T) {
	b := tarball(t, []entry{
		{"top/", "", tar.TypeDir},
		{"top/README.md", "readme", tar.TypeReg},
		{"top/.github/workflows/x.yaml", "ci", tar.TypeReg},
		{"top/dns/a.yaml", "dns", tar.TypeReg},
		{"top/http/", "", tar.TypeDir},
		{"top/http/a/one.yaml", "one", tar.TypeReg},
		{"top/http/a/notes.md", "notes", tar.TypeReg},
		{"top/http/two.yaml", "two", tar.TypeReg},
	})
	got, err := readTar(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["http/a/one.yaml"]) != "one" || string(got["http/two.yaml"]) != "two" {
		t.Errorf("got %v", got)
	}
}

func TestReadTarRefuses(t *testing.T) {
	for name, es := range map[string][]entry{
		"dot-dot":  {{"top/http/../../x.yaml", "x", tar.TypeReg}},
		"absolute": {{"/top/http/x.yaml", "x", tar.TypeReg}},
		"symlink":  {{"top/http/x.yaml", "", tar.TypeSymlink}},
		"hardlink": {{"top/http/x.yaml", "", tar.TypeLink}},
	} {
		_, err := readTar(bytes.NewReader(tarball(t, es)))
		if !errors.Is(err, errArchive) {
			t.Errorf("%s: err %v, want errArchive", name, err)
		}
	}
	if _, err := readTar(strings.NewReader("not gzip")); !errors.Is(err, errArchive) {
		t.Errorf("not gzip: %v", err)
	}
}

func TestManifestHash(t *testing.T) {
	a := manifestHash(map[string][]byte{"http/a.yaml": []byte("1"), "http/b.yaml": []byte("2")})
	b := manifestHash(map[string][]byte{"http/b.yaml": []byte("2"), "http/a.yaml": []byte("1")})
	c := manifestHash(map[string][]byte{"http/a.yaml": []byte("1"), "http/b.yaml": []byte("3")})
	d := manifestHash(map[string][]byte{"http/a.yaml": []byte("1"), "http/c.yaml": []byte("2")})
	if a != b || a == c || a == d {
		t.Errorf("a %s b %s c %s d %s", a, b, c, d)
	}
}

func TestDownloadRetries(t *testing.T) {
	retryBase = time.Millisecond
	defer func() { retryBase = 2 * time.Second }()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if _, err := download(context.Background(), srv.URL, t.TempDir()); err != nil || n.Load() != 3 {
		t.Errorf("err %v after %d tries", err, n.Load())
	}
	n.Store(-100) // fails every time
	_, err := download(context.Background(), srv.URL, t.TempDir())
	if !errors.Is(err, errDownload) || n.Load() != -96 {
		t.Errorf("err %v, tries %d (want 4)", err, n.Load()+100)
	}
}

func TestTemplatesHashMismatchIsNotRun(t *testing.T) {
	f := t.TempDir() + "/t.tar.gz"
	if err := os.WriteFile(f, tarball(t, []entry{{"top/http/x.yaml", "x", tar.TypeReg}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := templates(f); !errors.Is(err, errHash) {
		t.Errorf("err %v, want errHash", err)
	}
}

const placeholderTemplate = `
id: example-0001
info:
  name: Example
  tags: example,lfi
  classification:
    cve-id: cve-2099-0001
variables:
  v: abc
http:
  - method: GET
    path:
      - "{{BaseURL}}/a/b?x={{v}}&y={{randstr}}"
      - "{{BaseURL}}"
      - "{{BaseURL}}?v={{v}}"
      - "http://{{Hostname}}/c"
  - raw:
      - |
        POST /d?e={{p}} HTTP/1.1
        Host: {{Hostname}}
    payloads:
      p:
        - one
        - two
`

func TestConvert(t *testing.T) {
	a, err := convert("http/x.yaml", []byte(placeholderTemplate))
	if err != nil {
		t.Fatal(err)
	}
	want := []target{{"GET", "/a/b?x=abc&y=x"}, {"GET", "/"}, {"GET", "/?v=abc"}, {"POST", "/d?e=one"}}
	if a.ID != "example-0001" || a.Class != "path" || len(a.CVEs) != 1 || a.CVEs[0] != "CVE-2099-0001" || len(a.Lines) != len(want) {
		t.Fatalf("got %+v", a)
	}
	for i := range want {
		if a.Lines[i] != want[i] {
			t.Errorf("line %d: %+v, want %+v", i, a.Lines[i], want[i])
		}
	}
	if _, err := convert("http/y.yaml", []byte("id: y\ninfo:\n  name: y\n")); err == nil {
		t.Error("a template without requests converted")
	}
	if _, err := convert("http/z.yaml", []byte(":\n- [")); err == nil {
		t.Error("bad yaml converted")
	}
}

func TestLogLineParses(t *testing.T) {
	ev, _, err := newEvaluator("../..")
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := ev.parser.Parse([]byte(logLine(target{"GET", `/a"b\c?q=abc` + "\x01"})))
	if !ok || rec.Method != "GET" || rec.Path != `/a"b\c` || rec.Query != "q=abc\x01" {
		t.Errorf("parsed %+v ok %v", rec, ok)
	}
}

func TestHostCases(t *testing.T) {
	pkgs, cves, err := hostPackages("../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != len(hostCases) || len(cves) != len(hostCases) {
		t.Errorf("%d packages, %d CVEs, %d cases", len(pkgs), len(cves), len(hostCases))
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Package] = true
	}
	for k, r := range registryName { // each renaming is used
		if !got[r.Package] {
			t.Errorf("%s: no case has %s", k, r.Package)
		}
	}
}

func TestNormalRequests(t *testing.T) {
	a, err := normalRequests()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := normalRequests()
	targets := map[string]bool{}
	n := 0
	for _, x := range apps {
		if x.Source == "" {
			t.Errorf("%s: no source", x.Name)
		}
		n += len(x.Routes) * perRoute
	}
	if len(a) != n || len(b) != n {
		t.Fatalf("%d, %d requests, want %d", len(a), len(b), n)
	}
	ev, _, err := newEvaluator("../..")
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("not the same every run: %v / %v", a[i], b[i])
		}
		rec, ok := ev.parser.Parse([]byte(a[i].Line))
		if !ok {
			t.Fatalf("%s does not parse", a[i].ID)
		}
		k := rec.Method + " " + rec.Path + "?" + rec.Query
		if targets[k] {
			t.Errorf("%s: the same method and target as another request", a[i].ID)
		}
		targets[k] = true
		if rec.Referer != "" && !strings.HasPrefix(rec.Referer, "https://example.com/") && !strings.HasPrefix(rec.Referer, "https://www.example.com/") {
			t.Errorf("%s: referer %q", a[i].ID, rec.Referer)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		tags, cwes []string
		want       string
	}{
		{[]string{"cve", "rce", "ognl"}, nil, "code"},
		{[]string{"rce", "deserialization", "java"}, nil, "deser"},
		{[]string{"rce", "ssti"}, nil, "code"},
		{[]string{"rce", "log4j"}, nil, "jndi"},
		{[]string{"rce", "command-injection"}, nil, "cmdi"},
		{[]string{"rce", "java"}, []string{"CWE-78"}, "cmdi"},
		{[]string{"rce", "java"}, []string{"cwe-502"}, "deser"},
		{[]string{"rce", "java"}, []string{"CWE-284"}, rceUnspecified},
		{[]string{"rce"}, nil, rceUnspecified},
		{[]string{"rce", "file-upload"}, nil, "upload"},
		{[]string{"cve", "panel"}, nil, ""},
	} {
		if got := classify(c.tags, c.cwes); got != c.want {
			t.Errorf("%v %v: %q, want %q", c.tags, c.cwes, got, c.want)
		}
	}
}

func TestReadTarLimits(t *testing.T) {
	if _, err := readTar(bytes.NewReader(tarball(t, []entry{{`top/http\x.yaml`, "x", tar.TypeReg}}))); !errors.Is(err, errArchive) {
		t.Errorf("backslash: %v", err)
	}
	// A header larger than a template may be, or than what follows it.
	for name, size := range map[string]int64{"too large": maxTemplate + 1, "short": 10} {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: "top/http/x.yaml", Mode: 0o644, Typeflag: tar.TypeReg, Size: size})
		tw.Write([]byte("abc"))
		tw.Flush()
		gz.Close()
		if _, err := readTar(bytes.NewReader(buf.Bytes())); !errors.Is(err, errArchive) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A name not in its clean form is not a template.
	got, err := readTar(bytes.NewReader(tarball(t, []entry{{"top/http/./x.yaml", "x", tar.TypeReg}, {"top/http/y.yaml", "y", tar.TypeReg}})))
	if err != nil || len(got) != 1 || got["http/y.yaml"] == nil {
		t.Errorf("got %v, %v", got, err)
	}
	es := make([]entry, maxTemplates+1)
	for i := range es {
		es[i] = entry{fmt.Sprintf("top/http/%d.yaml", i), "", tar.TypeReg}
	}
	if _, err := readTar(bytes.NewReader(tarball(t, es))); !errors.Is(err, errArchive) {
		t.Errorf("%d templates: %v", len(es), err)
	}
	c := &capped{r: strings.NewReader("abcdef"), left: 4}
	if b, err := io.ReadAll(c); err == nil || string(b) != "abcd" {
		t.Errorf("capped: %q, %v", b, err)
	}
}

// placeholderSet: a made-up archive of four templates, one per way a
// template is counted, the last naming a CVE of the host's.
func placeholderSet(t *testing.T, hostCVE string) []byte {
	t.Helper()
	tpl := func(id, tags, cve string) string {
		return "id: " + id + "\ninfo:\n  name: x\n  tags: " + tags + "\n  classification:\n    cve-id: " + cve +
			"\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/abc?a=abc\"\n"
	}
	return tarball(t, []entry{
		{"top/http/a.yaml", tpl("ex-a", "example,lfi", "cve-2099-0001"), tar.TypeReg},
		{"top/http/b.yaml", tpl("ex-b", "example,panel", "cve-2099-0002"), tar.TypeReg},
		{"top/http/c.yaml", tpl("ex-c", "example,rce", "cve-2099-0003"), tar.TypeReg},
		{"top/http/d.yaml", "id: ex-d\ninfo:\n  name: d\n", tar.TypeReg},
		{"top/http/e.yaml", tpl("ex-e", "example,xss", hostCVE), tar.TypeReg},
	})
}

func anyHostCVE(t *testing.T) string {
	t.Helper()
	_, cves, err := hostPackages("../..")
	if err != nil {
		t.Fatal(err)
	}
	for c := range cves {
		return c
	}
	t.Fatal("no host CVE")
	return ""
}

func TestEvaluatorRun(t *testing.T) {
	ev, cases, err := newEvaluator("../..")
	if err != nil {
		t.Fatal(err)
	}
	files, err := readTar(bytes.NewReader(placeholderSet(t, anyHostCVE(t))))
	if err != nil {
		t.Fatal(err)
	}
	normal, _ := normalRequests()
	st := ev.run(files, normal)
	if st.Templates != 5 || st.NotConverted != 1 || st.Unclassified != 1 || st.RCEUnspecified != 1 ||
		len(st.Classes) != 2 || *st.Classes["path"] != (ClassStat{1, 0}) || *st.Classes["xss"] != (ClassStat{1, 0}) ||
		st.Host.Cases != cases || st.Host.TemplatesForCVE != 1 || st.NormalRequests != len(normal) || st.FalsePositives != 0 ||
		st.NormalRoutes != len(normal)/perRoute || st.NormalDistinct < st.NormalRoutes || st.NormalDistinct >= len(normal) {
		t.Errorf("stats %+v", st)
	}
	again := ev.run(files, normal)
	ev.cases++
	moved := ev.run(files, normal)
	if again.GradedHash != st.GradedHash || moved.GradedHash == st.GradedHash {
		t.Errorf("graded hash %s, again %s, with another host %s", st.GradedHash, again.GradedHash, moved.GradedHash)
	}
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	tb, base := dir+"/t.tar.gz", dir+"/baseline.json"
	b := placeholderSet(t, anyHostCVE(t))
	if err := os.WriteFile(tb, b, 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := readTar(bytes.NewReader(b))
	wantHash = manifestHash(files)
	defer func() { wantHash = templatesHash }()
	if rc := run(base, true, "../..", tb); rc != 0 {
		t.Fatalf("write: %d", rc)
	}
	if rc := run(base, false, "../..", tb); rc != 0 {
		t.Errorf("same: %d, want 0", rc)
	}
	raw, _ := os.ReadFile(base)
	for name, edit := range map[string]func(*baseline){
		"false positives": func(x *baseline) { x.FalsePositives++ },
		"host":            func(x *baseline) { x.Stats.Host.VersionUnknown++ },
		"templates hash":  func(x *baseline) { x.TemplatesHash = "0" },
		"normal distinct": func(x *baseline) { x.NormalDistinct++ },
	} {
		var x baseline
		json.Unmarshal(raw, &x)
		edit(&x)
		out, _ := json.Marshal(x)
		os.WriteFile(base, out, 0o600)
		if rc := run(base, false, "../..", tb); rc != 1 {
			t.Errorf("%s changed: %d, want 1", name, rc)
		}
	}
	if rc := run(dir+"/none.json", false, "../..", tb); rc != 2 {
		t.Errorf("no baseline: %d, want 2", rc)
	}
	if rc := run(base, false, dir, tb); rc != 2 {
		t.Errorf("no bench: %d, want 2", rc)
	}
	wantHash = "0"
	if rc := run(base, false, "../..", tb); rc != 3 {
		t.Errorf("hash mismatch: %d, want 3", rc)
	}
	if rc := run(base, false, "../..", dir+"/missing.tar.gz"); rc != 3 {
		t.Errorf("no tarball: %d, want 3", rc)
	}
}

// The limits a run is unlikely to reach, lowered, through the whole path.
func TestLimitsWholePath(t *testing.T) {
	defer func(e int, u, d int64, r time.Duration) { maxEntries, maxUnpacked, maxDownload, retryBase = e, u, d, r }(maxEntries, maxUnpacked, maxDownload, retryBase)
	maxEntries = 3
	if _, err := readTar(bytes.NewReader(tarball(t, []entry{{"top/a", "a", tar.TypeReg}, {"top/b", "b", tar.TypeReg}, {"top/c", "c", tar.TypeReg}, {"top/d", "d", tar.TypeReg}}))); !errors.Is(err, errArchive) {
		t.Errorf("4 entries past 3: %v", err)
	}
	maxEntries, maxUnpacked = 100, 8192
	if _, err := readTar(bytes.NewReader(tarball(t, []entry{{"top/docs/a.md", strings.Repeat("a", 20000), tar.TypeReg}}))); !errors.Is(err, errArchive) {
		t.Errorf("unpacking past the cap, outside http/: %v", err)
	}
	maxDownload, retryBase = 10, time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("a"), 100)) }))
	defer srv.Close()
	if _, err := download(context.Background(), srv.URL, t.TempDir()); !errors.Is(err, errDownload) {
		t.Errorf("downloading past the cap: %v", err)
	}
}
