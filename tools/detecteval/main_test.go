package main

// These tests use made-up templates of Nuclei's shape with placeholder
// values (a=abc): they check the mechanics, and hold no attack string.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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
			h.Linkname, h.Size = "../../etc/x", 0
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
	want := []target{{"GET", "/a/b?x=abc&y=x"}, {"GET", "/"}, {"POST", "/d?e=one"}}
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
}

func TestNormalRequests(t *testing.T) {
	a, err := normalRequests()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := normalRequests()
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
		if rec.Referer != "" && !strings.HasPrefix(rec.Referer, "https://example.com/") && !strings.HasPrefix(rec.Referer, "https://www.example.com/") {
			t.Errorf("%s: referer %q", a[i].ID, rec.Referer)
		}
	}
}
