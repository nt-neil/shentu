package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

func TestCases(t *testing.T) {
	cases, err := loadCases("../../bench/cves")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 40 || len(cases) > 60 {
		t.Errorf("%d cases, want 40 to 60", len(cases))
	}
	wp := 0
	for _, c := range cases {
		if c.Ecosystem == "wordpress-plugin" {
			wp++
		}
	}
	if 2*wp <= len(cases) {
		t.Errorf("%d of %d cases are WordPress plugins, want more than half", wp, len(cases))
	}
}

func TestCaseChecks(t *testing.T) {
	good := Case{ID: "CVE-2024-12345", Ecosystem: "npm", Package: "@scope/pkg", Vulnerable: "1.0.0", Fixed: "1.0.1",
		Class: "sqli", Lang: "js", SourceURL: "https://github.com/advisories/GHSA-xxxx", Note: "A plain sentence.",
		FixFiles: []FixFile{{Path: "lib/a.js", Vulnerable: [][]int{{3, 4}}, Fixed: [][]int{{3, 5}}}}, file: "x/CVE-2024-12345.toml"}
	if err := good.check(); err != nil {
		t.Fatalf("good case: %v", err)
	}
	for name, mod := range map[string]func(*Case){
		"file name":         func(c *Case) { c.file = "x/other.toml" },
		"lang":              func(c *Case) { c.Lang = "php" },
		"class":             func(c *Case) { c.Class = "xss" },
		"same versions":     func(c *Case) { c.Fixed = c.Vulnerable },
		"version slash":     func(c *Case) { c.Fixed = "../1" },
		"source host":       func(c *Case) { c.SourceURL = "https://example.com/CVE-2024-12345" },
		"source http":       func(c *Case) { c.SourceURL = "http://nvd.nist.gov/vuln/detail/CVE-2024-12345" },
		"source path":       func(c *Case) { c.SourceURL = "https://github.com/someone/repo" },
		"note code":         func(c *Case) { c.Note = "calls eval($x);" },
		"note newline":      func(c *Case) { c.Note = "one\ntwo" },
		"path escape":       func(c *Case) { c.FixFiles[0].Path = "../a.js" },
		"path unclean":      func(c *Case) { c.FixFiles[0].Path = "lib//a.js" },
		"path vendor":       func(c *Case) { c.FixFiles[0].Path = "node_modules/x/a.js" },
		"path language":     func(c *Case) { c.FixFiles[0].Path = "lib/a.py" },
		"range order":       func(c *Case) { c.FixFiles[0].Vulnerable = [][]int{{5, 4}} },
		"range shape":       func(c *Case) { c.FixFiles[0].Fixed = [][]int{{5}} },
		"no fixed range":    func(c *Case) { c.FixFiles[0].Fixed = nil },
		"no fix files":      func(c *Case) { c.FixFiles = nil },
		"wordpress package": func(c *Case) { c.Ecosystem, c.Lang, c.FixFiles[0].Path = "wordpress-plugin", "php", "a.php" },
	} {
		c := good
		c.FixFiles = []FixFile{good.FixFiles[0]}
		mod(&c)
		if err := c.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTarget(t *testing.T) {
	dest := t.TempDir()
	for name, want := range map[string]string{
		"pkg/a.php":          filepath.Join(dest, "a.php"),
		"pkg/./b/../c.php":   filepath.Join(dest, "c.php"),
		"pkg/":               "",
		"a.php":              "",
		"pkg/../a.php":       "",
		"../a.php":           "error",
		"pkg/../../a.php":    "error",
		"/etc/passwd":        "error",
		`pkg\..\..\a.php`:    "error",
		"pkg/a\x00.php":      "error",
		"pkg/x/../../../a.p": "error",
	} {
		got, err := target(dest, name)
		if want == "error" {
			if !errors.Is(err, errEscape) {
				t.Errorf("%q: got %q, %v; want an escape error", name, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", name, got, err, want)
		}
	}
}

func writeZip(t *testing.T, entries func(*zip.Writer)) string {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	entries(w)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func zipFile(t *testing.T, w *zip.Writer, name, body string, mode fs.FileMode) {
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(body))
}

func TestUnpackZip(t *testing.T) {
	archive := writeZip(t, func(w *zip.Writer) {
		zipFile(t, w, "pkg/", "", fs.ModeDir|0o755)
		zipFile(t, w, "pkg/src/a.php", "<?php echo 1;", 0o755)
		zipFile(t, w, "pkg/readme.txt", "text", 0o644)
		zipFile(t, w, "pkg/link.php", "/etc/passwd", fs.ModeSymlink|0o777)
	})
	dest := t.TempDir()
	if err := unpack(archive, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "src", "a.php"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Errorf("a.php is executable: %v", info.Mode())
	}
	for _, skipped := range []string{"readme.txt", "link.php"} {
		if _, err := os.Lstat(filepath.Join(dest, skipped)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was written: %v", skipped, err)
		}
	}
}

func TestUnpackZipSlip(t *testing.T) {
	outside := t.TempDir()
	dest := filepath.Join(outside, "release")
	os.Mkdir(dest, 0o755)
	for _, name := range []string{"pkg/../../evil.php", "../evil.php", "/tmp/evil.php", `pkg\..\..\evil.php`} {
		archive := writeZip(t, func(w *zip.Writer) {
			zipFile(t, w, "pkg/ok.php", "<?php", 0o644)
			zipFile(t, w, name, "<?php", 0o644)
		})
		if err := unpack(archive, dest); !errors.Is(err, errEscape) {
			t.Errorf("%q: got %v, want an escape error", name, err)
		}
		if _, err := os.Stat(filepath.Join(outside, "evil.php")); err == nil {
			t.Fatalf("%q: a file was written outside the release directory", name)
		}
		os.Remove(filepath.Join(dest, "ok.php"))
	}
}

func TestUnpackZipDuplicate(t *testing.T) {
	archive := writeZip(t, func(w *zip.Writer) {
		zipFile(t, w, "pkg/a.php", "<?php // first", 0o644)
		zipFile(t, w, "pkg/a.php", "<?php // second", 0o644)
	})
	if err := unpack(archive, t.TempDir()); err == nil {
		t.Error("a second entry with the same name was accepted")
	}
}

func writeTarGz(t *testing.T, entries []tar.Header, bodies map[string]string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		h := h
		body := bodies[h.Name]
		h.Size = int64(len(body))
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	name := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestUnpackTarLinks(t *testing.T) {
	outside := t.TempDir()
	dest := filepath.Join(outside, "release")
	os.Mkdir(dest, 0o755)
	// A link to a directory outside, then a file "through" it: the link is not
	// created, so the file lands in a real directory inside dest.
	archive := writeTarGz(t, []tar.Header{
		{Name: "package/out", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777},
		{Name: "package/hard.js", Typeflag: tar.TypeLink, Linkname: "/etc/passwd", Mode: 0o644},
		{Name: "package/out/x.js", Typeflag: tar.TypeReg, Mode: 0o755},
	}, map[string]string{"package/out/x.js": "1"})
	if err := unpack(archive, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dest, "out"))
	if err != nil || !info.IsDir() {
		t.Fatalf("out is not a plain directory: %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "x.js")); err == nil {
		t.Fatal("x.js was written through the link")
	}
	if _, err := os.Lstat(filepath.Join(dest, "hard.js")); err == nil {
		t.Error("hard link was created")
	}

	bad := writeTarGz(t, []tar.Header{{Name: "package/../../evil.js", Typeflag: tar.TypeReg, Mode: 0o644}}, map[string]string{"package/../../evil.js": "1"})
	if err := unpack(bad, dest); !errors.Is(err, errEscape) {
		t.Errorf("got %v, want an escape error", err)
	}
	link := writeTarGz(t, []tar.Header{{Name: "../link", Typeflag: tar.TypeSymlink, Linkname: "/", Mode: 0o777}}, nil)
	if err := unpack(link, dest); !errors.Is(err, errEscape) {
		t.Errorf("link name outside: got %v, want an escape error", err)
	}
}

func TestRegistryMetadata(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	loc, err := pypiSdist([]byte(`{"urls":[{"packagetype":"bdist_wheel","filename":"a.whl","url":"https://files.pythonhosted.org/a.whl"},
		{"packagetype":"sdist","filename":"a-1.0.tar.gz","url":"https://files.pythonhosted.org/a-1.0.tar.gz","digests":{"sha256":"` + hex.EncodeToString(sum[:]) + `"}}]}`))
	if err != nil || loc.ext != ".tar.gz" || !strings.HasSuffix(loc.url, "a-1.0.tar.gz") || len(loc.want) != 32 {
		t.Errorf("pypi: %+v, %v", loc, err)
	}
	if _, err := pypiSdist([]byte(`{"urls":[{"packagetype":"sdist","filename":"a-1.0.tar.gz","url":"https://x"}]}`)); err == nil {
		t.Error("pypi sdist without a digest was accepted")
	}
	if _, err := npmTarball([]byte(`{"dist":{"tarball":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","shasum":"abc"}}`)); err == nil {
		t.Error("npm tarball without sha512 integrity was accepted")
	}
	for _, raw := range []string{"http://downloads.wordpress.org/plugin/a.zip", "https://evil.example/a.zip", "https://registry.npmjs.org:8443/a"} {
		f := &fetcher{client: newClient()}
		if _, err := f.open(raw); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%s: got %v, want a refusal", raw, err)
		}
	}
}

func TestJudge(t *testing.T) {
	rs := []rules.Rule{
		{ID: "php-sqli-a", Lang: "php", Class: "sqli"},
		{ID: "php-sqli-b", Lang: "php", Class: "sqli"},
		{ID: "php-cmdi-a", Lang: "php", Class: "cmdi"},
	}
	r := caseResult{Case: Case{Lang: "php", Class: "sqli", FixFiles: []FixFile{{Path: "a.php", Vulnerable: [][]int{{100, 102}}, Fixed: [][]int{{100, 105}}}}}}
	r.Vuln.Findings = []engine.Finding{
		{RuleID: "php-sqli-a", Path: "a.php", Line: 112}, // 10 after the range: at the fix
		{RuleID: "php-sqli-b", Path: "a.php", Line: 200}, // elsewhere in the file
		{RuleID: "php-sqli-b", Path: "b.php", Line: 101}, // another file
		{RuleID: "php-cmdi-a", Path: "a.php", Line: 101}, // another class
	}
	r.FixedScan.Findings = []engine.Finding{{RuleID: "php-sqli-a", Path: "a.php", Line: 90}, {RuleID: "php-sqli-b", Path: "a.php", Line: 101}}
	judge(&r, rs)
	if !r.Caught || !r.FixedFP || r.InFixFiles != 2 || len(r.Rules) != 2 {
		t.Fatalf("got %+v", r)
	}
	if a, b := r.Rules[0], r.Rules[1]; !a.Vuln || !a.Fixed || b.Vuln || !b.Fixed {
		t.Errorf("rules: %+v", r.Rules)
	}

	r = caseResult{Case: r.Case}
	r.Vuln.Findings = []engine.Finding{{RuleID: "php-sqli-a", Path: "a.php", Line: 89}}
	judge(&r, rs)
	if r.Caught || r.FixedFP {
		t.Errorf("a finding 11 lines before the range counted: %+v", r)
	}
}
