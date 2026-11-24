package tools

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// pypiFeeds answers OSV as for PyPI: vulns by exact name and version, an
// advisory's aliases, and the KEV catalog; it keeps every query.
type pypiFeeds struct {
	mu      sync.Mutex
	vulns   map[string][]string // name@version → ids
	aliases map[string][]string // id → aliases
	kev     []string            // CVEs in the catalog
	queries []string            // name@version, ecosystem PyPI
}

func (f *pypiFeeds) RoundTrip(r *http.Request) (*http.Response, error) {
	var body any
	switch {
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		var q struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		f.mu.Lock()
		for i, x := range q.Queries {
			key := x.Package.Name + "@" + x.Version
			if x.Package.Ecosystem == "PyPI" {
				f.queries = append(f.queries, key)
			}
			res[i] = map[string]any{}
			var vs []map[string]string
			for _, id := range f.vulns[key] {
				vs = append(vs, map[string]string{"id": id})
			}
			if vs != nil && x.Package.Ecosystem == "PyPI" {
				res[i]["vulns"] = vs
			}
		}
		f.mu.Unlock()
		body = map[string]any{"results": res}
	case strings.Contains(r.URL.Path, "/vulns/"):
		body = map[string]any{"aliases": f.aliases[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]}
	default: // the KEV catalog
		var vs []map[string]string
		for _, c := range f.kev {
			vs = append(vs, map[string]string{"cveID": c, "vulnerabilityName": "Test Bug", "dateAdded": "2026-11-01"})
		}
		body = map[string]any{"vulnerabilities": vs}
	}
	b, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
}

func noSystemSitePackages(t *testing.T) {
	t.Cleanup(SetSitePackagesForTest(nil))
}

// dist writes an installed package: dir/<folder>.dist-info/METADATA with
// name and version, and INSTALLER when installer is set.
func dist(t *testing.T, dir, folder, name, version, installer string) {
	t.Helper()
	d := filepath.Join(dir, folder+".dist-info")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "METADATA"), []byte("Metadata-Version: 2.1\nName: "+name+"\nVersion: "+version+"\nSummary: test\n\nName: not-this\n"), 0o644)
	if installer != "" {
		os.WriteFile(filepath.Join(d, "INSTALLER"), []byte(installer+"\n"), 0o644)
	}
}

// record writes rel under dir with content, and lists it with its sha256
// in the RECORD of folder.dist-info, as pip does.
func record(t *testing.T, dir, folder, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(content), 0o644)
	sum := sha256.Sum256([]byte(content))
	f, err := os.OpenFile(filepath.Join(dir, folder+".dist-info", "RECORD"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "%s,sha256=%s,%d\n", rel, base64.RawURLEncoding.EncodeToString(sum[:]), len(content))
	f.Close()
}

func venvSite(t *testing.T, root, app string) string {
	sp := filepath.Join(root, app, ".venv", "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(sp, 0o755); err != nil {
		t.Fatal(err)
	}
	return sp
}

// A venv's installed packages are checked against OSV as PyPI, by their
// PEP 503 names, and one exploited is marked KEV; a fixed version is not
// reported. On integ no site-packages folder was read.
func TestAppVulnsSitePackages(t *testing.T) {
	noSystemSitePackages(t)
	root := t.TempDir()
	sp := venvSite(t, root, "app")
	dist(t, sp, "LiteLLM-1.30.0", "LiteLLM", "1.30.0", "pip")
	dist(t, sp, "typing_extensions-4.0.0", "typing_extensions", "4.0.0", "")
	dist(t, sp, "requests-2.32.3", "requests", "2.32.3", "pip")
	fixed := venvSite(t, root, "other")
	dist(t, fixed, "litellm-1.80.0", "litellm", "1.80.0", "uv")
	f := &pypiFeeds{
		vulns:   map[string][]string{"litellm@1.30.0": {"GHSA-test-lite"}, "typing-extensions@4.0.0": {"PYSEC-test-1"}},
		aliases: map[string][]string{"GHSA-test-lite": {"CVE-2026-40217"}},
		kev:     []string{"CVE-2026-40217"},
	}
	out, err := AppVulns(context.Background(), &http.Client{Transport: f}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"litellm@1.30.0": true, "typing-extensions@4.0.0": true, "requests@2.32.3": true, "litellm@1.80.0": true}
	if len(f.queries) != len(want) {
		t.Errorf("queries %q", f.queries)
	}
	for _, q := range f.queries {
		if !want[q] {
			t.Errorf("query %q: not a PEP 503 name of an installed package", q)
		}
	}
	files, _ := out["files"].([]AppResult)
	got := map[string]AppResult{}
	for _, r := range files {
		got[r.Path] = r
	}
	r := got[sp]
	if r.Kind != "site-packages" || r.Ecosystem != "PyPI" || r.Packages != 3 || len(r.Affected) != 2 {
		t.Fatalf("%s: %+v (all: %+v)", sp, r, files)
	}
	if len(r.Exploited) != 1 || r.Exploited[0].Package != "litellm" || r.Exploited[0].CVE != "CVE-2026-40217" {
		t.Errorf("exploited %+v", r.Exploited)
	}
	if o := got[fixed]; o.Kind != "site-packages" || o.Packages != 1 || len(o.Affected) != 0 {
		t.Errorf("fixed version: %+v", o)
	}
	if out["site_packages"] != 2 || out["lock_files"] != 0 || out["partial"] != nil {
		t.Errorf("site_packages %v, lock_files %v, partial %v", out["site_packages"], out["lock_files"], out["partial"])
	}
}

func TestPEP503(t *testing.T) {
	for in, want := range map[string]string{"LiteLLM": "litellm", "typing_extensions": "typing-extensions",
		"zope.interface": "zope-interface", "Foo__Bar-.baz": "foo-bar-baz"} {
		if got := pep503(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// .pth lines Python runs are counted, a tool's own file is told apart only
// when every such line is the tool's to the letter, and no line's text is
// kept.
func TestSitePackagesPth(t *testing.T) {
	noSystemSitePackages(t)
	root := t.TempDir()
	sp := venvSite(t, root, "app")
	secret := "sk-" + strings.Repeat("Q", 6) + "-pth-marker" // put together at run time
	nspkg := "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');m = has_mfs and sys.modules.setdefault('google', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('google', [os.path.dirname(p)])));m = m or sys.modules.setdefault('google', types.ModuleType('google'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)"
	files := map[string]string{
		"distutils-precedence.pth":           "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
		"_virtualenv.pth":                    "import _virtualenv",
		"__editable__.mypkg-1.0.pth":         "import __editable___mypkg_1_0_finder; __editable___mypkg_1_0_finder.install()\n",
		"google_auth-2.0.0-py3.12-nspkg.pth": nspkg + "\n",
		"paths.pth":                          "/opt/lib\n# import nothing\n",
		"evil.pth":                           "import os; os.environ['X'] = '" + secret + "'\nimport\tsys\n",
		"__editable__.other-1.0.pth":         "import __editable___other_1_0_finder; __editable___other_1_0_finder.install()\nimport os; os.system('" + secret + "')\n",
		"protobuf-4.0-py3.12-nspkg.pth":      strings.Replace(nspkg, "(p not in mp)", "__import__('os').system('x') or (p not in mp)", 1),
		"__editable__.mixed-1.0.pth":         "import __editable___a_finder; __editable___b_finder.install()\n",
		"easy-install.pth":                   "import sys; sys.__plen = len(sys.path)\n./foo.egg\n",
	}
	files["cr.pth"] = "/opt/lib\rimport os\r"               // Python ends a line at \r too
	files["bom.pth"] = "\ufeffimport os\n"                  // and drops a UTF-8 BOM
	files["vt.pth"] = "/opt/lib\vimport os\n"               // 3.13 splits as str.splitlines()
	files["ls.pth"] = "/opt/lib\u2028import os\n"           // U+2028 too
	files["nel.pth"] = "/opt/lib\x85import os\n"            // and 0x85 read in the locale's encoding
	files["x-nspkg.pth"] = nspkg + "\v__import__('os')\n"   // known up to \v: 3.12 runs it all
	files["y-nspkg.pth"] = nspkg + "\x85__import__('os')\n" // known up to 0x85, not UTF-8: 3.12 and UTF-8 run it all
	for n, c := range files {
		os.WriteFile(filepath.Join(sp, n), []byte(c), 0o644)
	}
	// the modules the known files import, as their tools installed them
	os.WriteFile(filepath.Join(sp, "..", "..", "..", "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0o644)
	dist(t, sp, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, sp, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	dist(t, sp, "mypkg-1.0", "mypkg", "1.0", "pip")
	record(t, sp, "mypkg-1.0", "__editable___mypkg_1_0_finder.py", "def install(): pass\n")
	// the same files where their module is not their tool's: no venv, no
	// setuptools RECORD, a finder changed after install
	bad := venvSite(t, root, "bad")
	os.WriteFile(filepath.Join(bad, "_virtualenv.pth"), []byte(files["_virtualenv.pth"]), 0o644)
	os.WriteFile(filepath.Join(bad, "distutils-precedence.pth"), []byte(files["distutils-precedence.pth"]), 0o644)
	os.WriteFile(filepath.Join(bad, "__editable__.mypkg-1.0.pth"), []byte(files["__editable__.mypkg-1.0.pth"]), 0o644)
	dist(t, bad, "mypkg-1.0", "mypkg", "1.0", "pip")
	record(t, bad, "mypkg-1.0", "__editable___mypkg_1_0_finder.py", "def install(): pass\n")
	os.WriteFile(filepath.Join(bad, "__editable___mypkg_1_0_finder.py"), []byte("import os\n"), 0o644)
	os.Symlink(filepath.Join(sp, "evil.pth"), filepath.Join(bad, "linked.pth"))
	out, err := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	pth, _ := out["pth"].([]PthFile)
	got := map[string]PthFile{}
	for _, f := range pth {
		n := filepath.Base(f.Path)
		if filepath.Dir(f.Path) == bad {
			n = "bad/" + n
		}
		got[n] = f
	}
	want := map[string]PthFile{
		"distutils-precedence.pth":           {ImportLines: 1, Known: "setuptools"},
		"_virtualenv.pth":                    {ImportLines: 1, Known: "virtualenv"},
		"__editable__.mypkg-1.0.pth":         {ImportLines: 1, Known: "editable install"},
		"google_auth-2.0.0-py3.12-nspkg.pth": {ImportLines: 1, Known: "setuptools namespace package"},
		"easy-install.pth":                   {ImportLines: 1, Known: "setuptools"},
		"__editable__.mixed-1.0.pth":         {ImportLines: 1},
		"cr.pth":                             {ImportLines: 1},
		"bom.pth":                            {ImportLines: 1},
		"vt.pth":                             {ImportLines: 1},
		"ls.pth":                             {ImportLines: 1},
		"nel.pth":                            {ImportLines: 1},
		"x-nspkg.pth":                        {ImportLines: 1},
		"y-nspkg.pth":                        {ImportLines: 1},
		"bad/_virtualenv.pth":                {ImportLines: 1},
		"bad/distutils-precedence.pth":       {ImportLines: 1},
		"bad/__editable__.mypkg-1.0.pth":     {ImportLines: 1},
		"evil.pth":                           {ImportLines: 2},
		"__editable__.other-1.0.pth":         {ImportLines: 2},
		"protobuf-4.0-py3.12-nspkg.pth":      {ImportLines: 1},
	}
	if len(got) != len(want) {
		t.Errorf("listed %v", got)
	}
	for n, w := range want {
		g, ok := got[n]
		if w.Path = filepath.Join(sp, n); strings.HasPrefix(n, "bad/") {
			w.Path = filepath.Join(bad, strings.TrimPrefix(n, "bad/"))
		}
		if !ok || g != w {
			t.Errorf("%s: %+v, want %+v", n, g, w)
		}
	}
	if p, _ := out["partial"].(string); !strings.Contains(p, "linked.pth 不是一般檔案") {
		t.Errorf("a symlinked .pth is not said: %q", p)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "os.system") {
		t.Errorf("a .pth line's text is in the result: %s", b)
	}
}

// Past a bound, or a file not read, the scan says what it did not check;
// it reads the first 64 KiB of a METADATA and follows no symlink.
func TestSitePackagesBounds(t *testing.T) {
	noSystemSitePackages(t)
	feeds := &http.Client{Transport: &pypiFeeds{}}
	partial := func(out map[string]any) string { s, _ := out["partial"].(string); return s }

	root := t.TempDir()
	sp := venvSite(t, root, "app")
	dist(t, sp, "big-1.0", "big", "1.0", "pip")
	os.WriteFile(filepath.Join(sp, "big-1.0.dist-info", "METADATA"), []byte("Name: big\nVersion: 1.0\n\n"+strings.Repeat("x", 200<<10)), 0o644)
	nover := filepath.Join(sp, "nover-1.0.dist-info")
	os.MkdirAll(nover, 0o755)
	os.WriteFile(filepath.Join(nover, "METADATA"), []byte("Name: nover\n"), 0o644)
	os.WriteFile(filepath.Join(sp, "huge.pth"), []byte(strings.Repeat("/x\n", 30<<10)), 0o644)
	elsewhere := t.TempDir() // a venv reached only through a symlink
	dist(t, filepath.Join(elsewhere, "site-packages"), "linked-1.0", "linked", "1.0", "pip")
	os.MkdirAll(filepath.Join(root, "l", "lib", "python3.12"), 0o755)
	os.Symlink(filepath.Join(elsewhere, "site-packages"), filepath.Join(root, "l", "lib", "python3.12", "site-packages"))
	os.Symlink(elsewhere, filepath.Join(root, "link"))
	out, _ := AppVulns(context.Background(), feeds, []string{root})
	files, _ := out["files"].([]AppResult)
	if len(files) != 1 || files[0].Path != sp || files[0].Packages != 1 {
		t.Fatalf("files %+v", files)
	}
	p := partial(out)
	if !strings.Contains(p, "1 個套件的 METADATA 讀不到") || !strings.Contains(p, "huge.pth 超過 64 KiB") {
		t.Errorf("partial %q", p)
	}

	old := [3]int{sitePkgDistMax, sitePkgVisits, sitePkgDirsMax}
	t.Cleanup(func() { sitePkgDistMax, sitePkgVisits, sitePkgDirsMax = old[0], old[1], old[2] })
	sitePkgDistMax = 1
	dist(t, sp, "two-1.0", "two", "1.0", "pip")
	out, _ = AppVulns(context.Background(), feeds, []string{root})
	if p := partial(out); !strings.Contains(p, "超過單一資料夾 1 個的上限") {
		t.Errorf("dist cap: %q", p)
	}
	sitePkgDistMax, sitePkgDirsMax = old[0], 1
	venvSite(t, root, "zzz")
	out, _ = AppVulns(context.Background(), feeds, []string{root})
	if p := partial(out); !strings.Contains(p, "site-packages 資料夾超過 1 個") {
		t.Errorf("folder cap: %q", p)
	}
	sitePkgDirsMax, sitePkgVisits = old[2], 3
	out, _ = AppVulns(context.Background(), feeds, []string{root})
	if p := partial(out); !strings.Contains(p, "走到 3 個項目的上限") {
		t.Errorf("walk cap: %q", p)
	}
}

// In the system's folders under /usr/lib the OS package manager installs
// too: only a package pip (or its like) wrote INSTALLER for is read there;
// /usr/local's are all read. A path asked about leaves the system's out.
func TestSitePackagesSystem(t *testing.T) {
	sys := t.TempDir()
	managed := filepath.Join(sys, "usr", "lib", "python3.12", "dist-packages")
	local := filepath.Join(sys, "usr", "local", "lib", "python3.12", "dist-packages")
	os.MkdirAll(managed, 0o755)
	os.MkdirAll(local, 0o755)
	dist(t, managed, "fromapt-1.0", "fromapt", "1.0", "")
	dist(t, managed, "fromdebian-1.0", "fromdebian", "1.0", "debian")
	dist(t, managed, "frompip-1.0", "frompip", "1.0", "pip")
	os.WriteFile(filepath.Join(managed, "oldstyle-1.0.egg-info"), []byte("Name: oldstyle\nVersion: 1.0\n"), 0o644)
	dist(t, local, "bylocal-1.0", "bylocal", "1.0", "")
	t.Cleanup(SetSitePackagesForTest([]string{filepath.Join(sys, "usr", "lib", "python3*", "dist-packages"), filepath.Join(sys, "usr", "local", "lib", "python3*", "dist-packages")}))
	oldP := osManagedPrefixes
	osManagedPrefixes = []string{filepath.Join(sys, "usr", "lib") + "/"}
	t.Cleanup(func() { osManagedPrefixes = oldP })
	f := &pypiFeeds{}
	if _, err := AppVulns(context.Background(), &http.Client{Transport: f}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.queries, " ") != "frompip@1.0 bylocal@1.0" {
		t.Errorf("queries %q, want frompip and bylocal only", f.queries)
	}
	// The system's own setuptools keeps no RECORD (Debian): its
	// distutils-precedence.pth is setuptools' where the package manager's
	// files are root's alone; not in /usr/local, not a file others can write.
	pthText := "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
	os.WriteFile(filepath.Join(local, "distutils-precedence.pth"), []byte(pthText), 0o644)
	os.WriteFile(filepath.Join(managed, "distutils-precedence.pth"), []byte(pthText), 0o644)
	os.MkdirAll(filepath.Join(managed, "_distutils_hack"), 0o755)
	os.WriteFile(filepath.Join(managed, "_distutils_hack", "__init__.py"), []byte("def add_shim(): pass\n"), 0o644)
	known := func() map[string]string {
		out, _ := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, nil)
		m := map[string]string{}
		pth, _ := out["pth"].([]PthFile)
		for _, p := range pth {
			m[filepath.Dir(p.Path)] = p.Known
		}
		return m
	}
	oldRoot := rootOnly
	t.Cleanup(func() { rootOnly = oldRoot })
	rootOnly = func(string, bool) bool { return true } // as root installed them
	if k := known(); k[managed] != "setuptools" || k[local] != "" {
		t.Errorf("root's own: %q", k)
	}
	rootOnly = func(p string, _ bool) bool { return !strings.HasSuffix(p, "__init__.py") } // a module others can write
	if k := known(); k[managed] != "" {
		t.Errorf("a module not root's alone: %q", k)
	}
	// another _distutils_hack, earlier on sys.path (/usr/local), not
	// setuptools': the system's .pth would import it
	rootOnly = func(string, bool) bool { return true }
	os.Remove(filepath.Join(local, "distutils-precedence.pth"))
	if k := known(); k[managed] != "setuptools" {
		t.Errorf("before the shadow: %q", k)
	}
	os.WriteFile(filepath.Join(local, "_distutils_hack.py"), []byte("import os\n"), 0o644)
	if k := known(); k[managed] != "" {
		t.Errorf("a shadowing _distutils_hack.py: %q", k)
	}
	f.queries = nil
	if _, err := appVulnsIn(context.Background(), &http.Client{Transport: f}, []string{t.TempDir()}, false); err != nil || len(f.queries) != 0 {
		t.Errorf("a path asked about read the system's: %q %v", f.queries, err)
	}
}
