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
		"paths.pth":                          "extra-lib\n# import nothing\n",
		"evil.pth":                           "import os; os.environ['X'] = '" + secret + "'\nimport\tsys\n",
		"__editable__.other-1.0.pth":         "import __editable___other_1_0_finder; __editable___other_1_0_finder.install()\nimport os; os.system('" + secret + "')\n",
		"protobuf-4.0-py3.12-nspkg.pth":      strings.Replace(nspkg, "(p not in mp)", "__import__('os').system('x') or (p not in mp)", 1),
		"__editable__.mixed-1.0.pth":         "import __editable___a_finder; __editable___b_finder.install()\n",
		"easy-install.pth":                   "import sys; sys.__plen = len(sys.path)\n./foo.egg\n", // B3: a folder put first
		"evil2-nspkg.pth":                    nspkg + "\n",                                          // B2: the template, no package behind it
	}
	files["cr.pth"] = "extra-lib\rimport os\r"              // Python ends a line at \r too
	files["bom.pth"] = "\ufeffimport os\n"                  // and drops a UTF-8 BOM
	files["vt.pth"] = "extra-lib\vimport os\n"              // 3.13 splits as str.splitlines()
	files["ls.pth"] = "extra-lib\u2028import os\n"          // U+2028 too
	files["nel.pth"] = "extra-lib\x85import os\n"           // and 0x85 read in the locale's encoding
	files["x-nspkg.pth"] = nspkg + "\v__import__('os')\n"   // known up to \v: 3.12 runs it all
	files["y-nspkg.pth"] = nspkg + "\x85__import__('os')\n" // known up to 0x85, not UTF-8: 3.12 and UTF-8 run it all
	for n, c := range files {
		os.WriteFile(filepath.Join(sp, n), []byte(c), 0o644)
	}
	// the tools' own records of the known files: virtualenv's key, the
	// RECORDs of setuptools, of the editable install and of the nspkg's
	os.WriteFile(filepath.Join(sp, "..", "..", "..", "pyvenv.cfg"), []byte("home = /usr/bin\nvirtualenv = 20.25.0\n"), 0o644)
	os.WriteFile(filepath.Join(sp, "_virtualenv.py"), []byte("def x(): pass\n"), 0o644)
	dist(t, sp, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, sp, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	dist(t, sp, "mypkg-1.0", "mypkg", "1.0", "pip")
	record(t, sp, "mypkg-1.0", "__editable___mypkg_1_0_finder.py", "def install(): pass\n")
	dist(t, sp, "google_auth-2.0.0", "google-auth", "2.0.0", "pip")
	record(t, sp, "google_auth-2.0.0", "google_auth-2.0.0-py3.12-nspkg.pth", files["google_auth-2.0.0-py3.12-nspkg.pth"])
	// another venv root's alone: B1 (a plain venv, no virtualenv key),
	// and an easy-install.pth with no folder that its RECORD lists
	app2 := venvSite(t, root, "app2")
	os.WriteFile(filepath.Join(app2, "..", "..", "..", "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0o644)
	os.WriteFile(filepath.Join(app2, "_virtualenv.pth"), []byte("import _virtualenv\n"), 0o644)
	os.WriteFile(filepath.Join(app2, "_virtualenv.py"), []byte("import os\n"), 0o644)
	dist(t, app2, "eggs-1.0", "eggs", "1.0", "pip")
	record(t, app2, "eggs-1.0", "easy-install.pth", "import sys; sys.__plen = len(sys.path)\n")
	// a venv a user can write: the same files, records and all, are not
	// proven (B4: a RECORD written next to its module); a finder changed
	// after install, no virtualenv key: ones to look at
	bad := venvSite(t, root, "bad")
	os.WriteFile(filepath.Join(bad, "..", "..", "..", "pyvenv.cfg"), []byte("virtualenv = 20.25.0\n"), 0o644)
	os.WriteFile(filepath.Join(bad, "_virtualenv.pth"), []byte(files["_virtualenv.pth"]), 0o644)
	os.WriteFile(filepath.Join(bad, "distutils-precedence.pth"), []byte(files["distutils-precedence.pth"]), 0o644)
	dist(t, bad, "setuptools-99.0.0", "setuptools", "99.0.0", "pip")
	record(t, bad, "setuptools-99.0.0", "_distutils_hack/__init__.py", "import os\n")
	os.WriteFile(filepath.Join(bad, "__editable__.mypkg-1.0.pth"), []byte(files["__editable__.mypkg-1.0.pth"]), 0o644)
	dist(t, bad, "mypkg-1.0", "mypkg", "1.0", "pip")
	record(t, bad, "mypkg-1.0", "__editable___mypkg_1_0_finder.py", "def install(): pass\n")
	os.WriteFile(filepath.Join(bad, "__editable___mypkg_1_0_finder.py"), []byte("import os\n"), 0o644)
	// app3, root's alone: an easy-install.pth its RECORD lists, with a
	// folder in it (put first on sys.path)
	app3 := venvSite(t, root, "app3")
	dist(t, app3, "eggs-1.0", "eggs", "1.0", "pip")
	record(t, app3, "eggs-1.0", "easy-install.pth", "import sys; sys.__plen = len(sys.path)\neggs-dir\n")
	// upper: the folder and its files root's, a folder above it a user's
	upper := venvSite(t, root, "upper")
	os.WriteFile(filepath.Join(upper, "distutils-precedence.pth"), []byte(files["distutils-precedence.pth"]), 0o644)
	dist(t, upper, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, upper, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	// root's alone: app, app2, app3, the folders above them, and the
	// site-packages of upper (not the folders above it); bad is a user's
	appDir, app2Dir := filepath.Join(root, "app"), filepath.Join(root, "app2")
	oldRoot := rootOnly
	t.Cleanup(func() { rootOnly = oldRoot })
	rootOnly = func(p string, _ bool) bool {
		if p == upper || strings.HasPrefix(p, upper+string(filepath.Separator)) {
			return true
		}
		if strings.HasPrefix(p, filepath.Join(root, "upper")) {
			return false
		}
		for _, d := range []string{appDir, app2Dir, filepath.Join(root, "app3")} {
			if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) || strings.HasPrefix(d, p+string(filepath.Separator)) || p == string(filepath.Separator) {
				return true
			}
		}
		return false
	}
	out, err := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	pth, _ := out["pth"].([]PthFile)
	got := map[string]PthFile{}
	for _, f := range pth {
		n := filepath.Base(f.Path)
		switch filepath.Dir(f.Path) {
		case bad:
			n = "bad/" + n
		case app2:
			n = "app2/" + n
		case app3:
			n = "app3/" + n
		case upper:
			n = "upper/" + n
		}
		got[n] = f
	}
	want := map[string]PthFile{
		"distutils-precedence.pth":           {ImportLines: 1, Known: "setuptools"},
		"_virtualenv.pth":                    {ImportLines: 1, Known: "virtualenv"},
		"__editable__.mypkg-1.0.pth":         {ImportLines: 1, Known: "editable install"},
		"google_auth-2.0.0-py3.12-nspkg.pth": {ImportLines: 1, Known: "setuptools namespace package"},
		"easy-install.pth":                   {ImportLines: 1}, // B3
		"evil2-nspkg.pth":                    {ImportLines: 1}, // B2
		"app2/_virtualenv.pth":               {ImportLines: 1}, // B1
		"app2/easy-install.pth":              {ImportLines: 1, Known: "setuptools"},
		"app3/easy-install.pth":              {ImportLines: 1},                         // a folder in it
		"upper/distutils-precedence.pth":     {ImportLines: 1, Unproven: "setuptools"}, // a folder above a user's
		"__editable__.mixed-1.0.pth":         {ImportLines: 1},
		"cr.pth":                             {ImportLines: 1},
		"bom.pth":                            {ImportLines: 1},
		"vt.pth":                             {ImportLines: 1},
		"ls.pth":                             {ImportLines: 1},
		"nel.pth":                            {ImportLines: 1},
		"x-nspkg.pth":                        {ImportLines: 1},
		"y-nspkg.pth":                        {ImportLines: 1},
		"bad/_virtualenv.pth":                {ImportLines: 1, Unproven: "virtualenv"},
		"bad/distutils-precedence.pth":       {ImportLines: 1, Unproven: "setuptools"}, // B4
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
		switch w.Path = filepath.Join(sp, n); {
		case strings.HasPrefix(n, "bad/"):
			w.Path = filepath.Join(bad, strings.TrimPrefix(n, "bad/"))
		case strings.HasPrefix(n, "app2/"):
			w.Path = filepath.Join(app2, strings.TrimPrefix(n, "app2/"))
		case strings.HasPrefix(n, "app3/"):
			w.Path = filepath.Join(app3, strings.TrimPrefix(n, "app3/"))
		case strings.HasPrefix(n, "upper/"):
			w.Path = filepath.Join(upper, strings.TrimPrefix(n, "upper/"))
		}
		if !ok || g != w {
			t.Errorf("%s: %+v, want %+v", n, g, w)
		}
	}
	// a symlinked .pth: said, and the folders it may add are unknown
	os.Symlink(filepath.Join(sp, "evil.pth"), filepath.Join(bad, "linked.pth"))
	out, _ = AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{root})
	if p, _ := out["partial"].(string); !strings.Contains(p, "linked.pth 不是一般檔案") {
		t.Errorf("a symlinked .pth is not said: %q", p)
	}
	pth, _ = out["pth"].([]PthFile)
	for _, f := range pth {
		if filepath.Base(f.Path) == "distutils-precedence.pth" && (f.Known != "" || f.Unproven != "") {
			t.Errorf("known with a .pth not read: %+v", f)
		}
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

	// a venv 8 folders below the root: not looked into, and said (N-239-2)
	deepRoot := t.TempDir()
	deepSP := venvSite(t, filepath.Join(deepRoot, "a", "b", "c", "d", "e", "f", "g", "h"), "app")
	dist(t, deepSP, "litellm-1.30.0", "litellm", "1.30.0", "pip")
	out, _ = AppVulns(context.Background(), feeds, []string{deepRoot})
	if p := partial(out); !strings.Contains(p, "超過 8 層") || out["site_packages"] != 0 {
		t.Errorf("deep venv: site_packages %v, partial %q", out["site_packages"], p)
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
	rootOnly = func(p string, _ bool) bool { return p != filepath.Join(sys, "usr", "lib") } // a folder above a user's
	if k := known(); k[managed] != "" {
		t.Errorf("a folder above not root's alone: %q", k)
	}
	// another _distutils_hack, earlier on sys.path (/usr/local), not
	// setuptools': the system's .pth would import it
	rootOnly = func(string, bool) bool { return true }
	os.Remove(filepath.Join(local, "distutils-precedence.pth"))
	if k := known(); k[managed] != "setuptools" {
		t.Errorf("before the shadow: %q", k)
	}
	for _, shadow := range []string{"_distutils_hack.py", "_distutils_hack.cpython-312-x86_64-linux-gnu.so", "_distutils_hack.pyc"} {
		os.WriteFile(filepath.Join(local, shadow), []byte("x"), 0o644)
		if k := known(); k[managed] != "" {
			t.Errorf("a shadowing %s: %q", shadow, k)
		}
		os.Remove(filepath.Join(local, shadow))
	}
	// one in a folder a .pth path line adds
	extra := t.TempDir()
	os.WriteFile(filepath.Join(local, "extra.pth"), []byte(extra+"\n"), 0o644)
	if k := known(); k[managed] != "setuptools" {
		t.Errorf("an empty added folder: %q", k)
	}
	os.WriteFile(filepath.Join(extra, "_distutils_hack.py"), []byte("x"), 0o644)
	if k := known(); k[managed] != "" {
		t.Errorf("a shadow in a folder a .pth adds: %q", k)
	}
	os.Remove(filepath.Join(extra, "_distutils_hack.py"))
	os.WriteFile(filepath.Join(local, "extra.pth"), []byte(extra+"\u3000\x1f\n"), 0o644) // Python strips these too
	os.WriteFile(filepath.Join(extra, "_distutils_hack.py"), []byte("x"), 0o644)
	if k := known(); k[managed] != "" {
		t.Errorf("a path line ending in U+3000: %q", k)
	}
	os.Remove(filepath.Join(extra, "_distutils_hack.py"))
	zip := filepath.Join(t.TempDir(), "hack.zip") // a zip on sys.path is imported from
	os.WriteFile(zip, []byte("PK"), 0o644)
	os.WriteFile(filepath.Join(local, "zip.pth"), []byte(zip+"\n"), 0o644)
	if k := known(); k[managed] != "" {
		t.Errorf("a zip added: %q", k)
	}
	os.Remove(filepath.Join(local, "zip.pth"))
	os.WriteFile(filepath.Join(local, "extra.pth"), []byte(extra+"\n"), 0o644)
	// a path line in UTF-8 with 0x85 in a character (Å is C3 85): one
	// folder, not cut there (S-239-1)
	aring := filepath.Join(t.TempDir(), "hackÅdir")
	os.MkdirAll(aring, 0o755)
	os.WriteFile(filepath.Join(local, "extra.pth"), []byte(aring+"\n"), 0o644)
	if k := known(); k[managed] != "setuptools" {
		t.Errorf("an empty folder named with Å: %q", k)
	}
	os.WriteFile(filepath.Join(aring, "_distutils_hack.py"), []byte("x"), 0o644)
	if k := known(); k[managed] != "" {
		t.Errorf("a shadow in a folder named with Å: %q", k)
	}
	os.Remove(filepath.Join(aring, "_distutils_hack.py"))
	os.WriteFile(filepath.Join(local, "extra.pth"), []byte(extra+"\n"), 0o644)
	os.Chmod(extra, 0) // an added folder that cannot be listed
	if k := known(); k[managed] != "" && os.Getuid() != 0 {
		t.Errorf("an added folder not listed: %q", k)
	}
	os.Chmod(extra, 0o755)
	os.WriteFile(filepath.Join(local, "big.pth"), []byte(strings.Repeat("#\n", 40<<10)), 0o644) // past 64 KiB
	if k := known(); k[managed] != "" {
		t.Errorf("a .pth not read whole: %q", k)
	}
	os.Remove(filepath.Join(local, "big.pth"))
	if k := known(); k[managed] != "setuptools" {
		t.Errorf("after: %q", k)
	}
	// the walk cut short: not every folder was looked at
	oldV := sitePkgVisits
	t.Cleanup(func() { sitePkgVisits = oldV })
	sitePkgVisits = 0
	out, _ := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{t.TempDir()})
	pth, _ := out["pth"].([]PthFile)
	for _, p := range pth {
		if p.Known != "" {
			t.Errorf("known after a cut walk: %+v", p)
		}
	}
	sitePkgVisits = oldV
	f.queries = nil
	if _, err := appVulnsIn(context.Background(), &http.Client{Transport: f}, []string{t.TempDir()}, false); err != nil || len(f.queries) != 0 {
		t.Errorf("a path asked about read the system's: %q %v", f.queries, err)
	}
}

// A _distutils_hack in the system package manager's folder is the system's
// only with every folder above it root's alone: else it may shadow
// setuptools' own, and no distutils-precedence.pth is known.
func TestSitePackagesShadowFoldersAbove(t *testing.T) {
	sys := t.TempDir()
	managed := filepath.Join(sys, "usr", "lib", "python3.12", "dist-packages")
	local := filepath.Join(sys, "usr", "local", "lib", "python3.12", "dist-packages")
	os.MkdirAll(filepath.Join(managed, "_distutils_hack"), 0o755)
	os.WriteFile(filepath.Join(managed, "_distutils_hack", "__init__.py"), []byte("def add_shim(): pass\n"), 0o644)
	os.MkdirAll(local, 0o755)
	os.WriteFile(filepath.Join(local, "distutils-precedence.pth"), []byte("import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"), 0o644)
	dist(t, local, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, local, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	t.Cleanup(SetSitePackagesForTest([]string{managed, local}))
	oldP, oldRoot := osManagedPrefixes, rootOnly
	t.Cleanup(func() { osManagedPrefixes, rootOnly = oldP, oldRoot })
	osManagedPrefixes = []string{filepath.Join(sys, "usr", "lib") + "/"}
	known := func() string {
		out, _ := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, nil)
		pth, _ := out["pth"].([]PthFile)
		for _, p := range pth {
			if filepath.Dir(p.Path) == local {
				return p.Known
			}
		}
		return "not listed"
	}
	rootOnly = func(string, bool) bool { return true }
	if k := known(); k != "setuptools" {
		t.Errorf("all root's: %q", k)
	}
	rootOnly = func(p string, _ bool) bool { return p != filepath.Join(sys, "usr", "lib") }
	if k := known(); k != "" {
		t.Errorf("the system's _distutils_hack under a folder a user can write: %q", k)
	}
}
