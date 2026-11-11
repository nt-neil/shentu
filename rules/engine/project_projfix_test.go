package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

// A file kept again (parsed for another file's call, then scanned itself)
// counts once: resident is the sum of the files held, and the LRU names each
// file once, so the cache still lets files go when it is full.
func TestProjectKeepTwice(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['x']);\n",
		"b.php": "<?php\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n",
	}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	pr := e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
	for _, f := range []string{"a.php", "b.php", "b.php", "a.php"} {
		if _, _, err := pr.ScanCallsTimed(f, []byte(files[f])); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	sum := 0
	for _, c := range pr.ctx {
		sum += c.tokens
	}
	seen := map[string]bool{}
	for _, f := range pr.lru {
		if seen[f] {
			t.Errorf("lru %v names %s twice", pr.lru, f)
		}
		seen[f] = true
	}
	if pr.resident != sum || len(pr.lru) != len(pr.ctx) {
		t.Errorf("resident %d, tokens held %d; lru %v for %d files held", pr.resident, sum, pr.lru, len(pr.ctx))
	}
}

// A constant define()d in the callee's file is a fixed prefix there, whatever
// file the call came from and whichever file is scanned first.
func TestProjectCalleeDefines(t *testing.T) {
	e := engineForTest(t)
	ssrf := func(fs []Finding) (out []Finding) {
		for _, f := range fs {
			if strings.Contains(f.RuleID, "ssrf") {
				out = append(out, f)
			}
		}
		return out
	}
	caller := "<?php\nrequire 'b.php';\nfetch_api($_GET['p']);\n"
	for _, c := range []struct {
		name, callee string
		want         bool
	}{
		{"defined host", "<?php\ndefine('MY_API', 'https://api.example.com/');\nfunction fetch_api($p) {\n\treturn wp_remote_get(MY_API . $p);\n}\n", false},
		{"no prefix", "<?php\nfunction fetch_api($p) {\n\treturn wp_remote_get($p);\n}\n", true},
	} {
		files := map[string]string{"a.php": caller, "b.php": c.callee}
		read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
		for _, order := range [][]string{{"a.php", "b.php"}, {"b.php", "a.php"}} {
			pr := e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
			var got []Finding
			for _, f := range order {
				fs, _, err := pr.ScanCallsTimed(f, []byte(files[f]))
				if err != nil {
					t.Fatalf("%s %s: %v", c.name, f, err)
				}
				got = append(got, ssrf(fs)...)
			}
			if (len(got) > 0) != c.want {
				t.Errorf("%s, scanned %v: SSRF findings %v, want reported = %v", c.name, order, got, c.want)
			}
		}
	}
}

// The index cache is kept only for the route models and limits it was made
// with: a file indexed again under other route models or limits gets the
// routes and the Limited mark those give.
func TestProjectIndexCacheKey(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{"r.php": "<?php\nRoute::get('/user/{id}', [UserController::class, 'show']);\n"}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	cache := filepath.Join(t.TempDir(), "codeindex.json")
	pr := e.NewProject([]string{"r.php"}, read, ProjectOptions{CacheFile: cache})
	if fi := pr.files["r.php"]; fi == nil || len(fi.Routes) == 0 || fi.Limited {
		t.Fatalf("indexed with the route models: %+v", fi)
	}

	noRoutes := *e
	noRoutes.routes = map[string][]*croute{}
	if fi := noRoutes.NewProject([]string{"r.php"}, read, ProjectOptions{CacheFile: cache}).files["r.php"]; fi == nil || len(fi.Routes) != 0 {
		t.Errorf("without route models, from the cache: %+v; want no routes", fi)
	}

	small := *e
	small.Limits.MaxTokens = 5
	if fi := small.NewProject([]string{"r.php"}, read, ProjectOptions{CacheFile: cache}).files["r.php"]; fi == nil || !fi.Limited {
		t.Errorf("with a 5-token limit, from the cache: %+v; want Limited", fi)
	}
}
