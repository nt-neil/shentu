package engine

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// projectScan indexes files and scans them all, returning "path:line" findings.
func projectScan(t *testing.T, e *Engine, files map[string]string, opt ProjectOptions) ([]string, *Project) {
	t.Helper()
	got, pr, errs := projectScanErrs(t, e, files, opt)
	for p, err := range errs {
		if !(errors.Is(err, ErrCalls) && pr.Stopped() != "") { // past a cap, ErrCalls says so
			t.Errorf("%s: %v", p, err)
		}
	}
	return got, pr
}

// projectScanErrs is projectScan returning each file's error instead.
func projectScanErrs(t *testing.T, e *Engine, files map[string]string, opt ProjectOptions) ([]string, *Project, map[string]error) {
	t.Helper()
	errs := map[string]error{}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no file")
	}
	pr := e.NewProject(paths, read, opt)
	var out []string
	for _, p := range paths {
		if LangOf(p) == "" {
			continue
		}
		fs, err := pr.Scan(p, []byte(files[p]))
		if err != nil {
			errs[p] = err
		}
		for _, f := range fs {
			k := f.Path + ":" + itoa(f.Line)
			if !slices.Contains(out, k) { // two rules on one line count once here
				out = append(out, k)
			}
		}
	}
	return out, pr, errs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func TestProject(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	cases := []struct {
		name  string
		files map[string]string
		want  []string // findings, in any order
		calls []string // files that must say their calls were not followed (ErrCalls)
	}{
		{"php static call", map[string]string{
			"ctl.php":   P + "Model::find($_GET['id']);\n",
			"model.php": P + "class Model {\n  static function find($id) { mysqli_query($db, \"SELECT * FROM t WHERE id = $id\"); }\n}\n",
		}, []string{"model.php:3"}, nil},
		{"php object from new", map[string]string{
			"a.php":      P + "$m = new Mailer();\n$m->send($_POST['to']);\n",
			"mailer.php": P + "class Mailer {\n  function send($to) { exec('mail ' . $to); }\n}\n",
		}, []string{"mailer.php:3"}, nil},
		{"php typed parameter", map[string]string{
			"a.php":      P + "function h(Mailer $m) { $m->send($_POST['to']); }\n",
			"mailer.php": P + "class Mailer {\n  function send($to) { exec('mail ' . $to); }\n}\n",
		}, []string{"mailer.php:3"}, nil},
		{"php inherited method", map[string]string{
			"c.php":    P + "class C extends Base {\n  function h() { $this->q($_GET['x']); }\n}\n",
			"base.php": P + "class Base {\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\n",
		}, []string{"base.php:3"}, nil},
		{"php included function", map[string]string{
			"a.php":       P + "require __DIR__ . '/inc/lib.php';\nrun($_GET['x']);\n",
			"inc/lib.php": P + "function run($v) { system('ls ' . $v); }\n",
		}, []string{"inc/lib.php:2"}, nil},
		{"php namespace and use", map[string]string{
			"app/Http/Ctl.php":   P + "namespace App\\Http;\nuse App\\Repo\\Users;\nUsers::find($_GET['q']);\n",
			"app/Repo/Users.php": P + "namespace App\\Repo;\nclass Users {\n  static function find($q) { mysqli_query($db, \"SELECT '$q'\"); }\n}\n",
		}, []string{"app/Repo/Users.php:4"}, nil},
		{"php returned input", map[string]string{
			"a.php":   P + "mysqli_query($db, \"S \" . input('x'));\n",
			"lib.php": P + "function input($k) { return $_GET[$k]; }\n",
		}, []string{"a.php:2"}, nil},
		{"php sanitizing helper in another file", map[string]string{
			"a.php":   P + "$id = clean($_GET['id']);\nmysqli_query($db, \"S $id\");\n",
			"lib.php": P + "function clean($v) { return intval($v); }\n",
		}, nil, nil},
		{"php ambiguous function", map[string]string{
			"a.php": P + "run($_GET['x']);\n",
			"b.php": P + "function run($v) { system('ls ' . $v); }\n",
			"c.php": P + "function run($v) { echo $v; }\n",
		}, nil, []string{"a.php"}}, // which run() is meant is unknown: not silently clean
		{"php unknown object", map[string]string{
			"a.php":      P + "$m->send($_POST['to']);\n",
			"mailer.php": P + "class Mailer {\n  function send($to) { exec('mail ' . $to); }\n}\n",
		}, nil, nil},
		{"php validator in the same file", map[string]string{
			"a.php": P + "function valid_col($c) { return in_array($c, array('id', 'name'), true); }\n$c = $_GET['c'];\nif (!valid_col($c)) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n",
		}, nil, nil},
		{"php validator in another file", map[string]string{
			"a.php":   P + "$c = $_GET['c'];\nif (!Cols::valid($c)) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n",
			"lib.php": P + "class Cols {\n  static function valid($c) { return in_array($c, array('id', 'name'), true); }\n}\n",
		}, nil, nil},
		{"php function that is not always a check", map[string]string{
			"a.php": P + "function valid_col($c) { if ($c == 'all') { return true; } return in_array($c, array('id'), true); }\n$c = $_GET['c'];\nif (!valid_col($c)) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n",
		}, []string{"a.php:5"}, nil},
		{"php allowlist from an unknown call given no input", map[string]string{
			"a.php": P + "function edit($args) {\n  $f = $args['f'];\n  $theme = get_theme('default');\n  if (0 !== validate_file($f, array_keys($theme->files()))) { return; }\n  file_get_contents('/t/' . $f);\n}\n",
			"b.php": P + "edit($_POST);\n",
		}, nil, nil},
		{"php list from an unknown call given input", map[string]string{
			"a.php": P + "function edit($args) {\n  $f = $args['f'];\n  $theme = get_theme($args['t']);\n  if (0 !== validate_file($f, array_keys($theme->files()))) { return; }\n  file_get_contents('/t/' . $f);\n}\n",
			"b.php": P + "edit($_POST);\n",
		}, []string{"a.php:6"}, nil},
		{"php allowlist made of input", map[string]string{
			"a.php": P + "function edit($args) {\n  $f = $args['f'];\n  if (!in_array($f, explode(',', $args['ok']), true)) { return; }\n  file_get_contents('/t/' . $f);\n}\n",
			"b.php": P + "edit($_POST);\n",
		}, []string{"a.php:5"}, nil},
		{"php allowlists made of request data", map[string]string{
			"a.php": P + "$f = $_GET['f'];\nif (!in_array($f, json_decode($_GET['ok']), true)) { return; }\nfile_get_contents('/t/' . $f);\n" +
				"if (!in_array($f, array_keys($_POST), true)) { return; }\nfile_get_contents('/u/' . $f);\n" +
				"$ok = unserialize($_GET['ok']);\nif (!in_array($f, $ok, true)) { return; }\nfile_get_contents('/v/' . $f);\n",
		}, []string{"a.php:4", "a.php:6", "a.php:7", "a.php:9"}, nil}, // 7: unserialize is a sink of its own
		{"php method of the code's own named like a sink", map[string]string{
			"a.php":   P + "$q = new TermQuery();\n$q->query($_GET['x']);\n",
			"lib.php": P + "class TermQuery {\n  function query($a) { return count($a); }\n}\n",
		}, nil, nil},
		{"php method of the code's own that reaches the driver", map[string]string{
			"a.php":   P + "$d = new Db();\n$d->query('SELECT ' . $_GET['x']);\n",
			"lib.php": P + "class Db {\n  function query($s) { return mysqli_query($this->c, $s); }\n}\n",
		}, []string{"lib.php:3"}, nil},
		{"python from import", map[string]string{
			"app/views.py": "from .db import run\n\ndef view(request):\n    run(request.args['q'])\n",
			"app/db.py":    "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n",
		}, []string{"app/db.py:2"}, nil},
		{"python import module", map[string]string{
			"views.py": "import util\n\ndef view(request):\n    util.run(request.args['q'])\n",
			"util.py":  "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n",
		}, []string{"util.py:2"}, nil},
		{"js require", map[string]string{
			"app.js": "const db = require('./db')\napp.get('/', (req, res) => { db.q(req.query.a) })\n",
			"db.js":  "exports.q = function (x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db.js:2"}, nil},
		{"js import", map[string]string{
			"app.js": "import { q } from './db.js'\napp.get('/', (req, res) => { q(req.query.a) })\n",
			"db.js":  "export function q(x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db.js:2"}, nil},
	}
	for _, c := range cases {
		got, _, errs := projectScanErrs(t, e, c.files, ProjectOptions{})
		if !sameSet(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		for p, err := range errs {
			if !errors.Is(err, ErrCalls) || !slices.Contains(c.calls, p) {
				t.Errorf("%s: %s: %v", c.name, p, err)
			}
		}
		for _, p := range c.calls {
			if !errors.Is(errs[p], ErrCalls) {
				t.Errorf("%s: %s: want ErrCalls, got %v", c.name, p, errs[p])
			}
		}
	}
}

// A file with no source name of its own, only a parameter that reaches a sink,
// is still scanned in project mode: its input comes from a caller in another
// file (or, with framework routes, from the route). A prefilter that skips a
// rule for files without one of its sources must be off here, in the project
// scan and in the second pass of a file scan alike.
func TestProjectParamOnlyFile(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"lib.php":   "<?php\nfunction run_cmd($c) {\n  system('ls ' . $c);\n}\nfunction find_row($id) {\n  mysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n}\n",
		"ctl.php":   "<?php\nrun_cmd($_GET['c']);\nfind_row($_POST['id']);\n",
		"db.py":     "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n",
		"views.py":  "from db import run\n\ndef view(request):\n    run(request.args['q'])\n",
		"sh.js":     "exports.go = function (x) {\n  child_process.exec('ls ' + x)\n}\n",
		"server.js": "const sh = require('./sh')\napp.get('/', (req, res) => { sh.go(req.query.a) })\n",
	}
	got, _ := projectScan(t, e, files, ProjectOptions{})
	for _, want := range []string{"lib.php:3", "lib.php:6", "db.py:2", "sh.js:2"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s: not reported in project mode (got %v)", want, got)
		}
	}
	for _, f := range []string{"lib.php", "db.py", "sh.js"} {
		if fs, _ := e.ScanFile(f, []byte(files[f])); len(fs) != 0 {
			t.Errorf("%s on its own: %v, want nothing (the input is only in the caller)", f, fs)
		}
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		if m[x]--; m[x] < 0 {
			return false
		}
	}
	return true
}

func TestProjectCacheAndLimits(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"ctl.php":   "<?php\nModel::find($_GET['id']);\n",
		"model.php": "<?php\nclass Model {\n  static function find($id) { mysqli_query($db, \"SELECT $id\"); }\n}\n",
	}
	cache := filepath.Join(t.TempDir(), "sub", "codeindex.json")
	got, pr := projectScan(t, e, files, ProjectOptions{CacheFile: cache})
	if len(got) != 1 || pr.Stopped() != "" {
		t.Fatalf("got %v, stopped %q", got, pr.Stopped())
	}
	info, err := os.Stat(cache)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v %v", info, err)
	}
	if c := loadIndexCache(cache); len(c) != 2 || c["model.php"] == nil || len(c["model.php"].Classes) != 1 {
		t.Fatalf("cache content: %+v", c)
	}
	// From the cache: the same result.
	if got2, _ := projectScan(t, e, files, ProjectOptions{CacheFile: cache}); !sameSet(got, got2) {
		t.Errorf("from the cache: %v, want %v", got2, got)
	}
	// Over the file cap: calls stay inside each file, and the project says why.
	got3, pr3 := projectScan(t, e, files, ProjectOptions{MaxFiles: 1})
	if _, err := pr3.ScanCalls("ctl.php", []byte(files["ctl.php"])); !errors.Is(err, ErrCalls) {
		t.Errorf("past the file cap: %v, want ErrCalls", err)
	}
	if pr3.Stopped() == "" || len(got3) != 0 {
		t.Errorf("file cap: got %v, stopped %q", got3, pr3.Stopped())
	}
}
