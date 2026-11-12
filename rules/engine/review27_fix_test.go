package engine

import (
	"errors"
	"testing"
)

// The review of #27 (1f85b3b): each case is one item it found, kept as a regression test.
func TestReview27Fixes(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	single := []struct {
		name string
		code string
		want bool
	}{
		// 1. a list made from input is no allowlist, whatever builds it
		{"array_map list", P + "$f = $_GET['f'];\nif (!in_array($f, array_map('trim', $_GET['ok']), true)) { exit; }\nmysqli_query($db, \"S $f\");\n", true},
		{"str_getcsv list", P + "$f = $_GET['f'];\nif (!in_array($f, str_getcsv($_GET['ok']), true)) { exit; }\ninclude '/t/' . $f;\n", true},
		{"array_column list", P + "$f = $_GET['f'];\nif (!in_array($f, array_column($_POST['rows'], 'n'), true)) { exit; }\nmysqli_query($db, \"S $f\");\n", true},
		{"array_diff list", P + "$f = $_GET['f'];\nif (!in_array($f, array_diff((array) $_GET['ok'], ['x']), true)) { exit; }\ninclude '/t/' . $f;\n", true},
		{"loose in_array against numbers", P + "$id = $_GET['id'];\nif (!in_array($id, array(1, 2, 3))) { exit; }\nmysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n", true},
		{"strict in_array against numbers", P + "$id = $_GET['id'];\nif (!in_array($id, array(1, 2, 3), true)) { exit; }\nmysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n", false},
		{"fixed list", P + "$f = $_GET['f'];\nif (!in_array($f, array('a.php', 'b.php'), true)) { exit; }\ninclude '/t/' . $f;\n", false},
		// 2. validators check the value passed in, against a list the call does not bring as input
		{"validator list from the caller's input", P + "function ok($c, $l) { return in_array($c, $l, true); }\n$c = $_GET['c'];\nif (!ok($c, explode(',', $_GET['l']))) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n", true},
		{"validator list fixed by the caller", P + "function ok($c, $l) { return in_array($c, $l, true); }\n$c = $_GET['c'];\nif (!ok($c, array('id', 'name'))) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n", false},
		{"validator that reassigns its parameter", P + "function ok($c) { $c = 'id'; return in_array($c, array('id', 'name'), true); }\n$c = $_GET['c'];\nif (!ok($c)) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n", true},
		{"validator with a closure returning true", P + "function ok($c) { $g = function () { return true; }; return in_array($c, array('id'), true); }\n$c = $_GET['c'];\nif (!ok($c)) { return; }\nmysqli_query($db, \"SELECT * FROM t ORDER BY $c\");\n", false},
		// 7. an argument passed by name
		{"preg_replace_callback(callback: input)", P + "echo preg_replace_callback(pattern: '/x/', callback: $_GET['fn'], subject: $t);\n", true},
	}
	for _, c := range single {
		fs, err := e.ScanFile("a.php", []byte(c.code))
		if (len(fs) > 0) != c.want || err != nil {
			t.Errorf("%s: %v %v, want reported %v", c.name, fs, err, c.want)
		}
	}

	cross := []struct {
		name  string
		files map[string]string
		want  []string
		calls []string // files that must return ErrCalls
	}{
		// 3. an interface or abstract method named like a sink does not hide the sink
		{"interface query", map[string]string{
			"a.php": P + "function h(DbI $d) { $d->query('SELECT ' . $_GET['x']); }\n",
			"i.php": P + "interface DbI { function query($s); }\n",
		}, []string{"a.php:2"}, nil},
		{"abstract query", map[string]string{
			"a.php": P + "function h(Base $d) { $d->query('SELECT ' . $_GET['x']); }\n",
			"b.php": P + "abstract class Base { abstract function query($s); }\n",
		}, []string{"a.php:2"}, nil},
		// 4. recursion across files
		{"cycle across files", map[string]string{
			"a.php": P + "function fa($v) { fb($v); }\nfa($_GET['x']);\n",
			"b.php": P + "function fb($v) { if ($v) { fa($v); } system('ls ' . $v); }\n",
		}, []string{"b.php:2"}, nil},
		{"include cycle", map[string]string{
			"a.php": P + "require 'b.php';\nfunction fa($v) { fb($v); }\nfa($_GET['x']);\n",
			"b.php": P + "require 'a.php';\nfunction fb($v) { if ($v) { fa($v); } system('ls ' . $v); }\n",
		}, []string{"b.php:3"}, nil},
		// resolution gaps
		{".inc include", map[string]string{
			"a.php":   P + "require __DIR__ . '/lib.inc';\nrun($_GET['x']);\n",
			"lib.inc": P + "function run($v) { system('ls ' . $v); }\n",
			"z.php":   P + "function run($v) { echo intval($v); }\n",
		}, []string{"lib.inc:2"}, nil},
		{"class name case differs from use", map[string]string{
			"app/Ctl.php":   P + "namespace App;\nuse App\\repo\\users;\nusers::find($_GET['q']);\n",
			"app/Users.php": P + "namespace App\\Repo;\nclass Users {\n  static function find($q) { mysqli_query($db, \"SELECT '$q'\"); }\n}\n",
		}, []string{"app/Users.php:4"}, nil},
		{"fully qualified static call", map[string]string{
			"ctl.php":   P + "\\App\\Users::find($_GET['q']);\n",
			"Users.php": P + "namespace App;\nclass Users {\n  static function find($q) { mysqli_query($db, \"SELECT '$q'\"); }\n}\n",
		}, []string{"Users.php:4"}, nil},
		{"same class name, the included one", map[string]string{
			"ctl.php":  P + "require 'a/Db.php';\nDb::run($_GET['q']);\n",
			"a/Db.php": P + "class Db {\n  static function run($q) { mysqli_query($c, \"S $q\"); }\n}\n",
			"b/Db.php": P + "class Db {\n  static function run($q) { echo 1; }\n}\n",
		}, []string{"a/Db.php:3"}, nil},
		{"include with a variable folder, two files of that name", map[string]string{
			"a.php":     P + "require $dir . '/run.php';\nrun($_GET['x']);\n",
			"x/run.php": P + "function run($v) { system('ls ' . $v); }\n",
			"run.php":   P + "function run($v) { echo intval($v); }\n",
		}, nil, []string{"a.php"}},
		{"js default export", map[string]string{
			"app.js": "import q from './db'\napp.get('/', (req, res) => { q(req.query.a) })\n",
			"db.js":  "export default function q(x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db.js:2"}, nil},
		{"js re-export", map[string]string{
			"app.js":      "import { q } from './db'\napp.get('/', (req, res) => { q(req.query.a) })\n",
			"db/index.js": "export { q } from './impl'\n",
			"db/impl.js":  "export function q(x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db/impl.js:2"}, nil},
		{"js module.exports = require", map[string]string{
			"app.js":      "const { q } = require('./db')\napp.get('/', (req, res) => { q(req.query.a) })\n",
			"db/index.js": "module.exports = require('./impl')\n",
			"db/impl.js":  "exports.q = function (x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db/impl.js:2"}, nil},
		{"js .jsx module", map[string]string{
			"app.js": "import { q } from './db'\napp.get('/', (req, res) => { q(req.query.a) })\n",
			"db.jsx": "export function q(x) {\n  pool.query('SELECT ' + x)\n}\n",
		}, []string{"db.jsx:2"}, nil},
		{"js relative module the project does not have", map[string]string{
			"app.js": "import { q } from './gone'\napp.get('/', (req, res) => { q(req.query.a) })\n",
		}, nil, []string{"app.js"}},
		{"python two util.py", map[string]string{
			"views.py":       "from util import run\n\ndef view(request):\n    run(request.args['q'])\n",
			"util.py":        "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n",
			"vendor/util.py": "def run(q):\n    print(q)\n",
		}, nil, []string{"views.py"}},
	}
	for _, c := range cross {
		got, _, errs := projectScanErrs(t, e, c.files, ProjectOptions{})
		if !sameSet(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		for _, p := range c.calls {
			if !errors.Is(errs[p], ErrCalls) {
				t.Errorf("%s: %s: want ErrCalls, got %v", c.name, p, errs[p])
			}
		}
	}

	// 5. past a cap, ScanCalls says calls were not followed
	files := map[string]string{"ctl.php": P + "Model::find($_GET['id']);\n",
		"model.php": P + "class Model {\n  static function find($id) { mysqli_query($db, \"S $id\"); }\n}\n"}
	for _, opt := range []ProjectOptions{{MaxHeap: 1}, {MaxTime: 1}} {
		pr := e.NewProject([]string{"ctl.php", "model.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, opt)
		if fs, err := pr.ScanCalls("ctl.php", []byte(files["ctl.php"])); len(fs) == 0 && !errors.Is(err, ErrCalls) {
			t.Errorf("%+v: no finding and %v, want ErrCalls", opt, err)
		}
	}
}
