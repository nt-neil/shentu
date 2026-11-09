package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestInterproc(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	cases := []struct {
		name, lang, src string
		want            int // first line reported, 0 for none
	}{
		{"php method reaches sink", "php", P + "class A {\n  function h() { $id = $_GET['id']; $this->q($id); }\n  private function q($v) { mysqli_query($db, \"SELECT * FROM t WHERE id = $v\"); }\n}\n", 4},
		{"php only the tainted parameter", "php", P + "function find($a, $b) { mysqli_query($db, \"SELECT $b\"); }\nfind($_GET['x'], 'k');\n", 0},
		{"php second parameter tainted", "php", P + "function find($a, $b) { mysqli_query($db, \"SELECT $b\"); }\nfind('k', $_GET['x']);\n", 2},
		{"php return carries input", "php", P + "function input() { return $_GET['x']; }\nmysqli_query($db, \"SELECT \" . input());\n", 3},
		{"php sanitizing helper", "php", P + "function clean($v) { return intval($v); }\n$id = clean($_GET['id']);\nmysqli_query($db, \"SELECT $id\");\n", 0},
		{"php helper passes input through", "php", P + "function trimmed($v) { return trim($v); }\n$id = trimmed($_GET['id']);\nmysqli_query($db, \"SELECT $id\");\n", 4},
		{"php recursion", "php", P + "function r($v, $n) {\n  if ($n > 0) { return r($v, $n - 1); }\n  return $v;\n}\nmysqli_query($db, \"SELECT \" . r($_GET['x'], 3));\n", 6},
		{"php recursion reaching a sink", "php", P + "function walk($v, $n) {\n  if ($n > 0) { walk($v, $n - 1); return; }\n  mysqli_query($db, \"SELECT $v\");\n}\nwalk($_GET['x'], 3);\n", 4},
		{"php closure in a variable", "php", P + "$f = function($v) use ($db) { mysqli_query($db, \"SELECT $v\"); };\n$f($_GET['a']);\n", 2},
		{"php self static", "php", P + "class B {\n  static function q($v) { mysqli_query($db, \"S $v\"); }\n  static function h() { self::q($_POST['a']); }\n}\n", 3},
		{"php two levels", "php", P + "class C {\n  function h() { $this->a($_GET['x']); }\n  function a($v) { $this->b('pre' . $v); }\n  function b($w) { mysqli_query($db, \"S $w\"); }\n}\n", 5},
		{"php other object not resolved", "php", P + "class D {\n  function h() { $other->q($_GET['x']); }\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\n", 0},
		{"php unknown call inside the callee", "php", P + "function attach($id) { $p = get_post($id); mysqli_query($db, \"S $p\"); }\nattach($_REQUEST['post_id']);\n", 0},
		{"php unknown call before the call", "php", P + "function q($v) { mysqli_query($db, \"S $v\"); }\nq(get_post($_REQUEST['post_id']));\n", 0},
		{"php returned source through an unknown call", "php", P + "function locale() { return sanitize_locale_name($_GET['l']); }\nmysqli_query($db, \"S \" . locale());\n", 0},
		{"php unknown call in the same function still reports", "php", P + "$p = get_post($_REQUEST['post_id']);\nmysqli_query($db, \"S $p\");\n", 3},
		{"php hmac checked before unserialize", "php", P + "function load($v) {\n  if (!hash_equals(sign($v), $_POST['h'])) { return; }\n  return unserialize($v);\n}\nload($_POST['data']);\n", 0},
		{"php hash_equals of two inputs", "php", P + "function load($v) {\n  if (!hash_equals($v, $_POST['h'])) { return; }\n  return unserialize($v);\n}\nload($_POST['data']);\n", 4},
		{"php unkeyed hash is no check", "php", P + "function load($v) {\n  if (!hash_equals(md5($v), $_POST['h'])) { return; }\n  return unserialize($v);\n}\nload($_POST['data']);\n", 4},
		{"php hash_hmac with a secret", "php", P + "function load($v) {\n  if (!hash_equals(hash_hmac('sha256', $v, SECRET_KEY), $_POST['h'])) { return; }\n  return unserialize($v);\n}\nload($_POST['data']);\n", 0},
		{"php hash_hmac with the attacker's key", "php", P + "function load($v) {\n  if (!hash_equals(hash_hmac('sha256', $v, $_POST['k']), $_POST['h'])) { return; }\n  return unserialize($v);\n}\nload($_POST['data']);\n", 4},
		{"php no hmac check", "php", P + "function load($v) {\n  return unserialize($v);\n}\nload($_POST['data']);\n", 3},
		{"php uncalled function", "php", P + "function q($v) { mysqli_query($db, \"S $v\"); }\n", 0},
		{"python function", "python", "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n\ndef view(request):\n    run(request.args['q'])\n", 2},
		{"python self method", "python", "class V:\n    def get(self, request):\n        self.q(request.GET['c'])\n\n    def q(self, c):\n        cur.execute(f\"SELECT {c}\")\n", 6},
		{"js function", "js", "function q(x) { pool.query(\"SELECT \" + x) }\napp.get('/', (req, res) => { q(req.query.a) })\n", 1},
		{"js this method", "js", "class S {\n  h(req) { this.q(req.body.n) }\n  q(n) { pool.query(`SELECT ${n}`) }\n}\n", 3},
		// From the review of #21.
		{"weak: base64_decode inside callee (cmdi)", "php", P + "function run($c) { system(base64_decode($c)); }\nrun($_POST['c']);\n", 2},
		{"weak: trim inside callee (sqli)", "php", P + "function q($id) { mysqli_query($db, \"SELECT * FROM t WHERE id=\" . trim($id)); }\nq($_GET['id']);\n", 2},
		{"weak: urldecode at call site", "php", P + "function run($c) { system($c); }\nrun(urldecode($_GET['c']));\n", 2},
		{"weak py: callee strips", "python", "def run(q):\n    cur.execute(\"SELECT %s\" % q.strip())\n\ndef view(request):\n    run(request.args['q'])\n", 2},
		{"regression: weak base return hides param", "php", P + "function pick($v) {\n  if (isset($_GET['d'])) { return trim($_GET['d']); }\n  return $v;\n}\n$id = pick($_GET['id']);\nmysqli_query($db, \"SELECT $id\");\n", 7},
		{"retWeak shared across params", "php", P + "function pick($a, $b) { if ($b) { return strtolower($b); } return $a; }\nfunction run($q) { $x = pick($q, ''); mysqli_query($db, \"SELECT $x\"); }\nrun($_GET['q']);\n", 3},
		{"regression: php named args", "php", P + "function build($prefix, $q) { $n = intval($prefix); return \"SELECT \" . $q; }\n$sql = build(q: $_GET['q'], prefix: 'x');\nmysqli_query($db, $sql);\n", 4},
		{"regression: python kwargs", "python", "def build(prefix, q):\n    n = int(prefix)\n    return \"SELECT \" + q\n\ndef view(request):\n    sql = build(q=request.args['q'], prefix='x')\n    cur.execute(sql)\n", 7},
		{"python kwargs into sink", "python", "def run(prefix, q):\n    cur.execute(\"SELECT %s\" % q)\n\ndef view(request):\n    run(q=request.args['q'], prefix='x')\n", 2},
		{"regression: 17th param returned", "php", P + "function b($a1,$a2,$a3,$a4,$a5,$a6,$a7,$a8,$a9,$a10,$a11,$a12,$a13,$a14,$a15,$a16,$a17) { $n = intval($a1); return \"SELECT \" . $a17; }\n$s = b(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,$_GET['x']);\nmysqli_query($db, $s);\n", 4},
		{"17th param into sink", "php", P + "function b($a1,$a2,$a3,$a4,$a5,$a6,$a7,$a8,$a9,$a10,$a11,$a12,$a13,$a14,$a15,$a16,$a17) { mysqli_query($db, \"SELECT $a17\"); }\nb(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,$_GET['x']);\n", 2},
		{"return array", "php", P + "function wrap($x) { return ['q' => $x]; }\n$a = wrap($_GET['x']);\nmysqli_query($db, \"S \" . $a['q']);\n", 4},
		{"php arrow fn in var", "php", P + "$f = fn($v) => mysqli_query($db, \"S $v\");\n$f($_GET['a']);\n", 2},
		{"js arrow in const", "js", "const q = (x) => pool.query(\"SELECT \" + x)\napp.get('/', (req, res) => { q(req.query.a) })\n", 1},
		{"js function expr in const", "js", "const q = function (x) { pool.query(\"SELECT \" + x) }\napp.get('/', (req, res) => { q(req.query.a) })\n", 1},
		{"parent::", "php", P + "class A { static function q($v) { mysqli_query($db, \"S $v\"); } }\nclass B extends A { static function h() { parent::q($_GET['x']); } }\n", 2},
		{"static::", "php", P + "class A { static function q($v) { mysqli_query($db, \"S $v\"); }\n static function h() { static::q($_GET['x']); } }\n", 2},
		{"ClassName::", "php", P + "class A { static function q($v) { mysqli_query($db, \"S $v\"); } }\nA::q($_GET['x']);\n", 2},
		{"FP: same-named method of another class", "php", P + "class Safe {\n  function save($v) { mysqli_query($db, \"S \" . intval($v)); }\n  function h() { $this->save($_GET['x']); }\n}\nclass Other {\n  function save($v) { mysqli_query($db, \"S $v\"); }\n}\n", 0},
		{"mutual recursion stale member", "php", P + "f('const');\nfunction f($x) { if ($x != '') { g($x); } system($x); }\nfunction g($y) { f($y); }\ng($_GET['c']);\n", 3},
		{"mutual recursion stale member, g relevant on its own", "php", P + "f('const');\nfunction f($x) { if ($x != '') { g($x); } system($x); }\nfunction g($y) { $k = escapeshellarg('k'); f($y); }\ng($_GET['c']);\n", 3},
		{"mutual recursion, f defined first", "php", P + "function f($x) { if ($x != '') { g($x); } system($x); }\nfunction g($y) { f($y); }\ng($_GET['c']);\n", 2},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "f", []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		got := 0
		if len(fs) > 0 {
			got = fs[0].Line
		}
		if got != c.want {
			t.Errorf("%s: reported line %d, want %d (%+v)", c.name, got, c.want, fs)
		}
	}
}

func TestLibraryMode(t *testing.T) {
	app := engineForTest(t)
	lib := engineForTest(t)
	lib.Library = true
	P := "<?php\n"
	cases := []struct {
		name, lang, src string
		want            int // line reported in library mode; app mode must report nothing
	}{
		{"php public method embeds a parameter", "php", P + "class Q {\n  public function trunc($kind) { return $this->db->query(\"SELECT DATE_TRUNC('$kind', d)\"); }\n}\n", 3},
		{"php parameter passed as is", "php", P + "class Q {\n  public function raw($sql) { return $this->db->query($sql); }\n}\n", 0},
		{"php private method", "php", P + "class Q {\n  private function trunc($kind) { return $this->db->query(\"SELECT '$kind'\"); }\n}\n", 0},
		{"php numeric parameter", "php", P + "class Q {\n  public function page(int $n) { return $this->db->query(\"SELECT * LIMIT $n\"); }\n}\n", 0},
		{"php public through a private helper", "php", P + "class Q {\n  public function find($col) { return $this->run('SELECT ' . $col); }\n  private function run($sql) { return $this->db->query($sql); }\n}\n", 4},
		{"python embeds", "python", "def trunc(kind, field):\n    cursor.execute(\"SELECT DATE_TRUNC('%s', %s)\" % (kind, field))\n", 2},
		{"python as is", "python", "def run(sql, params):\n    cursor.execute(sql, params)\n", 0},
		{"python underscore is private", "python", "def _trunc(kind):\n    cursor.execute(\"SELECT '%s'\" % kind)\n", 0},
		{"js builds code", "js", "function template(variable) {\n  return Function('obj', 'with (' + variable + ') { return 1 }')\n}\n", 2},
		{"js code as is", "js", "function run(src) {\n  return eval(src)\n}\n", 0},
		{"lib: public wrapper, private helper embeds", "php", P + "class Q {\n  public function find($id) { return $this->run($id); }\n  private function run($id) { return $this->db->query(\"SELECT * FROM t WHERE id = $id\"); }\n}\n", 4},
		{"lib FP: private __construct", "php", P + "class Q {\n  private function __construct($t) { $this->db->query(\"SELECT * FROM $t\"); }\n}\n", 0},
		{"lib FP: python nested def in private fn", "python", "def _helper():\n    def inner(kind):\n        cursor.execute(\"SELECT '%s'\" % kind)\n    return inner\n", 0},
		{"lib FP: protected implicit via phpdoc? (public static ok)", "php", P + "class Q {\n  public static function t($k) { return $this->db->query(\"SELECT '$k'\"); }\n}\n", 3},
		{"php path from a parameter", "php", P + "class F {\n  public function load($name) { return file_get_contents('/srv/data/' . $name); }\n}\n", 0},
	}
	if fs, _ := lib.Scan("python", "tests/test_q.py", []byte("def trunc(kind):\n    cursor.execute(\"SELECT '%s'\" % kind)\n")); len(fs) > 0 {
		t.Errorf("library mode reported in a test file: %+v", fs)
	}
	for _, c := range cases {
		if fs, _ := app.Scan(c.lang, "f", []byte(c.src)); len(fs) > 0 {
			t.Errorf("%s: app mode reported %+v", c.name, fs)
		}
		fs, err := lib.Scan(c.lang, "f", []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		got := 0
		if len(fs) > 0 {
			got = fs[0].Line
		}
		if got != c.want {
			t.Errorf("%s: library mode reported line %d, want %d (%+v)", c.name, got, c.want, fs)
		}
	}
}

// Known gaps, kept as cases so a fix shows up: by-reference output parameters
// and Python lambdas are not followed.
func TestInterprocGaps(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	for _, c := range []struct {
		name, lang, src string
		want            int
	}{
		{"by-ref out param", "php", P + "function fill(&$out, $in) { $out = \"SELECT \" . $in; }\nfill($sql, $_GET['x']);\nmysqli_query($db, $sql);\n", 4},
		{"python lambda", "python", "q = lambda x: cur.execute(\"SELECT %s\" % x)\n\ndef view(request):\n    q(request.args['q'])\n", 1},
	} {
		fs, _ := e.Scan(c.lang, "f", []byte(c.src))
		t.Logf("known gap, %s: reported %d finding(s), the right answer is line %d", c.name, len(fs), c.want)
	}
}

func TestInterprocDeepChain(t *testing.T) {
	e := engineForTest(t)
	var b strings.Builder
	b.WriteString("<?php\nsystem($_GET['direct']);\nf0($_GET['c']);\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "function f%d($x) { f%d($x); }\n", i, i+1)
	}
	b.WriteString("function f40($x) { system($x); }\n")
	fs, err := e.Scan("php", "f", []byte(b.String()))
	if !errors.Is(err, ErrLimit) {
		t.Errorf("a chain deeper than the cap: err %v, want ErrLimit", err)
	}
	if len(fs) == 0 || fs[0].Line != 2 {
		t.Errorf("the direct finding is lost: %+v", fs)
	}
}
