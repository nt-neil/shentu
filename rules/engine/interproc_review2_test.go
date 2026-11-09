package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// hostileFile is a complete graph of mutually recursive functions, each with
// several sinks, followed by five vulnerabilities written out directly.
func hostileFile(n, filler int) (string, []int) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "function f%d($x, $y) {\n", i)
		for j := 0; j < n; j++ {
			if j != i {
				fmt.Fprintf(&b, "  if ($y > %d) { f%d($x, $y - 1); }\n", j, j)
			}
		}
		b.WriteString("  system($x);\n  eval($x);\n  mysqli_query($db, \"SELECT $x\");\n  include $x;\n")
		for k := 0; k < filler; k++ {
			fmt.Fprintf(&b, "  $v%d = strlen($x) + %d;\n", k, k)
		}
		b.WriteString("}\n")
	}
	lines := strings.Count(b.String(), "\n")
	b.WriteString("eval($_GET['a']);\nunserialize($_COOKIE['b']);\ninclude $_GET['c'];\nmysqli_query($db, \"SELECT \" . $_GET['d']);\nsystem($_GET['e']);\n")
	return b.String(), []int{lines + 1, lines + 2, lines + 3, lines + 4, lines + 5}
}

// A file built to make the cross-function analysis slow must not hide the
// vulnerabilities written out in it, nor take long.
func TestInterprocHostileRecursion(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct{ n, filler int }{{10, 0}, {20, 100}, {30, 100}} {
		src, want := hostileFile(c.n, c.filler)
		start := time.Now()
		fs, _ := e.Scan("php", "f", []byte(src))
		d := time.Since(start)
		got := map[int]bool{}
		for _, f := range fs {
			got[f.Line] = true
		}
		for _, l := range want {
			if !got[l] {
				t.Errorf("n=%d filler=%d (%d bytes): the direct finding at line %d is missing", c.n, c.filler, len(src), l)
			}
		}
		limit := 6 * time.Second
		if c.n == 10 {
			limit = 2 * time.Second // 236234a took milliseconds here
		}
		if d > limit {
			t.Errorf("n=%d filler=%d: %v", c.n, c.filler, d)
		}
		t.Logf("n=%d filler=%d bytes=%d: %v", c.n, c.filler, len(src), d)
	}
}

func TestInterprocReview2(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	cases := []struct {
		name, lang, src string
		want            int // a line that must be reported; 0 = nothing
	}{
		{"trait method", "php", P + "trait T {\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\nclass C { use T;\n  function a() { $this->q($_GET['x']); }\n}\n", 3},
		{"namespaced parent", "php", P + "class A {\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\nclass B extends \\A {\n  function h() { $this->q($_GET['x']); }\n}\n", 3},
		{"subclass override", "php", P + "class A {\n  function h() { $this->q($_GET['x']); }\n  function q($v) { echo 1; }\n}\nclass B extends A {\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\n", 7},
		{"js spread before", "js", "function q(a, b) { pool.query('SELECT ' + b) }\napp.get('/', (req, res) => { q(...[1], req.query.a) })\n", 1},
		{"python star args", "python", "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n\ndef view(request):\n    run(*request.args.getlist('q'))\n", 2},
		{"php names ignore case", "php", P + "function run($v) { system('ls ' . $v); }\nRUN($_GET['x']);\n", 2},
		{"php method names ignore case", "php", P + "class C {\n  function h() { $this->Q($_GET['x']); }\n  function q($v) { system('ls ' . $v); }\n}\n", 4},
		{"python super", "python", "class A:\n    def q(self, v):\n        cur.execute(\"S %s\" % v)\n\nclass B(A):\n    def h(self, request):\n        super().q(request.args['x'])\n", 3},
		{"js super", "js", "class A { q(v) { pool.query('S ' + v) } }\nclass B extends A { h(req) { super.q(req.query.a) } }\n", 1},
		{"local helper wrapping an unknown call", "php", P + "function load($id) { return get_post($id); }\nfunction q($v) { mysqli_query($db, \"S $v\"); }\nq(load($_REQUEST['id']));\n", 0},
		{"pass-through on another object", "js", "function q(v) { pool.query('S ' + v) }\napp.get('/', (req, res) => { q(validator.trim(req.query.a)) })\n", 0},
		{"pass-through bare call", "php", P + "function q($v) { mysqli_query($db, \"S $v\"); }\nq(trim($_GET['x']));\n", 2},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "f", []byte(c.src))
		var got []int
		for _, f := range fs {
			got = append(got, f.Line)
		}
		ok := len(got) == 0
		if c.want != 0 {
			ok = false
			for _, l := range got {
				ok = ok || l == c.want
			}
		}
		if !ok {
			t.Errorf("%s: lines %v err %v, want %d", c.name, got, err, c.want)
		}
	}
}

func TestInterprocReview3(t *testing.T) {
	e := engineForTest(t)
	P := "<?php\n"
	cases := []struct {
		name, lang, src string
		want            int // a line that must be reported; 0 = nothing
	}{
		{"local helper returning an unknown call through a variable", "php", P + "function load($id) { $p = get_post($id); return $p; }\nfunction q($v) { mysqli_query($db, \"S $v\"); }\nq(load($_REQUEST['id']));\n", 0},
		{"local helper returning its parameter through a variable", "php", P + "function load($id) { $p = trim($id); return $p; }\nfunction q($v) { mysqli_query($db, \"S $v\"); }\nq(load($_REQUEST['id']));\n", 3},
		{"subclass overrides the caller too", "php", P + "class A {\n  function h() { $this->q($_GET['x']); }\n  function q($v) { echo 1; }\n}\nclass B extends A {\n  function h() { echo 2; }\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\n", 0},
		{"subclass overrides the caller but calls the parent's", "php", P + "class A {\n  function h() { $this->q($_GET['x']); }\n  function q($v) { echo 1; }\n}\nclass B extends A {\n  function h() { parent::h(); }\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\n", 8},
		{"trait used after the method", "php", P + "trait T {\n  function q($v) { mysqli_query($db, \"S $v\"); }\n}\nclass C {\n  function a() { $this->q($_GET['x']); }\n  use T;\n}\n", 3},
		{"python decode on the receiver", "python", "def run(q):\n    cur.execute(\"SELECT %s\" % q)\n\ndef view(request):\n    run(request.args['q'].decode())\n", 2},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "f", []byte(c.src))
		var got []int
		for _, f := range fs {
			got = append(got, f.Line)
		}
		ok := len(got) == 0
		if c.want != 0 {
			ok = false
			for _, l := range got {
				ok = ok || l == c.want
			}
		}
		if !ok {
			t.Errorf("%s: lines %v err %v, want %d", c.name, got, err, c.want)
		}
	}
}

// One file stays within the engine's MaxTime, the second pass included.
func TestInterprocFileTime(t *testing.T) {
	e := engineForTest(t)
	src, want := hostileFile(60, 120)
	start := time.Now()
	fs, _ := e.Scan("php", "f", []byte(src))
	d := time.Since(start)
	got := map[int]bool{}
	for _, f := range fs {
		got[f.Line] = true
	}
	for _, l := range want {
		if !got[l] {
			t.Errorf("%d bytes: the direct finding at line %d is missing", len(src), l)
		}
	}
	if max := e.Limits.MaxTime + e.Limits.MaxTime/2; d > max {
		t.Errorf("%d bytes took %v, over %v", len(src), d, max)
	}
	t.Logf("%d bytes: %v", len(src), d)
}
