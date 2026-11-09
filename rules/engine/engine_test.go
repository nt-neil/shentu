package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules"
)

// texts returns "kind:text" for each token, with string parts in brackets.
func texts(toks []Token) []string {
	var out []string
	for _, t := range toks {
		s := t.Text
		switch t.Kind {
		case Str:
			s = "S:" + s
			for _, p := range t.Parts {
				s += "[" + strings.Join(texts(p.Toks), " ") + "]"
			}
		case Newline:
			s = "NL"
		case Indent:
			s = "IN"
		case Dedent:
			s = "DE"
		}
		out = append(out, s)
	}
	return out
}

func hasTok(toks []Token, want string) bool {
	for _, s := range texts(toks) {
		if s == want {
			return true
		}
	}
	return false
}

func TestLexPHP(t *testing.T) {
	src := "<html><?php\n// $_GET in a comment\n# and $_POST\n/* $_COOKIE */\n" +
		"$a = \"x $b y {$c['k']} ${d} $e->f $g[1]\";\n" +
		"$h = 'no $i here';\n" +
		"$s = <<<SQL\n  SELECT {$j}\n  SQL;\n" +
		"$n = <<<'RAW'\n$k\nRAW;\n" +
		"$o = `ls $p`;\n?>tail<?= $q ?>"
	toks := LexPHP(src)
	for _, bad := range []string{"$_GET", "$_POST", "$_COOKIE", "$i", "$k", "html", "tail"} {
		if hasTok(toks, bad) {
			t.Errorf("%s should not be a token", bad)
		}
	}
	for _, want := range []string{
		"S:x $b y {$c['k']} ${d} $e->f $g[1][$b][$c [ S:k ]][$d][$e -> f][$g [ 1 ]]",
		"S:no $i here",
		"S:  SELECT {$j}[$j]",
		"S:$k",
		"S:ls $p[$p]",
		"echo", "$q",
	} {
		if !hasTok(toks, want) {
			t.Errorf("missing %q in %q", want, texts(toks))
		}
	}
	if got := toks[len(toks)-1]; got.Line != 14 {
		t.Errorf("last token on line %d, want 14", got.Line)
	}
	for _, src := range []string{"<?php 'open", "<?php \"open {$x", "<?php $x = <<<EOT\nno end", "<?php `x"} {
		toks := LexPHP(src)
		if len(toks) == 0 || toks[len(toks)-1].Kind != Str || toks[len(toks)-1].Flags&FlagOpen == 0 {
			t.Errorf("%q: want an unterminated string last, got %q", src, texts(toks))
		}
	}
	if toks := LexPHP("<?php /* open $_GET"); len(toks) != 0 {
		t.Errorf("unterminated comment lexed as %q", texts(toks))
	}
}

func TestLexPython(t *testing.T) {
	src := "# request.args in a comment\ndef f(request):\n    q = f\"a {request.args['x']!r:>{w}} {{lit}}\"\n" +
		"    s = '''multi\n    {request.form}'''\n    if q:\n        run(q)\n    return s\n"
	toks := LexPython(src)
	if hasTok(toks, "request") && texts(toks)[0] == "request" {
		t.Error("comment lexed")
	}
	for _, want := range []string{
		"S:a {request.args['x']!r:>{w}} {{lit}}[request . args [ S:x ]]",
		"S:multi\n    {request.form}",
		"IN", "DE",
	} {
		if !hasTok(toks, want) {
			t.Errorf("missing %q in %q", want, texts(toks))
		}
	}
	in, de := 0, 0
	for _, tk := range toks {
		if tk.Kind == Indent {
			in++
		} else if tk.Kind == Dedent {
			de++
		}
	}
	if in != 2 || de != 2 {
		t.Errorf("indents %d dedents %d, want 2 and 2", in, de)
	}
	for _, src := range []string{"'open\nx = 1", "'''open", "f'{x", "f'{", "\\"} {
		LexPython(src)
	}
}

func TestLexJS(t *testing.T) {
	src := "// req.query\nconst a = `x ${req.query.a} ${`in ${b}`}`; /* req.body */\nconst r = /[/]req.query/g.test(c) / 2;\nconst s = 'req.body';"
	toks := LexJS(src)
	for _, want := range []string{"S:x ${req.query.a} ${`in ${b}`}[req . query . a][S:in ${b}[b]]", "S:[/]req.query", "S:req.body"} {
		if !hasTok(toks, want) {
			t.Errorf("missing %q in %q", want, texts(toks))
		}
	}
	for _, tk := range toks {
		if tk.Kind == Str && tk.Text == "[/]req.query" && tk.Flags&FlagRegex == 0 {
			t.Error("regex literal not flagged")
		}
	}
	for _, src := range []string{"`open ${", "'open", "/open", "/* open"} {
		LexJS(src)
	}
}

func engineForTest(t *testing.T) *Engine {
	t.Helper()
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEngineFlows(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, src string
		want            int // line reported by any rule, 0 for none
	}{
		{"php comment", "php", "<?php\n// mysqli_query($db, $_GET['x']);\n", 0},
		{"php plain string", "php", "<?php\n$x = 'mysqli_query($db, $_GET)';\necho $x;\n", 0},
		{"php interpolation", "php", "<?php\n$id = $_GET['id'];\nmysqli_query($db, \"SELECT $id\");\n", 3},
		{"php reassigned literal", "php", "<?php\n$id = $_GET['id'];\n$id = '1';\nmysqli_query($db, \"SELECT $id\");\n", 0},
		{"php array and concat", "php", "<?php\n$p = [];\n$p[] = $_POST['a'];\n$sql = 'x' . $p[0];\n$pdo->query($sql);\n", 5},
		{"php sanitizer", "php", "<?php\n$id = intval($_GET['id']);\n$pdo->query(\"SELECT $id\");\n", 0},
		{"php other function", "php", "<?php\nfunction a() { $id = $_GET['id']; }\nfunction b() { mysqli_query($db, \"SELECT $id\"); }\n", 0},
		{"python f-string", "python", "def v(request):\n    n = request.args['n']\n    cur.execute(f\"SELECT {n}\")\n", 3},
		{"python comment", "python", "def v(request):\n    # cur.execute(request.args['n'])\n    pass\n", 0},
		{"python allowlist", "python", "def v(request):\n    n = request.args['n']\n    if n not in ('a', 'b'):\n        return\n    cur.execute(f\"SELECT {n}\")\n", 0},
		{"js template", "js", "app.get('/', (req, res) => {\n  const n = req.query.n\n  pool.query(`SELECT ${n}`)\n})\n", 3},
		{"php transforming sanitizer as condition", "php", "<?php\n$id = $_GET['id'];\nif (intval($id)) {\n    mysqli_query($db, \"SELECT $id\");\n}\n", 4},
		{"php or die", "php", "<?php\n$id = $_GET['id'] or die();\nmysqli_query($db, \"SELECT $id\");\n", 3},
		{"php static orderByRaw", "php", "<?php\n$s = $request->input('sort');\nreturn Payment::orderByRaw($s)->get();\n", 3},
		{"python bindparams after text", "python", "def v():\n    col = request.args['c']\n    db.session.execute(text(f'SELECT {col} FROM t WHERE a = :a').bindparams(a=1))\n", 3},
		{"js qualified spawn", "js", "app.post('/b', (req, res) => {\n  cp.spawn('make', [req.body.t], { shell: true });\n});\n", 2},
		{"js number", "js", "app.get('/', (req, res) => {\n  const n = Number(req.query.n);\n  pool.query(`SELECT ${n}`);\n});\n", 0},
		// P1: a source after a qualifier.
		{"python qualified flask request", "python", "def add():\n    f = flask.request.files['f']\n    p = os.path.join('/srv', 'tmp_' + f.filename)\n", 3},
		{"python self.request", "python", "class V(View):\n    def get(self):\n        cur.execute('SELECT ' + self.request.GET['c'])\n", 3},
		{"python request attribute of a non-source", "python", "def v():\n    cur.execute('SELECT ' + resp.requests.args)\n", 0},
		// Found on real projects (E7): numbers, literal comparisons, empty values, filters,
		// allowlist intersections, fixed path prefixes, WordPress validators, regex checks.
		{"php int cast", "php", "<?php\n$id = (int) $_GET['id'];\nmysqli_query($db, \"SELECT $id\");\n", 0},
		{"php absint", "php", "<?php\n$n = absint($_GET['n']);\n$o = $n * 10;\nmysqli_query($db, \"SELECT 1 LIMIT $o\");\n", 0},
		{"python int", "python", "def v(request):\n    n = int(request.args['n'])\n    cur.execute(f\"SELECT {n}\")\n", 0},
		{"js parseInt", "js", "app.get('/', (req, res) => {\n  pool.query(`SELECT ${parseInt(req.query.n, 10)}`);\n});\n", 0},
		{"php literal compare", "php", "<?php\n$o = $_GET['o'];\nif ('ASC' !== $o) {\n    $o = 'DESC';\n}\nmysqli_query($db, \"SELECT 1 $o\");\n", 0},
		{"php loose true is no check", "php", "<?php\n$o = $_GET['o'];\nif ($o == true) {\n    mysqli_query($db, \"SELECT $o\");\n}\n", 4},
		{"php empty and index", "php", "<?php\n$p = $_GET;\nif (!empty($p['l'])) {\n    $p['l'] = intval($p['l']);\n}\nmysqli_query($db, 'SELECT 1 LIMIT ' . $p['l']);\n", 0},
		{"php other index stays tainted", "php", "<?php\n$p = $_GET;\n$p['l'] = 1;\nmysqli_query($db, 'SELECT ' . $p['c']);\n", 4},
		{"php isset true is no check", "php", "<?php\n$x = $_GET['x'];\nif (isset($x)) {\n    mysqli_query($db, \"SELECT $x\");\n}\n", 4},
		{"php apply_filters value", "php", "<?php\n$w = apply_filters('w', 'x', $_GET);\n$wpdb->query(\"SELECT $w\");\n", 0},
		{"php apply_filters tainted value", "php", "<?php\n$w = apply_filters('w', $_GET['w']);\n$wpdb->query(\"SELECT $w\");\n", 3},
		{"php array_intersect allowlist first", "php", "<?php\n$t = array_intersect(['a', 'b'], (array) $_GET['t']);\nmysqli_query($db, \"SELECT \" . implode(',', $t));\n", 0},
		{"php array_intersect keeps the input's keys", "php", "<?php\n$t = array_intersect((array) $_GET['t'], ['a', 'b']);\nmysqli_query($db, \"SELECT \" . implode(',', array_keys($t)));\n", 3},
		{"php dynamic index forgets known keys", "php", "<?php\n$a = [];\n$a['k'] = 'x';\n$a[$_GET['i']] = $_GET['v'];\nmysqli_query($db, 'SELECT ' . $a['k']);\n", 5},
		{"php phar behind a prefix", "php", "<?php\nif (file_exists(WP_PLUGIN_DIR . '/' . $_GET['p'])) {}\n$b = BASE . '/';\n$b .= $_GET['q'];\nif (is_file($b)) {}\n", 0},
		{"php phar at the start", "php", "<?php\n$f = $_GET['p'];\nif (file_exists($f . '.txt')) {}\n", 3},
		{"php validate_file", "php", "<?php\n$p = $_GET['p'];\nif (validate_file($p, $allowed)) {\n    wp_die();\n}\ninclude $p;\n", 0},
		{"php validate_file without a list", "php", "<?php\n$p = $_GET['p'];\nif (validate_file($p)) {\n    wp_die();\n}\ninclude $p;\n", 6},
		{"php validate_file wrong way", "php", "<?php\n$p = $_GET['p'];\nif (!validate_file($p, $allowed)) {\n    wp_die();\n}\ninclude $p;\n", 6},
		{"php validate_file_to_edit statement", "php", "<?php\n$f = $_GET['f'];\nvalidate_file_to_edit($f, $allowed);\nreadfile($f);\n", 0},
		{"php validate_file_to_edit without a list", "php", "<?php\n$f = $_GET['f'];\nvalidate_file_to_edit($f);\nreadfile($f);\n", 4},
		{"php regex deny class", "php", "<?php\n$x = $_POST['x'];\nif (preg_match('|[^a-z0-9_]|i', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 0},
		{"php regex allow anchored", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/^[a-z0-9_-]+$/i', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 0},
		{"php regex multiline is no check", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/^[a-z]+$/m', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 6},
		{"php regex with a dot is no check", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/^[a-z.]+$/', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 6},
		{"php regex A-z is no check", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/^[A-z]+$/', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 6},
		{"php regex deny class with u is no check", "php", "<?php\n$x = $_POST['x'];\nif (preg_match('/[^a-z0-9_]/u', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 6},
		{"php regex allow with u", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/^[a-z0-9_]+$/u', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 0},
		{"python pickle of decoded query", "python", "def v():\n    obj = pickle.loads(base64.b64decode(request.args['s']))\n", 2},
		{"php regex unanchored is no check", "php", "<?php\n$x = $_POST['x'];\nif (!preg_match('/[a-z]+/', $x)) {\n    die();\n}\nmysqli_query($db, \"SELECT $x\");\n", 6},
		{"python regex fullmatch", "python", "def v(request):\n    n = request.args['n']\n    if not re.fullmatch(r'[\\w-]+', n):\n        return\n    cur.execute(f\"SELECT {n}\")\n", 0},
		{"python regex match needs an end", "python", "def v(request):\n    n = request.args['n']\n    if not re.match(r'[a-z]+', n):\n        return\n    cur.execute(f\"SELECT {n}\")\n", 5},
		{"js regex test", "js", "app.get('/', (req, res) => {\n  const n = req.query.n;\n  if (!/^\\d+$/.test(n)) return;\n  pool.query(`SELECT ${n}`);\n});\n", 0},
		{"js regex multiline is no check", "js", "app.get('/', (req, res) => {\n  const n = req.query.n;\n  if (!/^\\d+$/m.test(n)) return;\n  pool.query(`SELECT ${n}`);\n});\n", 4},
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

func TestEngineLimits(t *testing.T) {
	e := engineForTest(t)
	e.Limits = Limits{MaxTokens: 1000, MaxTime: time.Second}
	src := "<?php\n" + strings.Repeat("$a = $b . $c;\n", 1000)
	if _, err := e.Scan("php", "big.php", []byte(src)); err != ErrLimit {
		t.Errorf("token cap: got %v, want ErrLimit", err)
	}
	e.Limits = Limits{MaxTokens: 1 << 20, MaxTime: time.Nanosecond}
	src = "<?php\n" + strings.Repeat("foreach ($a as $b) { foreach ($b as $c) { $d = $c . $_GET['x']; } }\n", 2000)
	if _, err := e.Scan("php", "slow.php", []byte(src)); err != ErrLimit {
		t.Errorf("time cap: got %v, want ErrLimit", err)
	}
}

// TestEngineHostile: inputs built to be slow must stop near the time cap and say
// so with ErrLimit; deep nesting counts as tainted; a string that swallows the
// rest of the file is reported as ErrPartial.
func TestEngineHostile(t *testing.T) {
	e := engineForTest(t)
	const limit = 500 * time.Millisecond
	e.Limits = Limits{MaxTokens: DefaultLimits.MaxTokens * 4, MaxTime: limit}
	R := strings.Repeat
	for _, c := range []struct{ name, lang, src string }{
		{"py [", "python", "x = " + R("[", 290000)},
		{"js [", "js", "x = " + R("[\n", 290000)}, // line breaks keep these from looking minified
		{"php [", "php", "<?php $x = " + R("[", 290000)},
		{"php (", "php", "<?php $x = " + R("(", 290000)},
		{"js {", "js", "x = " + R("{\n", 290000)},
		{"js f(", "js", "x = " + R("f(\n", 145000)},
		{"php ternary chain", "php", "<?php $x = " + R("$a ? $b : ", 50000) + "1;"},
		{"py long line", "python", "x = " + R("a + ", 200000) + "1\n"},
		{"js long call", "js", "exec(" + R("req.query.a,\n", 100000) + ")"},
		{"php nested ifs", "php", "<?php " + R("if ($a) { ", 20000) + "system($_GET['x']);" + R("}", 20000)},
		{"js nested closures", "js", R("function(){\n", 20000) + "exec(req.query.x)" + R("}\n", 20000)},
		{"php if/else in a loop", "php", "<?php function f(){ " + R("if ($c) { $a = $_GET['x']; } else { $a = 1; } ", 10000) + " system($a); }"},
		{"js loops", "js", "function f(){" + R("for (const a of b) { x = x + req.query.y; }\n", 10000) + "exec(x);}"},
	} {
		start := time.Now()
		_, err := e.Scan(c.lang, "x", []byte(c.src))
		took := time.Since(start)
		t.Logf("%-22s %v err=%v", c.name, took.Round(time.Millisecond), err)
		if took > limit+time.Second {
			t.Errorf("%s: took %v, cap %v", c.name, took, limit)
		}
		if took > limit && err != ErrLimit {
			t.Errorf("%s: over the cap (%v) but err = %v", c.name, took, err)
		}
	}

	e.Limits = DefaultLimits
	nested := "<?php " + R("if ($a) { ", 200) + "system($_GET['x']);" + R("}", 200)
	if fs, err := e.Scan("php", "nested.php", []byte(nested)); len(fs) == 0 || err != ErrLimit {
		t.Errorf("deep blocks: findings %v err %v, want a finding and ErrLimit", fs, err)
	}
	deep := "<?php\nsystem(" + R("(", 100) + "$_GET['c']" + R(")", 100) + ");\n"
	if fs, err := e.Scan("php", "deep.php", []byte(deep)); len(fs) == 0 || err != ErrLimit {
		t.Errorf("deep nesting: findings %v err %v, want a finding and ErrLimit", fs, err)
	}
	regex := "app.get('/x', (req, res) => {\n  if (ok) /`/.test(s);\n  exec(req.query.x);\n});\n"
	if fs, err := e.Scan("js", "re.js", []byte(regex)); len(fs) == 0 || err != nil {
		t.Errorf("regex after if (...): findings %v err %v", fs, err)
	}
	jsx := "const A = () => <p>it`s here</p>;\napp.get('/x', (req, res) => { exec(req.query.x); });\n"
	if _, err := e.Scan("js", "a.jsx", []byte(jsx)); err != ErrPartial {
		t.Errorf("backtick in JSX text: err %v, want ErrPartial", err)
	}
	for _, src := range []string{"<?php $a = 'open\nsystem($_GET['x']);", "<?php /* open\nsystem($_GET['x']);"} {
		if _, err := e.Scan("php", "open.php", []byte(src)); err != ErrPartial {
			t.Errorf("%q: err %v, want ErrPartial", src, err)
		}
	}
}

func TestMinified(t *testing.T) {
	long := strings.Repeat("a=1;", 400) + "\n" // 1600 non-blank bytes on one line
	bundle := strings.Repeat(long, 30)         // 48 KB
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"bundle", bundle, true},
		{"small file with long lines", long + long, false},
		{"hand-written with one long line", strings.Repeat("const x = req.query.x;\n", 2000) + long, false},
		{"padded lines", strings.Repeat("exec(req.query.c);"+strings.Repeat(" ", 1200)+"\n", 40), false},
		{"empty", "", false},
	} {
		if got := Minified([]byte(c.src)); got != c.want {
			t.Errorf("%s: Minified = %v, want %v", c.name, got, c.want)
		}
	}
	e := engineForTest(t)
	if _, err := e.Scan("js", "app.min.js", []byte(bundle)); !errors.Is(err, ErrMinified) {
		t.Errorf("minified file: err = %v, want ErrMinified", err)
	}
	// Hand-written lines in a mostly minified file are still read.
	mixed := bundle + "app.get('/x', (req, res) => { exec(req.query.c); });\n"
	if fs, err := e.Scan("js", "mixed.js", []byte(mixed)); !errors.Is(err, ErrMinified) || len(fs) == 0 || fs[0].Line != 31 {
		t.Errorf("mixed file: %v, %v; want a finding on line 31 and ErrMinified", fs, err)
	}
	// A long line that opened a template literal: without it the rest reads as a
	// string, and that is reported with the minified file.
	open := bundle + "const t = `" + strings.Repeat("x", 1200) + "\n`;\nexec(req.query.c);\n"
	if _, err := e.Scan("js", "open.js", []byte(open)); !errors.Is(err, ErrMinified) || !errors.Is(err, ErrPartial) {
		t.Errorf("open literal: err = %v, want ErrMinified and ErrPartial", err)
	}
}

// An output built from many joined parts is read in one pass: the HTML context
// is fed part by part, not re-read from the start for every part, so a long
// concatenation cannot push the file over the limits and out of the analysis.
func TestContextLinear(t *testing.T) {
	e := engineForTest(t)
	src := "<?php\necho '<a href=\"' " + strings.Repeat(". $_GET['a'] . '\" x=\"' ", 20000) + ";\n"
	start := time.Now()
	fs, err := e.Scan("php", "concat.php", []byte(src))
	if el := time.Since(start); errors.Is(err, ErrLimit) || el > 2*time.Second || len(fs) == 0 {
		t.Errorf("20000 joined parts: %v, err %v, %d findings; want under 2s, no ErrLimit, reported", el, err, len(fs))
	}
}
