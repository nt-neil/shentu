package engine

import (
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
