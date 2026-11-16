package engine

import (
	"testing"
	"time"
)

// The sources run of a summary (does the function return input of its own?)
// is skipped only where that cannot be: the function returns no value, or
// nothing that may bring input in is reached from it. A call whose target the
// call graph does not know counts as bringing input: the analysis may still
// resolve it to a function of the project. These must all be "may".
func TestMayReturnInput(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, rule, fn, src string
		want                      bool
	}{
		// PHP, php-sqli-string-concat ($_GET is a source)
		{"own source", "php", "php-sqli-string-concat", "f", "<?php\nfunction f() { return $_GET['x']; }\n", true},
		{"object method", "php", "php-sqli-string-concat", "f",
			"<?php\nclass M { function read() { return $_GET['x']; } }\nfunction f($m) { return $m->read(); }\n", true},
		{"static method", "php", "php-sqli-string-concat", "f",
			"<?php\nclass M { static function read() { return $_GET['x']; } }\nfunction f() { return M::read(); }\n", true},
		{"dynamic call", "php", "php-sqli-string-concat", "f", "<?php\nfunction f($cb) { return $cb(); }\n", true},
		{"call of a call", "php", "php-sqli-string-concat", "f", "<?php\nfunction f() { return make()(); }\n", true},
		{"include of a dynamic path", "php", "php-sqli-string-concat", "f", "<?php\nfunction f($p) { return include $p; }\n", true},
		{"require", "php", "php-sqli-string-concat", "f", "<?php\nfunction f() { return require __DIR__ . '/conf.php'; }\n", true},
		{"callable string", "php", "php-sqli-string-concat", "f",
			"<?php\nfunction g() { return $_GET['x']; }\nfunction f() { return call_user_func('g'); }\n", true},
		{"array callable", "php", "php-sqli-string-concat", "f",
			"<?php\nclass M { function read() { return $_GET['x']; } }\nfunction f($m) { return call_user_func(array($m, 'read')); }\n", true},
		{"closure in a variable", "php", "php-sqli-string-concat", "f",
			"<?php\nfunction f() { $c = function () { return $_GET['x']; }; return $c(); }\n", true},
		{"new of a class of the file", "php", "php-sqli-string-concat", "f",
			"<?php\nclass M { function __construct() { $this->v = $_GET['x']; } }\nfunction f() { return new M(); }\n", true},
		{"a function of the file that reads input", "php", "php-sqli-string-concat", "f",
			"<?php\nfunction g() { return $_GET['x']; }\nfunction f() { return g(); }\n", true},
		{"library call on a parameter", "php", "php-sqli-string-concat", "f", "<?php\nfunction f($x) { return strtoupper(trim($x)); }\n", false},
		{"no value returned", "php", "php-sqli-string-concat", "f", "<?php\nfunction f() { echo 'hi'; return; }\n", false},
		{"a function of the file without input", "php", "php-sqli-string-concat", "f",
			"<?php\nfunction g($x) { return $x . 'a'; }\nfunction f($y) { return g($y); }\n", false},
		// JavaScript, js-sqli-raw-interpolation (req.query is a source)
		{"js method of an object", "js", "js-sqli-raw-interpolation", "f",
			"class M { read(req) { return req.query.x; } }\nfunction f(m) { return m.read(); }\n", true},
		{"js computed call", "js", "js-sqli-raw-interpolation", "f", "function f(fns, k) { return fns[k](); }\n", true},
		{"js closure", "js", "js-sqli-raw-interpolation", "f", "function f(req) { const c = () => req.query.x; return c(); }\n", true},
		{"js arrow body", "js", "js-sqli-raw-interpolation", "f", "const f = (req) => req.query.x;\n", true},
		{"js no input", "js", "js-sqli-raw-interpolation", "f", "function f(a) { return a.trim(); }\n", false},
		// Python, a rule with request.args as a source
		{"py getattr call", "python", "python-sqli-dbapi-format", "f", "def f(o, n):\n    return getattr(o, n)()\n", true},
		{"py method", "python", "python-sqli-dbapi-format", "f",
			"class M:\n    def read(self):\n        return request.args['x']\n\ndef f(m):\n    return m.read()\n", true},
		{"py no input", "python", "python-sqli-dbapi-format", "f", "def f(a):\n    return a.strip()\n", false},
	}
	for _, c := range cases {
		var r *crule
		for _, x := range e.byLang[c.lang] {
			if x.rule.ID == c.rule {
				r = x
			}
		}
		if r == nil {
			t.Fatalf("%s: no rule %s", c.name, c.rule)
		}
		b := newBudget(Limits{MaxTokens: DefaultLimits.MaxTokens, MaxTime: 10 * time.Second})
		toks := lex(c.lang, c.src, b)
		tree := parse(c.lang, toks, b)
		ff := newFileFuncs(collectFuncs(tree, c.lang), c.lang)
		a := &analysis{r: r, php: c.lang == "php", py: c.lang == "python", js: c.lang == "js", b: b, kw: keywords[c.lang],
			seen: map[loc]bool{}, sc: newSummaries(ff), file: "a." + c.lang, ftoks: toks}
		fis := a.sc.funcs[c.fn]
		if len(fis) == 0 {
			t.Fatalf("%s: no function %s", c.name, c.fn)
		}
		if got := a.mayReturnInput(c.fn, fis[0]); got != c.want {
			t.Errorf("%s: mayReturnInput = %v, want %v\n%s", c.name, got, c.want, c.src)
		}
	}
}
