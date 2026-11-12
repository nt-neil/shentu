package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// A regular-expression test anchored at the start, with a fixed prefix
// ending in "/" and then a class that cannot be "/" or "\", fixes how a value
// starts: a redirect to it stays on the site. Not without the anchor, with
// input in the prefix, with .* first, with the class optional or holding a
// "/", nor when the test's result is not used.
func TestRegexPrefixGuard(t *testing.T) {
	one := 1
	rule := func(lang, src, sink string) rules.Rule {
		return rules.Rule{ID: lang, Lang: lang, Class: "open-redirect", CWE: "CWE-601", Severity: "medium", Title: "t",
			Sources: []string{src}, Sinks: []string{sink}, Sanitizers: []string{}, Args: []rules.Args{{Arg: &one, Leading: true}}}
	}
	e, err := New([]rules.Rule{rule("python", "self.get_argument(", "self.redirect("), rule("js", "req.query", "res.redirect("),
		rule("php", "$_GET", "wp_redirect(")})
	if err != nil {
		t.Fatal(err)
	}
	py := func(check string) string {
		return "class L(RequestHandler):\n    def get(self):\n        n = self.get_argument('n')\n" + check + "\n"
	}
	for _, c := range []struct {
		name, lang, src string
		want            bool
	}{
		{"re.match with a fixed prefix", "python", py("        if re.match(r'/[a-z][a-z0-9/_-]*', n,):\n            self.redirect(n)"), false},
		{"re.escape of a setting", "python", py("        if re.match(re.escape(BASE) + r'/[a-z]([a-z0-9/_-]|\\.[^.])+$', n):\n            self.redirect(n)"), false},
		{"a validator returning the test (taguette)", "python",
			"def is_next_url_safe(url, base_path):\n    return url and re.match(re.escape(base_path) + r'/[a-z]([a-z0-9/_-]|\\.[^.])+(?:\\?.*)?$', url)\n\n" +
				"class L(RequestHandler):\n    def get(self):\n        n = self.get_argument('n')\n        if is_next_url_safe(n, BASE):\n            self.redirect(n)\n        else:\n            self.redirect('/')\n", false},
		{"JavaScript /^\\/[a-z]/.test", "js", "app.get('/l', (req, res) => {\n  const n = req.query.n;\n  if (/^\\/[a-z]/.test(n)) res.redirect(n);\n});\n", false},
		{"PHP preg_match", "php", "<?php\n$n = $_GET['n'];\nif (preg_match('/^\\/[a-z]/', $n)) { wp_redirect($n); }\n", false},
		// not a check
		{"no anchor", "python", py("        if re.search(r'/[a-z]', n):\n            self.redirect(n)"), true},
		{"input as the prefix", "python", py("        if re.match(re.escape(self.get_argument('b')) + r'/[a-z]', n):\n            self.redirect(n)"), true},
		{".* first", "python", py("        if re.match(r'.*/[a-z]', n):\n            self.redirect(n)"), true},
		{"an optional class", "python", py("        if re.match(r'/[a-z]*', n):\n            self.redirect(n)"), true},
		{"a class holding /", "python", py("        if re.match(r'/[a-z/]', n):\n            self.redirect(n)"), true},
		{"the result not used", "python", py("        re.match(r'/[a-z]', n)\n        self.redirect(n)"), true},
		{"a top-level alternation", "python", py("        if re.match(r'/[a-z]|https?://', n):\n            self.redirect(n)"), true},
		{"a range holding /", "python", py("        if re.match(r'/[!-z]', n):\n            self.redirect(n)"), true},
		{"a class with an escape", "python", py("        if re.match(r'/[\\S]', n):\n            self.redirect(n)"), true},
		{"{0,} on the class", "python", py("        if re.match(r'/[a-z]{0,8}', n):\n            self.redirect(n)"), true},
		{"// as the prefix", "python", py("        if re.match(r'//[a-z]', n):\n            self.redirect(n)"), true},
		{"flags", "python", py("        if re.search(r'^/[a-z]', n, re.M):\n            self.redirect(n)"), true},
		{"JavaScript \\A", "js", "app.get('/l', (req, res) => {\n  const n = req.query.n;\n  if (/\\A\\/[a-z]/.test(n)) res.redirect(n);\n});\n", true},
		{"JavaScript without ^", "js", "app.get('/l', (req, res) => {\n  const n = req.query.n;\n  if (/\\/[a-z]/.test(n)) res.redirect(n);\n});\n", true},
	} {
		fs, err := e.Scan(c.lang, map[string]string{"python": "a.py", "js": "a.js", "php": "a.php"}[c.lang], []byte(c.src))
		if err != nil || (len(fs) > 0) != c.want {
			t.Errorf("%s: %v (err %v), want reported %v", c.name, fs, err, c.want)
		}
	}
}
