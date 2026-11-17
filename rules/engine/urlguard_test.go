package engine

import (
	"slices"
	"testing"
)

// A check of a parsed URL's host validates the URL and what it was parsed
// from, for the SSRF rules only: in JavaScript (new URL), Python (urlparse)
// and PHP (parse_url). A check of another URL's host, a scheme check, a value
// given a new value after the parse, or no check at all leave the request
// reported; an XSS rule still reports the same URL written into HTML.
func TestURLHostGuard(t *testing.T) {
	e := engineForTest(t)
	route := func(body string) string {
		return "app.get('/p', async (req, res) => {\n" + body + "  res.json(await r.json());\n});\n"
	}
	cases := []struct {
		name, lang, rule, src string
		want                  bool
	}{
		{"js: u.hostname checked, fetch(u)", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), false},
		{"js: u.host checked, fetch(the input)", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.host)) return res.sendStatus(403);\n  const r = await fetch(req.query.target);\n"), false},
		{"js: the host in a variable", "js", "js-ssrf-http-request",
			route("  const host = new URL(req.query.target).hostname;\n  if (!ALLOWED.includes(host)) return res.sendStatus(403);\n  const r = await fetch(req.query.target);\n"), false},
		{"js: compared with one host", "js", "js-ssrf-http-request",
			route("  const target = req.query.target;\n  const u = new URL(target);\n  if (u.hostname !== 'api.example.com') return res.sendStatus(403);\n  const r = await fetch(target);\n"), false},
		{"js: no check", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  const r = await fetch(u);\n"), true},
		{"js: another URL's host", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  const v = new URL(req.query.other);\n  if (!ALLOWED.has(v.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: only the scheme", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (u.protocol !== 'https:') return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: a new value after the parse", "js", "js-ssrf-http-request",
			route("  let target = req.query.a;\n  const u = new URL(target);\n  target = req.query.b;\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(target);\n"), true},
		{"js: an XSS rule still reads the URL", "js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  res.send('<a href=\"' + req.query.target + '\">next</a>');\n});\n", true},
		{"python: p.hostname checked", "python", "python-ssrf-http-request",
			"@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(request.args['u']).text\n", false},
		{"python: no check", "python", "python-ssrf-http-request",
			"@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    return requests.get(request.args['u']).text\n", true},
		{"php: parse_url($x, PHP_URL_HOST) checked", "php", "php-ssrf-http-request",
			"<?php\n$host = parse_url($_GET['u'], PHP_URL_HOST);\nif (!in_array($host, $allowed, true)) { exit; }\n$r = wp_remote_get($_GET['u']);\n", false},
		{"php: $p['host'] checked", "php", "php-ssrf-http-request",
			"<?php\n$p = parse_url($_GET['u']);\nif (!in_array($p['host'], $allowed, true)) { exit; }\n$r = wp_remote_get($_GET['u']);\n", false},
		{"php: no check", "php", "php-ssrf-http-request",
			"<?php\n$p = parse_url($_GET['u']);\n$r = wp_remote_get($_GET['u']);\n", true},
	}
	ext := map[string]string{"js": "js", "python": "py", "php": "php"}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "a."+ext[c.lang], []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
		if got := slices.Contains(ids, c.rule); got != c.want {
			t.Errorf("%s: %s reported %v, want %v (all: %v)", c.name, c.rule, got, c.want, ids)
		}
	}
}
