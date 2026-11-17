package engine

import (
	"slices"
	"testing"
)

// An allowlist check of a parsed URL's host validates that URL object, for
// the SSRF rules only: new URL in JavaScript, urlparse in Python. The string
// it was parsed from stays input (another parser may read another host), as
// does a URL from url.parse, a host truth test, a prefix check, a check of
// another URL, a URL that is something else on one path, a check against a
// string or an environment value (.includes and in are substring tests there),
// a URL written into after the check (u.host = v, Object.assign(u, ...), an
// alias's member), and no check; an XSS rule still reports the URL written into HTML.
func TestURLHostGuard(t *testing.T) {
	e := engineForTest(t)
	route := func(body string) string {
		return "const ALLOWED = new Set(['api.example.org']);\napp.get('/p', async (req, res) => {\n" + body + "  res.json(await r.json());\n});\n"
	}
	cases := []struct {
		name, lang, rule, src string
		want                  bool
	}{
		{"js: u.hostname in an allowlist, fetch(u)", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), false},
		{"js: u.host in an allowlist, fetch(u.href)", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.host)) return res.sendStatus(403);\n  const r = await fetch(u.href);\n"), false},
		{"js: compared with one host", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (u.hostname !== 'api.example.com') return res.sendStatus(403);\n  const r = await fetch(u);\n"), false},
		{"js: the string it was parsed from", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(req.query.target);\n"), true},
		{"js: url.parse", "js", "js-ssrf-http-request",
			route("  const u = url.parse(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u.href);\n"), true},
		{"js: a truth test of the host", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!u.hostname) return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: a suffix check of the host", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!u.hostname.endsWith('.example.com')) return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: no check", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  const r = await fetch(u);\n"), true},
		{"js: another URL's host", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  const v = new URL(req.query.other);\n  if (!ALLOWED.has(v.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: something else on one path", "js", "js-ssrf-http-request",
			route("  let u = new URL(req.query.target);\n  if (req.query.raw) { u = req.body; }\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u.url);\n"), true},
		{"js: a parsed object on one path", "js", "js-ssrf-http-request",
			route("  let u = new URL(req.query.target);\n  if (req.query.raw) { u = JSON.parse(req.query.raw); }\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), true},
		{"js: a URL on both paths", "js", "js-ssrf-http-request",
			route("  let u = new URL(req.query.target);\n  if (req.query.v) { u = new URL(req.query.other); }\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n"), false},
		{"js: an XSS rule still reads the URL", "js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  res.send('<a href=\"' + u.href + '\">next</a>');\n});\n", true},
		{"python: p.hostname in an allowlist, p.geturl()", "python", "python-ssrf-http-request",
			"ALLOWED = {'api.example.org'}\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", false},
		{"python: the string it was parsed from", "python", "python-ssrf-http-request",
			"ALLOWED = {'api.example.org'}\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(request.args['u']).text\n", true},
		{"js: u.host written after the check", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  u.host = req.query.h;\n  const r = await fetch(u);\n"), true},
		{"js: u.href written after the check", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  u.href = req.query.next;\n  const r = await fetch(u);\n"), true},
		{"js: Object.assign into u after the check", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  Object.assign(u, { host: req.query.h });\n  const r = await fetch(u);\n"), true},
		{"js: w.host written through an alias", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const w = u;\n  w.host = req.query.h;\n  const r = await fetch(u);\n"), true},
		{"js: u.pathname written with a fixed value", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  u.pathname = '/v1/items';\n  const r = await fetch(u);\n"), false},
		{"js: includes on a string", "js", "js-ssrf-http-request",
			"const ALLOWED = 'api.example.org';\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: includes on an environment value", "js", "js-ssrf-http-request",
			"const ALLOWED = process.env.ALLOWED_HOST;\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: includes on a name the file does not assign", "js", "js-ssrf-http-request",
			"app.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: includes on an array", "js", "js-ssrf-http-request",
			"const ALLOWED = ['api.example.org', 'cdn.example.org'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"js: includes on a split", "js", "js-ssrf-http-request",
			"const ALLOWED = process.env.ALLOWED_HOSTS.split(',');\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"python: in a string", "python", "python-ssrf-http-request",
			"ALLOWED = 'api.example.org'\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: in an environment value", "python", "python-ssrf-http-request",
			"ALLOWED = os.environ['ALLOWED_HOST']\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: in a list", "python", "python-ssrf-http-request",
			"@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ['api.example.org']:\n        abort(403)\n    return requests.get(u.geturl()).text\n", false},
		{"python: in a split", "python", "python-ssrf-http-request",
			"ALLOWED = os.environ['ALLOWED_HOSTS'].split(',')\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", false},
		{"php: parse_url's host (another parser than the client's)", "php", "php-ssrf-http-request",
			"<?php\n$p = parse_url($_GET['u']);\nif (!in_array($p['host'], $allowed, true)) { exit; }\n$r = wp_remote_get($_GET['u']);\n", true},
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
