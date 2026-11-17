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
		{"js: x.host written through an alias of an alias", "js", "js-ssrf-http-request",
			route("  const u = new URL(req.query.target);\n  if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);\n  const w = u;\n  const x = w;\n  x.host = req.query.h;\n  const r = await fetch(u);\n"), true},
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
		{"js: env || split default", "js", "js-ssrf-http-request",
			"const ALLOWED = process.env.H || 'a,b'.split(',');\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: ternary", "js", "js-ssrf-http-request",
			"const ALLOWED = process.env.H ? process.env.H : ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: env split", "js", "js-ssrf-http-request",
			"const ALLOWED = process.env.H.split(',');\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"js: (env || default).split", "js", "js-ssrf-http-request",
			"const ALLOWED = (process.env.H || 'a.example').split(',');\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"js: a destructured name of the same name in the handler", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const { ALLOWED } = process.env;\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: catch binds the name", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\ntry { init(); } catch (ALLOWED) { log(ALLOWED); }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: for binds the name", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\nfor (const ALLOWED of lists) { use(ALLOWED); }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: an object key of the name", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\nconst cfg = { ALLOWED: 'a.example' };\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: a default parameter", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\nfunction f(ALLOWED = ['b.example']) { return ALLOWED; }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: += turns the array into a string", "js", "js-ssrf-http-request",
			"let ALLOWED = ['a.example'];\nALLOWED += ',b.example';\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: assigned twice", "js", "js-ssrf-http-request",
			"let ALLOWED = ['a.example'];\nALLOWED = process.env.H;\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: a parameter of the same name", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\nfunction g(ALLOWED) { return ALLOWED; }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: a const inside a function", "js", "js-ssrf-http-request",
			"function load() { const ALLOWED = ['a.example']; return ALLOWED; }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: Object.assign in a declaration", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const z = Object.assign(u, { host: req.query.h });\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: Reflect.set", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  Reflect.set(u, 'host', req.query.h);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: u passed to a function that may change it", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\nfunction setHost(x, h) { x.host = h; }\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  setHost(u, req.query.h);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: u passed to a function, nothing else", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  touch(u);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: w = u, then u.host written, fetch(w)", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  const w = u;\n  u.host = req.query.h;\n  const r = await fetch(w);\n  res.json(await r.json());\n});\n", true},
		{"js: u.hostname written", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  u.hostname = req.query.h;\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: u.port written", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  u.port = req.query.p;\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: u.username written", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  u.username = req.query.n;\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", true},
		{"js: u.hostname written with a fixed value", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  u.hostname = 'a.example';\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"js: fetch(u) twice", "js", "js-ssrf-http-request",
			"const ALLOWED = ['a.example'];\napp.get('/p', async (req, res) => {\n  const u = new URL(req.query.target);\n  if (!ALLOWED.includes(u.hostname)) return res.sendStatus(403);\n  await fetch(u);\n  const r = await fetch(u);\n  res.json(await r.json());\n});\n", false},
		{"python: env or split default", "python", "python-ssrf-http-request",
			"ALLOWED = os.environ.get('H') or 'a,b'.split(',')\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: conditional expression", "python", "python-ssrf-http-request",
			"ALLOWED = os.environ['H'] if os.environ.get('H') else ['a.example']\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: env.get(default).split", "python", "python-ssrf-http-request",
			"ALLOWED = os.environ.get('H', 'a.example').split(',')\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", false},
		{"python: a parameter of the same name", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\ndef g(ALLOWED):\n    return ALLOWED\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: for binds the name", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\nfor ALLOWED in os.environ['H'].split(';'):\n    pass\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: with binds the name", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\nwith open('hosts') as ALLOWED:\n    pass\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: except binds the name", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\ntry:\n    load()\nexcept Exception as ALLOWED:\n    pass\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: a tuple of targets", "python", "python-ssrf-http-request",
			"ALLOWED, n = os.environ['H'], 1\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: a keyword of the name", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\ncfg = dict(ALLOWED='a.example')\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: assigned in a function", "python", "python-ssrf-http-request",
			"def load():\n    ALLOWED = ['a.example']\n    return ALLOWED\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    return requests.get(u.geturl()).text\n", true},
		{"python: _replace with input", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    u = u._replace(netloc=request.args['h'])\n    return requests.get(u.geturl()).text\n", true},
		{"python: _replace of the path", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    u = u._replace(path='/v1')\n    return requests.get(u.geturl()).text\n", false},
		{"python: list(u) with a new host", "python", "python-ssrf-http-request",
			"ALLOWED = ['a.example']\n@app.route('/p')\ndef p():\n    u = urlparse(request.args['u'])\n    if u.hostname not in ALLOWED:\n        abort(403)\n    parts = list(u)\n    parts[1] = request.args['h']\n    return requests.get(urlunparse(parts)).text\n", true},
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
