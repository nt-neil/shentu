package engine

import "testing"

// new URL(a, base): the path and query (pathname, search, searchParams, hash)
// are a's; the base gives the origin. A request value in the base reaches
// u.origin or the URL itself, not u.pathname.
func TestURLPathParts(t *testing.T) {
	e := engineForTest(t)
	h := func(body string) string { return "app.get('/f', (req, res) => {\n" + body + "\n});\n" }
	for _, c := range []struct {
		name, rule, src string
		want            bool
	}{
		{"path from a fixed first argument", "js-path-traversal-send-file",
			h("  const u = new URL('/static/logo.png', req.query.base);\n  fs.readFile(u.pathname, () => {});"), false},
		{"path written in place", "js-path-traversal-send-file",
			h("  fs.readFile(new URL('/static/logo.png', req.query.base).pathname, () => {});"), false},
		{"path from the request's first argument", "js-path-traversal-send-file",
			h("  const u = new URL(req.query.p, 'http://localhost');\n  fs.readFile(u.pathname, () => {});"), true},
		{"in place, from the request", "js-path-traversal-send-file",
			h("  fs.readFile(new URL(req.query.p, 'http://localhost').pathname, () => {});"), true},
		{"a relative first argument keeps the base's path", "js-path-traversal-send-file",
			h("  const u = new URL('logo.png', req.query.base);\n  fs.readFile(u.pathname, () => {});"), true},
		{"a variable first argument", "js-path-traversal-send-file",
			h("  fs.readFile(new URL(name, req.query.base).pathname, () => {});"), true},
		{"an absolute first argument", "js-path-traversal-send-file",
			h("  fs.readFile(new URL('https://cdn.example/logo.png', req.query.base).pathname, () => {});"), false},
		{"the whole URL from a request base", "js-ssrf-http-request",
			h("  fetch(new URL('/api', req.query.base));"), true},
		{"the URL variable from a request base", "js-ssrf-http-request",
			h("  const u = new URL('/api', req.query.base);\n  fetch(u);"), true},
	} {
		fs, err := e.Scan("js", "a.js", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == c.rule
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %s reported %v (err %v), want %v", c.name, c.rule, got, err, c.want)
		}
	}
}
