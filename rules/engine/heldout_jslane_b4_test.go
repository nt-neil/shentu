package engine

import "testing"

// heldOutJSLaneB4 are held-out cases for batch 4 of the JavaScript rule lane:
// Koa's ctx.body as an HTML response and Express's chained res.status().send(),
// in shapes apart from the rule samples.
var heldOutJSLaneB4 = []struct {
	name, lang, rule, src string
	vulnerable            bool
	gap                   string
}{
	{"koa html from route param", "js", "js-xss-response", "router.get('/u/:name', async (ctx) => {\n  ctx.body = `<section><h2>${ctx.params.name}</h2></section>`;\n});\n", true, ""},
	{"koa response.body from form", "js", "js-xss-response", "router.post('/echo', async (ctx) => {\n  const { msg } = ctx.request.body;\n  ctx.response.body = '<pre>' + msg + '</pre>';\n});\n", true, ""},
	{"koa attribute value", "js", "js-xss-response", "router.get('/img', async (ctx) => {\n  ctx.body = '<img alt=\"' + ctx.query.alt + '\" src=\"/a.png\">';\n});\n", true, ""},
	{"koa escaped html", "js", "js-xss-response", "router.get('/u/:name', async (ctx) => {\n  ctx.body = `<h2>${escapeHtml(ctx.params.name)}</h2>`;\n});\n", false, ""},
	{"koa json body", "js", "js-xss-response", "router.get('/s', async (ctx) => {\n  ctx.body = { q: ctx.query.q, hits: [] };\n});\n", false, ""},
	{"koa fixed body after a check", "js", "js-xss-response", "router.get('/s', async (ctx) => {\n  if (!ctx.query.q) { ctx.body = '<p>missing</p>'; return; }\n  ctx.body = '<p>ok</p>';\n});\n", false, ""},
	{"koa script variable", "js", "js-xss-response-url", "router.get('/boot', async (ctx) => {\n  const theme = ctx.query.theme;\n  ctx.body = '<script>window.THEME = \"' + theme + '\";</script>';\n});\n", true, ""},
	{"koa link href", "js", "js-xss-response-url", "router.get('/back', async (ctx) => {\n  ctx.body = `<a href=\"${ctx.query.back}\">back</a>`;\n});\n", true, ""},
	{"koa script jsesc", "js", "js-xss-response-url", "router.get('/boot', async (ctx) => {\n  ctx.body = '<script>window.Q = \"' + jsesc(ctx.query.q) + '\";</script>';\n});\n", false, ""},
	{"express status chain html", "js", "js-xss-response", "app.get('/fail', (req, res) => {\n  res.status(502).send(`<p>upstream ${req.query.target} failed</p>`);\n});\n", true, ""},
	{"express status set chain", "js", "js-xss-response", "app.get('/fail', (req, res) => {\n  res.status(400).set('Cache-Control', 'no-store').send('<b>' + req.params.code + '</b>');\n});\n", true, ""},
	{"express status chain sendStatus", "js", "js-xss-response", "app.get('/fail', (req, res) => {\n  console.error('bad target', req.query.target);\n  res.status(502).end();\n});\n", false, ""},
}

func TestHeldOutJSLaneB4(t *testing.T) {
	e := engineForTest(t)
	pass := 0
	for _, c := range heldOutJSLaneB4 {
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		found := false
		for _, f := range fs {
			found = found || f.RuleID == c.rule
		}
		ok := found == c.vulnerable && (c.vulnerable || len(fs) == 0)
		switch {
		case ok:
			pass++
			if c.gap != "" {
				t.Errorf("%s: marked as a known gap but now passes; remove the mark", c.name)
			}
		case c.gap != "":
			t.Logf("known gap, %s: %s", c.name, c.gap)
		case c.vulnerable:
			t.Errorf("%s: not reported by %s (got %+v)", c.name, c.rule, fs)
		default:
			t.Errorf("%s: reported %+v", c.name, fs)
		}
	}
	t.Logf("JS lane batch 4 held-out cases right: %d/%d", pass, len(heldOutJSLaneB4))
}
