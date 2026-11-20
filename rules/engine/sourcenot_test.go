package engine

import (
	"slices"
	"testing"
)

// The Host header is not input to the XSS rules, in any spelling: a route
// handler's headers, req.headers['host'], req.get('host'), NestJS's
// @Headers('host'), Next's headers().get('host'), and h.host after
// h = req.headers. Other headers stay input, and Host stays input to
// js-ssrf-host-header.
func TestXSSNotHost(t *testing.T) {
	e := engineForTest(t)
	express := func(v string) string {
		return "app.get('/p', (req, res) => {\n  res.send('<p>' + " + v + " + '</p>');\n});\n"
	}
	cases := []struct {
		name, file, rule, src string
		want                  bool
	}{
		{"route headers.host", "a.js", "js-xss-response", express("req.headers.host"), false},
		{"route headers['host']", "a.js", "js-xss-response", express("req.headers['host']"), false},
		{"route req.get('host')", "a.js", "js-xss-response", express("req.get('host')"), false},
		{"route req.header('Host')", "a.js", "js-xss-response", express("req.header('Host')"), false},
		{"route user-agent", "a.js", "js-xss-response", express("req.headers['user-agent']"), true},
		{"route referer", "a.js", "js-xss-response", express("req.headers.referer"), true},
		{"route req.get(name)", "a.js", "js-xss-response", express("req.get(h)"), false},
		{"other param name", "a.js", "js-xss-response",
			"app.get('/p', (rq, res) => {\n  res.send('<p>' + rq.headers.host + '</p>');\n});\n", false},
		{"other param name, user-agent", "a.js", "js-xss-response",
			"app.get('/p', (rq, res) => {\n  res.send('<p>' + rq.headers['user-agent'] + '</p>');\n});\n", true},
		{"nest @Headers('host')", "a.ts", "js-xss-response",
			"@Controller()\nexport class C {\n  @Get('p')\n  p(@Headers('host') host: string, @Res() res: Response) {\n    res.send('<p>' + host + '</p>');\n  }\n}\n", false},
		{"nest @Headers('x-name')", "a.ts", "js-xss-response",
			"@Controller()\nexport class C {\n  @Get('p')\n  p(@Headers('x-name') v: string, @Res() res: Response) {\n    res.send('<p>' + v + '</p>');\n  }\n}\n", true},
		{"url: route headers.host", "a.js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  res.send('<a href=\"' + req.headers.host + '\">x</a>');\n});\n", false},
		{"url: req.headers.get('host')", "a.js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  res.send('<a href=\"' + request.headers.get('host') + '\">x</a>');\n});\n", false},
		{"url: next headers().get('host')", "a.js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  res.send('<a href=\"' + headers().get('host') + '\">x</a>');\n});\n", false},
		{"url: referer", "a.js", "js-xss-response-url",
			"app.get('/p', (req, res) => {\n  res.send('<a href=\"' + req.headers.referer + '\">x</a>');\n});\n", true},
		{"url: koa ctx.request.header['host']", "a.js", "js-xss-response-url",
			"router.get('/p', async (ctx) => {\n  ctx.body = '<a href=\"' + ctx.request.header['host'] + '\">x</a>';\n});\n", false},
		{"url: koa ctx.request.header['x-name']", "a.js", "js-xss-response-url",
			"router.get('/p', async (ctx) => {\n  ctx.body = '<a href=\"' + ctx.request.header['x-name'] + '\">x</a>';\n});\n", true},
		{"url: h = req.headers, h.host", "a.js", "js-xss-response-url",
			"function f(req, res) {\n  const h = req.headers;\n  res.send('<a href=\"' + h.host + '\">x</a>');\n}\n", false},
		{"url: h = req.headers, h.referer", "a.js", "js-xss-response-url",
			"function f(req, res) {\n  const h = req.headers;\n  res.send('<a href=\"' + h.referer + '\">x</a>');\n}\n", true},
		{"ssrf: Host stays input", "a.js", "js-ssrf-host-header",
			"app.get('/p', async (req, res) => {\n  const r = await fetch('https://' + req.headers.host + '/x');\n  res.json(await r.json());\n});\n", true},
		{"ssrf: nest @Headers('host')", "a.ts", "js-ssrf-host-header",
			"@Controller()\nexport class C {\n  @Get('p')\n  async p(@Headers('host') host: string) {\n    return (await fetch('https://' + host + '/x')).json();\n  }\n}\n", true},
		{"ssrf: next headers().get('host')", "a.js", "js-ssrf-host-header",
			"export async function GET() {\n  const r = await fetch('https://' + headers().get('host') + '/x');\n  return Response.json(await r.json());\n}\n", true},
	}
	for _, c := range cases {
		lang := "js"
		if c.file == "a.ts" {
			lang = "ts"
		}
		fs, err := e.Scan(lang, c.file, []byte(c.src))
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
