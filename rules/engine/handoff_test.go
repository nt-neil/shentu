package engine

import (
	"slices"
	"testing"
)

// Where a rule handed a way of writing to another (route_not, chain_not, a
// narrower sanitizer, a sink taken out), each way is still reported, by the one
// rule that owns it: the Host header is js-ssrf-host-header's in every
// framework's spelling, a client made in the call (with or without arguments)
// is python-ssrf-async-client's, only an SQL driver's escape cleans
// js-sqli-node-http-query's input, and ->orderBy( is php-sqli-orderby-identifier's.
func TestHandoffOwner(t *testing.T) {
	e := engineForTest(t)
	express := func(v string) string {
		return "app.get('/p', async (req, res) => {\n  const r = await fetch('https://' + " + v + " + '/x');\n  res.json(await r.json());\n});\n"
	}
	alias := func(v string) string {
		return "app.get('/p', async (req, res) => {\n  const h = req.headers;\n  const r = await fetch('https://' + " + v + " + '/x');\n  res.json(await r.json());\n});\n"
	}
	koa := func(v string) string {
		return "router.get('/p', async (ctx) => {\n  const r = await fetch('https://' + " + v + " + '/x');\n  ctx.body = await r.text();\n});\n"
	}
	nest := func(param, v string) string {
		return "import { Controller, Get, Req, Request } from '@nestjs/common';\n" + nestBody(param, "", v)
	}
	nestNoImport := func(param, v string) string { // another library's @Req(): not NestJS's request (reqalias.go nestFile)
		return "import { Req } from './decorators';\n" + nestBody(param, "", v)
	}
	nestPre := func(pre, v string) string {
		return "import { Controller, Get, Req } from '@nestjs/common';\n" + nestBody("@Req() r: Request", pre, v)
	}
	flask := func(call string) string {
		return "import httpx\n\n@app.route('/f')\ndef f():\n    u = request.args.get('u')\n    return " + call + ".text\n"
	}
	node := func(v string) string {
		return "http.createServer((req, res) => {\n  const q = url.parse(req.url, true).query;\n  connection.query('SELECT * FROM t WHERE id = ' + " + v + ", (e, r) => res.end(JSON.stringify(r)));\n}).listen(8080);\n"
	}
	route := func(params, pre, v string) string { // a handler whose request is not called req
		return "app.get('/p', async (" + params + ") => {\n" + pre + "  const r = await fetch('https://' + " + v + " + '/x');\n  return r.text();\n});\n"
	}
	cases := []struct {
		name, lang, cwe, src string
		want                 []string
	}{
		{"(r, s) => r.headers.host", "js", "CWE-918", route("r, s", "", "r.headers.host"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.headers['host']", "js", "CWE-918", route("r, s", "", "r.headers['host']"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.headers['x-forwarded-host']", "js", "CWE-918", route("r, s", "", "r.headers['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.headers['X-Forwarded-Host'] is lower-cased as req's", "js", "CWE-918", route("r, s", "", "r.headers['X-Forwarded-Host']"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.headers['Host']", "js", "CWE-918", route("r, s", "", "r.headers['Host']"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.hostname", "js", "CWE-918", route("r, s", "", "r.hostname"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.host", "js", "CWE-918", route("r, s", "", "r.host"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.get('host')", "js", "CWE-918", route("r, s", "", "r.get('host')"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.header('x-forwarded-host')", "js", "CWE-918", route("r, s", "", "r.header('x-forwarded-host')"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.get('referer') is any header", "js", "CWE-918", "app.get('/p', async (r, s) => {\n  const x = await fetch(r.get('referer'));\n  return x.text();\n});\n", []string{"js-ssrf-http-request"}},
		{"(r, s) => q = r; q.headers.host", "js", "CWE-918", route("r, s", "  const q = r;\n", "q.headers.host"), []string{"js-ssrf-host-header"}},
		{"(r, s) => h = r.headers; h['Host']", "js", "CWE-918", route("r, s", "  const h = r.headers;\n", "h['Host']"), []string{"js-ssrf-host-header"}},
		{"({ headers }, s) => headers.host", "js", "CWE-918", route("{ headers }, s", "", "headers.host"), []string{"js-ssrf-host-header"}},
		{"({ headers: hd }, s) => hd['x-forwarded-host']", "js", "CWE-918", route("{ headers: hd }, s", "", "hd['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"({ query }, s) => query.u", "js", "CWE-918", "app.get('/p', async ({ query }, s) => {\n  const x = await fetch(query.u);\n  return x.text();\n});\n", []string{"js-ssrf-http-request"}},
		{"(r, s) => const { headers } = r; headers.host", "js", "CWE-918", route("r, s", "  const { headers } = r;\n", "headers.host"), []string{"js-ssrf-host-header"}},
		{"(r, s) => const { hostname: hn } = r; hn", "js", "CWE-918", route("r, s", "  const { hostname: hn } = r;\n", "hn"), []string{"js-ssrf-host-header"}},
		{"a callback's parameter of the same name shadows the request", "js", "CWE-918", "app.get('/p', async (r, s) => {\n  [{ hostname: 'a.example' }].forEach(async (r) => {\n    await fetch('https://' + r.hostname + '/x');\n  });\n  s.end();\n});\n", nil},
		{"q = r, then q = another object", "js", "CWE-918", route("r, s", "  let q = r;\n  q = { hostname: 'a.example' };\n", "q.hostname"), nil},
		{"q = r, q reassigned on one branch only (S-1)", "js", "CWE-918", route("r, s", "  let q = r;\n  if (s.locals.x) { q = { hostname: 'a.example' }; }\n", "q.hostname"), []string{"js-ssrf-host-header"}},
		{"q = r, q reassigned in a loop's body", "js", "CWE-918", route("r, s", "  let q = r;\n  for (const o of s.locals.list) { q = o; }\n", "q.hostname"), []string{"js-ssrf-host-header"}},
		{"q = r, q reassigned on one branch, read on that branch", "js", "CWE-918", "app.get('/p', async (r, s) => {\n  let q = r;\n  if (s.locals.x) {\n    q = { hostname: 'a.example' };\n    const x = await fetch('https://' + q.hostname + '/x');\n    return x.text();\n  }\n  s.end();\n});\n", nil},
		{"q = r, q = r.headers on one branch: both paths followed", "js", "CWE-918", route("r, s", "  let q = r;\n  if (s.locals.x) { q = r.headers; }\n", "q.host"), []string{"js-ssrf-host-header"}},
		{"q = r, q reassigned on both branches (reports more than it must)", "js", "CWE-918", route("r, s", "  let q = r;\n  if (s.locals.x) { q = { hostname: 'a.example' }; } else { q = { hostname: 'b.example' }; }\n", "q.hostname"), []string{"js-ssrf-host-header"}},
		{"const { 'x-forwarded-host': xfh } = r.headers (S-3)", "js", "CWE-918", route("r, s", "  const { 'x-forwarded-host': xfh } = r.headers;\n", "xfh"), []string{"js-ssrf-host-header"}},
		{"const { 'x-forwarded-host': xfh } = req.headers (S-3)", "js", "CWE-918", "app.get('/p', async (req, res) => {\n  const { 'x-forwarded-host': xfh } = req.headers;\n  const r = await fetch('https://' + xfh + '/x');\n  res.json(await r.json());\n});\n", []string{"js-ssrf-host-header"}},
		{"const { 'referer': ref } = r.headers is any header", "js", "CWE-918", route("r, s", "  const { 'referer': ref } = r.headers;\n", "ref"), []string{"js-ssrf-http-request"}},
		{"const { headers: { host } } = r (nested)", "js", "CWE-918", route("r, s", "  const { headers: { host } } = r;\n", "host"), []string{"js-ssrf-host-header"}},
		{"const { headers: { host: h } = {} } = r (nested, default)", "js", "CWE-918", route("r, s", "  const { headers: { host: h } = {} } = r;\n", "h"), []string{"js-ssrf-host-header"}},
		{"({ headers: { host } }, s) => host (nested parameter)", "js", "CWE-918", route("{ headers: { host } }, s", "", "host"), []string{"js-ssrf-host-header"}},
		{"({ request }) => request.header.host (Koa)", "js", "CWE-918", "const Koa = require('koa');\n" + route("{ request }", "", "request.header.host"), []string{"js-ssrf-host-header"}},
		{"({ request: { header } }) => header.host (Koa, nested)", "js", "CWE-918", "import Router from '@koa/router';\n" + route("{ request: { header } }", "", "header.host"), []string{"js-ssrf-host-header"}},
		{"({ request, state }) => request.get('referer') (Koa)", "js", "CWE-918", "const Koa = require('koa');\n" + route("{ request, state }", "", "request.get('referer')"), []string{"js-ssrf-http-request"}},
		{"({ body, state }, res) => body.u without Koa is Express's req.body (S-5)", "js", "CWE-918", "app.get('/p', async ({ body, state }, res) => {\n  const x = await fetch(body.u);\n  res.send(await x.text());\n});\n", []string{"js-ssrf-http-request"}},
		{"({ body, state }) => body.u in a Koa file is the response (S-5 control)", "js", "CWE-918", "const Koa = require('koa');\napp.get('/p', async ({ body, state }) => {\n  const x = await fetch(body.u);\n  return x.text();\n});\n", nil},
		{"h = r.headers, h = r.query on one branch, { host } = h: both paths (S-4)", "js", "CWE-918", route("r, s", "  let h = r.headers;\n  if (s.locals.x) { h = r.query; }\n  const { host } = h;\n", "host"), []string{"js-ssrf-host-header", "js-ssrf-http-request"}},
		{"h = r.headers, { host } = h: host-header's only (S-4 control)", "js", "CWE-918", route("r, s", "  const h = r.headers;\n  const { host } = h;\n", "host"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, x = h, x.host: host-header's only (integ S-1)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const x = h;\n    const r = await fetch('http://' + x.host + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, x = h, x['Host']: host-header's only (integ S-1)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const x = h;\n    const r = await fetch('http://' + x['Host'] + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, x = h, x['x-forwarded-host']: host-header's only (integ S-1)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const x = h;\n    const r = await fetch('http://' + x['x-forwarded-host'] + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h.host: host-header's (integ S-1 control)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const r = await fetch('http://' + h.host + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['Host']: host-header's (c-review S-r2-2)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const r = await fetch('http://' + h['Host'] + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, x = h, x.referer: http-request's (integ S-1 control)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    const x = h;\n    const r = await fetch(x.referer);\n    return r.text();\n  }\n}\n", []string{"js-ssrf-http-request"}},
		{"nest @Headers() h, x = h, x = another object on one branch: x still the headers (integ S-1)", "ts", "CWE-918", "import { Controller, Get, Headers } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async a(@Headers() h: any) {\n    let x = h;\n    if (h.debug) { x = { host: 'a.example' }; }\n    const r = await fetch('http://' + x.host + '/internal');\n    return r.text();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"h = r.headers, x = h, x.host: host-header's only (integ S-1)", "js", "CWE-918", route("r, s", "  const h = r.headers;\n  const x = h;\n", "x.host"), []string{"js-ssrf-host-header"}},
		{"x = r.headers or r.query by branch, x.host: both rules, the query path keeps it (integ S-1 control)", "js", "CWE-918", route("r, s", "  let x = r.headers;\n  if (s.locals.y) { x = r.query; }\n", "x.host"), []string{"js-ssrf-host-header", "js-ssrf-http-request"}},
		{"h = r.headers, x = h, x.referer: http-request's (integ S-1 control)", "js", "CWE-918", route("r, s", "  const h = r.headers;\n  const x = h;\n", "x.referer"), []string{"js-ssrf-http-request"}},
		{"next: h = await headers(), h.get('host') (a1)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = await headers();\n  const r = await fetch('https://' + h.get('host') + '/x');\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-host-header"}},
		{"next: h = await headers(), h.get('X-Forwarded-Host') (a1)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = await headers();\n  const r = await fetch('https://' + h.get('X-Forwarded-Host') + '/x');\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-host-header"}},
		{"next: h = await headers(), h.get('x-target') (a1)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = await headers();\n  const r = await fetch(h.get('x-target'));\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-http-request"}},
		{"next: h = headers() (sync), h.get('host') (a1)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = headers();\n  const r = await fetch('https://' + h.get('host') + '/x');\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-host-header"}},
		{"next: h = (await headers()), redirect to h.get('host') (a1)", "js", "CWE-601", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = (await headers());\n  redirect('https://' + h.get('host') + '/login');\n}\n", []string{"js-open-redirect-next"}},
		{"next: (await headers()).get('host') written out stays (a1 control)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const r = await fetch('https://' + (await headers()).get('host') + '/x');\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-host-header"}},
		{"next: h = await headers() without next/headers is another headers() (a1 control)", "js", "CWE-918", "import { headers } from './util';\nexport async function GET() {\n  const h = await headers();\n  const r = await fetch('https://' + h.get('host') + '/x');\n  return Response.json(await r.json());\n}\n", nil},
		{"next: h = new Headers(), h.get('host') is no request (a1 control)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  const h = new Headers();\n  const r = await fetch('https://' + h.get('host') + '/x');\n  return Response.json(await r.json());\n}\n", nil},
		{"next: h = await headers(), h reassigned before the read (a1 control)", "js", "CWE-918", "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport async function GET() {\n  let h = await headers();\n  h = new Map([['host', 'a.example']]);\n  const r = await fetch('https://' + h.get('host') + '/x');\n  return Response.json(await r.json());\n}\n", nil},
		{"not a route: cache.get(k, (r) => ...)", "js", "CWE-918", "cache.get('k', async (r) => {\n  const x = await fetch('https://' + r.hostname + '/x');\n  return x.text();\n});\n", nil},
		{"(c) => c.host (Koa by another name)", "js", "CWE-918", route("c", "", "c.host"), []string{"js-ssrf-host-header"}},
		{"(c) => c.request.header.host", "js", "CWE-918", route("c", "", "c.request.header.host"), []string{"js-ssrf-host-header"}},
		{"(request, response) => request.headers.host", "js", "CWE-918", route("request, response", "", "request.headers.host"), []string{"js-ssrf-host-header"}},
		{"(c) => c.headers.host", "js", "CWE-918", route("c", "", "c.headers.host"), []string{"js-ssrf-host-header"}},
		{"(rq, rs) => rq.headers['x-forwarded-host']", "js", "CWE-918", route("rq, rs", "", "rq.headers['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"(r, s) => h = r.headers; h.host", "js", "CWE-918", route("r, s", "  const h = r.headers;\n", "h.host"), []string{"js-ssrf-host-header"}},
		{"(r, s) => r.headers.referer", "js", "CWE-918", route("r, s", "", "r.headers.referer"), []string{"js-ssrf-http-request"}},
		{"(r, s) => r.headers[name]", "js", "CWE-918", route("r, s", "  const name = r.query.h;\n", "r.headers[name]"), []string{"js-ssrf-http-request"}},
		{"(r, s) => r.query.u", "js", "CWE-918", route("r, s", "", "r.query.u"), []string{"js-ssrf-http-request"}},
		{"c.request.headers.host", "js", "CWE-918", route("c", "", "c.request.headers.host"), []string{"js-ssrf-host-header"}},
		{"express req.headers.host", "js", "CWE-918", express("req.headers.host"), []string{"js-ssrf-host-header"}},
		{"express req.get('host')", "js", "CWE-918", express("req.get('host')"), []string{"js-ssrf-host-header"}},
		{"express x-forwarded-host", "js", "CWE-918", express("req.headers['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"express referer", "js", "CWE-918", express("req.headers.referer"), []string{"js-ssrf-http-request"}},
		{"h = req.headers, h.host", "js", "CWE-918", alias("h.host"), []string{"js-ssrf-host-header"}},
		{"h = req.headers, h['host']", "js", "CWE-918", alias("h['host']"), []string{"js-ssrf-host-header"}},
		{"h = req.headers, h['x-forwarded-host']", "js", "CWE-918", alias("h['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"h = req.headers, h.referer", "js", "CWE-918", alias("h.referer"), []string{"js-ssrf-http-request"}},
		{"koa ctx.headers.host", "js", "CWE-918", koa("ctx.headers.host"), []string{"js-ssrf-host-header"}},
		{"koa ctx.headers['x-forwarded-host']", "js", "CWE-918", koa("ctx.headers['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"koa ctx.request.headers.host", "js", "CWE-918", koa("ctx.request.headers.host"), []string{"js-ssrf-host-header"}},
		{"koa ctx.headers.referer", "js", "CWE-918", koa("ctx.headers.referer"), []string{"js-ssrf-http-request"}},
		{"koa ctx.header.host", "js", "CWE-918", koa("ctx.header.host"), []string{"js-ssrf-host-header"}},
		{"koa ctx.header['x-forwarded-host']", "js", "CWE-918", koa("ctx.header['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"koa ctx.request.header.host", "js", "CWE-918", koa("ctx.request.header.host"), []string{"js-ssrf-host-header"}},
		{"koa ctx.header.referer", "js", "CWE-918", "router.get('/p', async (ctx) => {\n  const r = await fetch(ctx.header.referer);\n  ctx.body = await r.text();\n});\n", []string{"js-ssrf-http-request"}},
		{"koa ctx.request.get('referer')", "js", "CWE-918", "router.get('/p', async (ctx) => {\n  const r = await fetch(ctx.request.get('referer'));\n  ctx.body = await r.text();\n});\n", []string{"js-ssrf-http-request"}},
		{"koa ctx.request.get('host')", "js", "CWE-918", koa("ctx.request.get('host')"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h.host", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h.host"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['host']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['host']"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['x-forwarded-host']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['x-callback']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['x-callback']"), []string{"js-ssrf-http-request"}},
		{"nest @Req() r, r.headers.host", "ts", "CWE-918", nest("@Req() r: Request", "r.headers.host"), []string{"js-ssrf-host-header"}},
		{"nest @Req() r, r.headers['x-forwarded-host']", "ts", "CWE-918", nest("@Req() r: Request", "r.headers['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"nest @Req() req, req.headers.host", "ts", "CWE-918", nest("@Req() req: Request", "req.headers.host"), []string{"js-ssrf-host-header"}},
		{"nest @Request() r, r.headers.host", "ts", "CWE-918", nest("@Request() r: Request", "r.headers.host"), []string{"js-ssrf-host-header"}},
		{"nest @Req() r, r.headers.referer", "ts", "CWE-918", nest("@Req() r: Request", "r.headers.referer"), []string{"js-ssrf-http-request"}},
		{"nest @Req() r, r.headers['x-callback']", "ts", "CWE-918", nest("@Req() r: Request", "r.headers['x-callback']"), []string{"js-ssrf-http-request"}},
		{"nest @Req() r, r.query.u", "ts", "CWE-918", nest("@Req() r: Request", "r.query.u"), []string{"js-ssrf-http-request"}},
		{"nest @Req() r, r.query.host", "ts", "CWE-918", nest("@Req() r: Request", "r.query.host"), []string{"js-ssrf-http-request"}},
		{"nest @Req() r, alias h = r.headers, h.host", "ts", "CWE-918", "import { Controller, Get, Req } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  async p(@Req() r: Request) {\n    const h = r.headers;\n    const x = await fetch('https://' + h.host + '/x');\n    return x.json();\n  }\n}\n", []string{"js-ssrf-host-header"}},
		{"nest @Req() r, a header object's host", "ts", "CWE-918", nest("@Req() r: Request", "r.body.host"), []string{"js-ssrf-http-request"}},
		{"nest q = r, q.headers.host", "ts", "CWE-918", nestPre("    const q = r;\n", "q.headers.host"), []string{"js-ssrf-host-header"}},
		{"nest const { headers } = r, headers.host", "ts", "CWE-918", nestPre("    const { headers } = r;\n", "headers.host"), []string{"js-ssrf-host-header"}},
		{"nest r.hostname", "ts", "CWE-918", nest("@Req() r: Request", "r.hostname"), []string{"js-ssrf-host-header"}},
		{"nest r.get('host')", "ts", "CWE-918", nest("@Req() r: Request", "r.get('host')"), []string{"js-ssrf-host-header"}},
		{"nest r.header('host')", "ts", "CWE-918", nest("@Req() r: Request", "r.header('host')"), []string{"js-ssrf-host-header"}},
		{"nest r.headers['Host']", "ts", "CWE-918", nest("@Req() r: Request", "r.headers['Host']"), []string{"js-ssrf-host-header"}},
		{"nest r.headers['X-Forwarded-Host']", "ts", "CWE-918", nest("@Request() r: Request", "r.headers['X-Forwarded-Host']"), []string{"js-ssrf-host-header"}},
		{"nest r.get('x-callback-url') is any header", "ts", "CWE-918", "import { Controller, Get, Req } from '@nestjs/common';\n" + nestBodyCall("r.get('x-callback-url')"), []string{"js-ssrf-http-request"}},
		{"another library's @Req() r: r.headers.host as any request object's", "ts", "CWE-918", nestNoImport("@Req() r: Request", "r.headers.host"), []string{"js-ssrf-http-request"}},
		{"nest @Headers('host')", "ts", "CWE-918", nest("@Headers('host') host: string", "host"), []string{"js-ssrf-host-header"}},
		{"next headers().get('host')", "js", "CWE-918",
			"export async function GET() {\n  const r = await fetch('https://' + headers().get('host') + '/x');\n  return Response.json(await r.json());\n}\n", []string{"js-ssrf-host-header"}},
		{"httpx.Client(timeout=5).get", "python", "CWE-918", flask("httpx.Client(timeout=5).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx.AsyncClient(follow_redirects=True).get", "python", "CWE-918", flask("httpx.AsyncClient(follow_redirects=True).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx.Client(timeout=5).post", "python", "CWE-918", flask("httpx.Client(timeout=5).post(u)"), []string{"python-ssrf-async-client"}},
		{"httpx.Client(**kw).get", "python", "CWE-918", flask("httpx.Client(**kw).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx.Client(timeout=5).request", "python", "CWE-918", flask("httpx.Client(timeout=5).request('GET', u)"), []string{"python-ssrf-async-client"}},
		{"httpx.Client().get", "python", "CWE-918", flask("httpx.Client().get(u)"), []string{"python-ssrf-async-client"}},
		{"aiohttp.ClientSession(timeout=t).get", "python", "CWE-918", flask("aiohttp.ClientSession(timeout=t).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx.get", "python", "CWE-918", flask("httpx.get(u)"), []string{"python-ssrf-http-request"}},
		{"requests.Session().get", "python", "CWE-918", flask("requests.Session().get(u)"), []string{"python-ssrf-http-request"}},
		{"node: lodash escape", "js", "CWE-89", node("_.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: validator escape", "js", "CWE-89", node("validator.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: plain", "js", "CWE-89", node("q.id"), []string{"js-sqli-node-http-query"}},
		{"node: mysql.escape", "js", "CWE-89", node("mysql.escape(q.id)"), nil},
		{"node: connection.escape", "js", "CWE-89", node("connection.escape(q.id)"), nil},
		{"node: pool.escape", "js", "CWE-89", node("pool.escape(q.id)"), nil},
		{"destructured host is Host (reqalias.go)", "js", "CWE-918",
			"app.get('/p', async (req, res) => {\n  const { host } = req.headers;\n  const r = await fetch('https://' + host + '/x');\n  res.json(await r.json());\n});\n", []string{"js-ssrf-host-header"}},
		{"req.headers['Host'] is Host", "js", "CWE-918", express("req.headers['Host']"), []string{"js-ssrf-host-header"}},
		{"req.headers['X-Forwarded-Host'] is X-Forwarded-Host", "js", "CWE-918", express("req.headers['X-Forwarded-Host']"), []string{"js-ssrf-host-header"}},
		{"ctx.request.headers['Host'] is Host", "js", "CWE-918", koa("ctx.request.headers['Host']"), []string{"js-ssrf-host-header"}},
		{"another object's headers keep their case", "js", "CWE-918",
			"app.get('/p', async (req, res) => {\n  const o = { headers: {} };\n  o.headers['X-Url'] = req.query.u;\n  const r = await fetch(o.headers['x-url']);\n  res.json(await r.json());\n});\n", nil},
		{"another object's header read in its case", "js", "CWE-918",
			"app.get('/p', async (req, res) => {\n  const o = { headers: {} };\n  o.headers['X-Url'] = req.query.u;\n  const r = await fetch(o.headers['X-Url']);\n  res.json(await r.json());\n});\n", []string{"js-ssrf-http-request"}},
		{"httpx client over several lines", "python", "CWE-918", flask("httpx.Client(\n        timeout=5,\n    ).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx client with_options", "python", "CWE-918", flask("httpx.Client(timeout=5).with_options(timeout=9).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx client with *args", "python", "CWE-918", flask("httpx.Client(*opts).get(u)"), []string{"python-ssrf-async-client"}},
		{"httpx client, fixed host", "python", "CWE-918", flask("httpx.Client(timeout=5).get('https://api.example.org/x')"), nil},
		{"other.httpx is not httpx", "python", "CWE-918", flask("other.httpx.Client(timeout=5).get(u)"), nil},
		{"myhttpx is not httpx", "python", "CWE-918", flask("myhttpx.Client(timeout=5).get(u)"), nil},
		{"node: he.escape", "js", "CWE-89", node("he.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: querystring.escape", "js", "CWE-89", node("querystring.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: sequelize.escape", "js", "CWE-89", node("sequelize.escape(q.id)"), nil},
		{"node: SqlString.escape", "js", "CWE-89", node("SqlString.escape(q.id)"), nil},
		{"node: conn.escape", "js", "CWE-89", node("conn.escape(q.id)"), nil},
		{"node: this.connection.escape", "js", "CWE-89", node("this.connection.escape(q.id)"), nil},
		{"node: this.pool.escape", "js", "CWE-89", node("this.pool.escape(q.id)"), nil},
		{"node: this.conn.escape", "js", "CWE-89", node("this.conn.escape(q.id)"), nil},
		{"httpx client: .json().get(k) reads the answer (known over-report)", "python", "CWE-918", flask("httpx.Client(timeout=5).get('https://api.example.org/x').json().get(u)"), []string{"python-ssrf-async-client"}},
		{"node: db.escape is not a driver's", "js", "CWE-89", node("db.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: myconnection.escape is not connection's", "js", "CWE-89", node("myconnection.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"node: this.db.escape is not a driver's", "js", "CWE-89", node("this.db.escape(q.id)"), []string{"js-sqli-node-http-query"}},
		{"CodeIgniter $this->db->escape in $this->db->query", "php", "CWE-89",
			"<?php\nclass Items extends CI_Controller {\n    public function show() {\n        return $this->db->query(\"SELECT * FROM items WHERE id = \" . $this->db->escape($this->input->get('id')))->result();\n    }\n}\n", []string{"php-sqli-string-concat"}},
		{"Laravel ->orderBy($request->query(...))", "php", "CWE-89",
			"<?php\nclass ItemController extends Controller {\n    public function index(Request $request) {\n        return Item::query()->orderBy($request->query('sort'))->get();\n    }\n}\n", []string{"php-sqli-orderby-identifier"}},
		{"CodeIgniter 4 ->orderBy(", "php", "CWE-89",
			"<?php\nclass Items extends BaseController {\n    public function index() {\n        return $this->db->table('items')->orderBy($this->request->getGet('sort'))->get()->getResultArray();\n    }\n}\n", []string{"php-sqli-orderby-identifier"}},
		{"CodeIgniter 3 ->order_by(", "php", "CWE-89",
			"<?php\nclass Items extends CI_Controller {\n    public function index() {\n        return $this->db->from('items')->order_by($this->input->get('sort'))->get()->result_array();\n    }\n}\n", []string{"php-sqli-codeigniter-query"}},
		{"->orderBy($_GET)", "php", "CWE-89", "<?php\n$rows = $builder->orderBy($_GET['sort'])->get();\n", []string{"php-sqli-orderby-identifier"}},
	}
	ext := map[string]string{"js": "js", "ts": "ts", "python": "py", "php": "php"}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "a."+ext[c.lang], []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.CWE == c.cwe && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %s reported by %v, want %v", c.name, c.cwe, got, c.want)
		}
	}
}

// nestBody is a NestJS controller fetching v, after pre, in a handler taking param.
func nestBody(param, pre, v string) string {
	return "@Controller()\nexport class C {\n  @Get('p')\n  async p(" + param + ") {\n" + pre + "    const r = await fetch('https://' + " + v + " + '/x');\n    return r.json();\n  }\n}\n"
}

// nestBodyCall is a NestJS controller fetching the URL u names.
func nestBodyCall(u string) string {
	return "@Controller()\nexport class C {\n  @Get('p')\n  async p(@Req() r: Request) {\n    const x = await fetch(" + u + ");\n    return x.json();\n  }\n}\n"
}

// In a project, a file importing NestJS makes another file's @Req() its
// request, as when the controller takes the decorator from the project's own
// module (reqalias.go nestFile); a project without NestJS does not.
func TestNestProjectImport(t *testing.T) {
	e := engineForTest(t)
	ctl := "import { Req } from './decorators';\n" + nestBody("@Req() r: Request", "", "r.headers.host")
	for _, c := range []struct {
		name, main string
		want       string
	}{
		{"a file imports @nestjs/core", "import { NestFactory } from '@nestjs/core';\nexport async function boot() {}\n", "js-ssrf-host-header"},
		{"no file imports NestJS", "export async function boot() {}\n", "js-ssrf-http-request"},
	} {
		files := map[string]string{"main.ts": c.main, "ctl.ts": ctl, "decorators.ts": "export const Req = () => () => undefined;\n"}
		read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
		pr := e.NewProject([]string{"main.ts", "ctl.ts", "decorators.ts"}, read, ProjectOptions{})
		fs, err := pr.Scan("ctl.ts", []byte(ctl))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.CWE == "CWE-918" && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		if !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: reported by %v, want %s", c.name, got, c.want)
		}
	}
}
