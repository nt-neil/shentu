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
		return "@Controller()\nexport class C {\n  @Get('p')\n  async p(" + param + ") {\n    const r = await fetch('https://' + " + v + " + '/x');\n    return r.json();\n  }\n}\n"
	}
	flask := func(call string) string {
		return "import httpx\n\n@app.route('/f')\ndef f():\n    u = request.args.get('u')\n    return " + call + ".text\n"
	}
	node := func(v string) string {
		return "http.createServer((req, res) => {\n  const q = url.parse(req.url, true).query;\n  connection.query('SELECT * FROM t WHERE id = ' + " + v + ", (e, r) => res.end(JSON.stringify(r)));\n}).listen(8080);\n"
	}
	cases := []struct {
		name, lang, cwe, src string
		want                 []string
	}{
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
		{"nest @Headers() h, h.host", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h.host"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['host']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['host']"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['x-forwarded-host']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['x-forwarded-host']"), []string{"js-ssrf-host-header"}},
		{"nest @Headers() h, h['x-callback']", "ts", "CWE-918", nest("@Headers() h: Record<string, string>", "h['x-callback']"), []string{"js-ssrf-http-request"}},
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
		{"destructured host goes to http-request", "js", "CWE-918",
			"app.get('/p', async (req, res) => {\n  const { host } = req.headers;\n  const r = await fetch('https://' + host + '/x');\n  res.json(await r.json());\n});\n", []string{"js-ssrf-http-request"}},
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
