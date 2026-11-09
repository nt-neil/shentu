package engine

import "testing"

// heldOutJSLane are held-out cases for the rules of the JavaScript rule lane
// (P1b), written apart from the rule samples: vulnerable code in other shapes,
// and safe code that looks close to it. A case with gap is a known miss.
var heldOutJSLane = []struct {
	name, rule, src string
	vulnerable      bool
	gap             string
}{
	// js-ssrf-host-header
	{"host header template", "js-ssrf-host-header", "app.post('/hook', async (req, res) => {\n  const url = `https://${req.get('host')}/api/notify`;\n  await got(url);\n  res.end();\n});\n", true, ""},
	{"hostname in https.get", "js-ssrf-host-header", "app.get('/x', (req, res) => {\n  https.get('https://' + req.hostname + '/health', (r) => r.pipe(res));\n});\n", true, ""},
	{"host header only logged", "js-ssrf-host-header", "app.get('/x', async (req, res) => {\n  console.log('host', req.get('host'));\n  const r = await fetch(CONFIG.apiBase + '/status');\n  res.json(await r.json());\n});\n", false, ""},
	// js-path-traversal-fs-ops
	{"rename to request name", "js-path-traversal-fs-ops", "app.post('/mv', (req, res) => {\n  const { from, to } = req.body;\n  fs.renameSync(path.join(DIR, from), path.join(DIR, to));\n  res.end();\n});\n", true, ""},
	{"append log by query", "js-path-traversal-fs-ops", "app.get('/note', (req, res) => {\n  fs.appendFile(`/var/app/notes/${req.query.book}.txt`, req.query.text + '\\n', () => res.end());\n});\n", true, ""},
	{"write stream to param", "js-path-traversal-fs-ops", "app.put('/up/:name', (req, res) => {\n  req.pipe(fs.createWriteStream(path.join(UP, req.params.name)));\n});\n", true, ""},
	{"mkdir from basename", "js-path-traversal-fs-ops", "app.post('/proj', (req, res) => {\n  const name = path.basename(String(req.body.name));\n  fs.mkdirSync(path.join(PROJECTS, name));\n  res.end();\n});\n", false, ""},
	{"rm fixed tmp", "js-path-traversal-fs-ops", "app.post('/clean', (req, res) => {\n  if (req.body.all === 'yes') fs.rmSync(TMP_DIR, { recursive: true, force: true });\n  res.end();\n});\n", false, ""},
	// js-path-traversal-exists-probe
	{"stat by query", "js-path-traversal-exists-probe", "app.get('/size', (req, res) => {\n  res.json({ size: fs.statSync(DATA + '/' + req.query.f).size });\n});\n", true, ""},
	{"access promise", "js-path-traversal-exists-probe", "app.head('/f/:n', async (req, res) => {\n  try { await fs.promises.access(path.join(ROOT, req.params.n)); res.sendStatus(200); } catch { res.sendStatus(404); }\n});\n", true, ""},
	{"exists of basename", "js-path-traversal-exists-probe", "app.get('/has', (req, res) => {\n  res.json(fs.existsSync(path.join(ROOT, path.basename(req.query.f))));\n});\n", false, ""},
	// js-cmdi-promisified-exec
	{"execAsync query", "js-cmdi-promisified-exec", "const execAsync = promisify(exec);\napp.get('/log', async (req, res) => {\n  const { stdout } = await execAsync('git log --oneline ' + req.query.branch);\n  res.send(stdout);\n});\n", true, ""},
	{"execAsync constant", "js-cmdi-promisified-exec", "const execAsync = promisify(exec);\napp.get('/log', async (req, res) => {\n  if (req.query.all === '1') console.log('all');\n  const { stdout } = await execAsync('git log --oneline -n 20');\n  res.type('text').send(stdout);\n});\n", false, ""},
	// js-sqli-node-http-query
	{"node http query template", "js-sqli-node-http-query", "http.createServer(async (req, res) => {\n  const { id } = url.parse(req.url, true).query;\n  const rows = await pool.query(`SELECT * FROM t WHERE id = ${id}`);\n  res.end(JSON.stringify(rows));\n});\n", true, ""},
	{"node http query bound", "js-sqli-node-http-query", "http.createServer(async (req, res) => {\n  const { id } = url.parse(req.url, true).query;\n  const rows = await pool.query('SELECT * FROM t WHERE id = ?', [id]);\n  res.end(JSON.stringify(rows));\n});\n", false, ""},
	// js-cmdi-spawn-sh-c
	{"bash -c concat", "js-cmdi-spawn-sh-c", "app.post('/run', (req, res) => {\n  const cmd = 'convert ' + req.body.file + ' out.png';\n  spawnSync('/bin/bash', ['-c', cmd]);\n  res.end();\n});\n", true, ""},
	{"sh -c fixed", "js-cmdi-spawn-sh-c", "app.post('/run', (req, res) => {\n  if (req.body.go === 'yes') spawnSync('sh', ['-c', 'make clean && make']);\n  res.end();\n});\n", false, ""},
	{"sh -c positional", "js-cmdi-spawn-sh-c", "app.get('/ping', (req, res) => {\n  execFile('sh', ['-c', 'ping -c 1 \"$1\"', 'ping', String(req.query.host)], (e, out) => res.send(out));\n});\n", false,
		"the input is a positional argument ($1) of a fixed command line, which is safe, but any tainted argument after -c is reported"},
	// Koa, Fastify and Hapi sources in the existing rules
	{"koa query eval", "js-code-eval-eval", "router.get('/calc', async (ctx) => {\n  ctx.body = { v: eval(ctx.query.expr) };\n});\n", true, ""},
	{"koa params readdir", "js-path-traversal-fs-ops", "router.get('/ls/:dir', async (ctx) => {\n  ctx.body = await fs.promises.readdir(path.join(ROOT, ctx.params.dir));\n});\n", true, ""},
	{"fastify params spawn shell", "js-cmdi-spawn-shell", "fastify.get('/build/:t', (request, reply) => {\n  spawn('make', [request.params.t], { shell: true });\n  reply.send('ok');\n});\n", true, ""},
	{"hapi payload yaml", "js-deserialization-yaml-load", "server.route({ method: 'POST', path: '/cfg', handler: (request) => yaml.load(request.payload, { schema: yaml.DEFAULT_FULL_SCHEMA }) });\n", true, ""},
	{"koa query compared", "js-code-eval-eval", "router.get('/m', async (ctx) => {\n  ctx.body = ctx.query.mode === 'raw' ? 'raw' : 'cooked';\n});\n", false, ""},
	{"koa throw guard", "js-sqli-object-input", "router.post('/login', async (ctx) => {\n  if (typeof ctx.request.body.email !== 'string') ctx.throw(400);\n  ctx.body = await knex('users').where({ email: ctx.request.body.email }).first();\n});\n", false, ""},
}

func TestHeldOutJSLane(t *testing.T) {
	e := engineForTest(t)
	pass := 0
	for _, c := range heldOutJSLane {
		fs, err := e.Scan("js", c.name, []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		found := false
		for _, f := range fs {
			found = found || f.RuleID == c.rule
		}
		// A safe case must be clean for every rule, a vulnerable one reported by its rule.
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
	t.Logf("JS lane held-out cases right: %d/%d", pass, len(heldOutJSLane))
}
