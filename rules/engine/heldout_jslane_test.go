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
	// batch 2: open redirect
	{"koa redirect query", "js-open-redirect-framework", "router.get('/back', async (ctx) => {\n  ctx.redirect(ctx.query.returnTo || '/');\n});\n", true, ""},
	{"hapi redirect payload", "js-open-redirect-framework", "server.route({ method: 'POST', path: '/out', handler: (request, h) => h.redirect(request.payload.url) });\n", true, ""},
	{"koa redirect fixed path", "js-open-redirect-framework", "router.get('/u/:name', async (ctx) => {\n  ctx.redirect('/users/' + encodeURIComponent(ctx.params.name));\n});\n", false, ""},
	{"location from query", "js-open-redirect-location-header", "app.get('/jump', (req, res) => {\n  res.set('Location', req.query.to);\n  res.sendStatus(302);\n});\n", true, ""},
	{"location fixed", "js-open-redirect-location-header", "app.get('/jump', (req, res) => {\n  if (req.query.lang === 'fr') res.setHeader('Location', '/fr/');\n  res.end();\n});\n", false, ""},
	{"host header koa", "js-open-redirect-host-header", "app.use(async (ctx, next) => {\n  if (ctx.protocol === 'http') return ctx.redirect(`https://${ctx.host}${ctx.url}`);\n  await next();\n});\n", true, ""},
	{"strict slash check", "js-open-redirect-redirect", "app.get('/next', (req, res) => {\n  const u = String(req.query.u);\n  if (!u.startsWith('/') || u.startsWith('//') || u.startsWith('/\\\\')) return res.redirect('/');\n  res.redirect(u);\n});\n", true, ""},
	// cases from the review of #26 (reviewjs_repro_test.go)
	{"review H-V1 double-quoted req.get('host')", "js-ssrf-host-header", "app.get('/t', async (req, res) => {\n  const r = await fetch(req.protocol + \"://\" + req.get(\"host\") + \"/internal/x\");\n  res.send(await r.text());\n});\n", true, ""},
	{"review H-V2 apostrophe shape (ternary + template)", "js-ssrf-host-header", "app.get('/f/*', async (req, res) => {\n  const u = await lookup(req.params[0]);\n  const proxyUrl = u.startsWith('/') ? `${req.protocol}://${req.get('host')}${u}` : u;\n  const r = await fetch(proxyUrl);\n  res.send(await r.text());\n});\n", true, ""},
	{"review H-V3 koa ctx.host", "js-ssrf-host-header", "router.get('/t', async (ctx) => {\n  const r = await fetch(`https://${ctx.host}/internal/x`);\n  ctx.body = await r.text();\n});\n", true, ""},
	{"review H-V4 fastify request.hostname", "js-ssrf-host-header", "fastify.get('/t', async (request, reply) => {\n  const r = await fetch('https://' + request.hostname + '/internal/x');\n  return r.text();\n});\n", true, ""},
	{"review H-V5 double-quoted x-forwarded-host key", "js-ssrf-host-header", "app.get('/t', async (req, res) => {\n  const r = await axios.get(\"https://\" + req.headers[\"x-forwarded-host\"] + \"/x\");\n  res.send(r.data);\n});\n", true, ""},
	{"review H-S1 host checked against allowlist", "js-ssrf-host-header", "const ALLOWED = new Set(['a.example.com', 'b.example.com']);\napp.get('/t', async (req, res) => {\n  const host = req.get('host');\n  if (!ALLOWED.has(host)) return res.sendStatus(400);\n  const r = await fetch(`https://${host}/status`);\n  res.send(await r.text());\n});\n", false, ""},
	{"review H-S2 host only forwarded as a header to a fixed URL", "js-ssrf-host-header", "app.get('/t', async (req, res) => {\n  const r = await fetch('https://api.example.com/v1/render', { headers: { 'X-Original-Host': req.get('host') } });\n  res.send(await r.text());\n});\n", false, ""},
	{"review H-S3 host in the query of a fixed URL", "js-ssrf-host-header", "app.get('/t', async (req, res) => {\n  const r = await fetch('https://api.example.com/tenant?host=' + encodeURIComponent(req.hostname));\n  res.json(await r.json());\n});\n", false, ""},
	{"review F-V1 fs.promises.unlink", "js-path-traversal-fs-ops", "app.post('/del', async (req, res) => {\n  await fs.promises.unlink(path.join(UP, req.body.name));\n  res.end();\n});\n", true, ""},
	{"review F-V2 fs/promises named import rm", "js-path-traversal-fs-ops", "import { rm } from 'fs/promises';\napp.post('/del', async (req, res) => {\n  await rm(path.join(UP, req.body.dir), { recursive: true });\n  res.end();\n});\n", true, ""},
	{"review F-V3 fsp = require('fs/promises')", "js-path-traversal-fs-ops", "const fsp = require('fs/promises');\napp.post('/mk', async (req, res) => {\n  await fsp.mkdir(path.join(UP, req.body.dir), { recursive: true });\n  res.end();\n});\n", true, ""},
	{"review F-V4 fs.promises.appendFile", "js-path-traversal-fs-ops", "app.post('/log', async (req, res) => {\n  await fs.promises.appendFile(path.join(LOGS, req.body.book), req.body.text);\n  res.end();\n});\n", true, ""},
	{"review F-V5 fs.cpSync", "js-path-traversal-fs-ops", "app.post('/cp', (req, res) => {\n  fs.cpSync(path.join(TPL, 'base'), path.join(PROJ, req.body.name), { recursive: true });\n  res.end();\n});\n", true, ""},
	{"review F-V6 startsWith on the raw input is not a boundary check", "js-path-traversal-fs-ops", "app.post('/rm', (req, res) => {\n  if (req.body.dir.startsWith('.')) return res.sendStatus(400);\n  fs.rmSync(path.join(UP, req.body.dir), { recursive: true, force: true });\n  res.end();\n});\n", true, ""},
	{"review F-V7 basename on a different part of the path", "js-path-traversal-fs-ops", "app.post('/rm', (req, res) => {\n  fs.rmSync(path.join(UP, req.body.dir, path.basename(req.body.file)));\n  res.end();\n});\n", true, ""},
	{"review F-S1 content (not path) from the request", "js-path-traversal-fs-ops", "app.post('/save', (req, res) => {\n  fs.writeFileSync(path.join(DIR, 'state.json'), JSON.stringify(req.body));\n  res.end();\n});\n", false, ""},
	{"review F-S2 numeric id", "js-path-traversal-fs-ops", "app.post('/mk/:id', (req, res) => {\n  const id = parseInt(req.params.id, 10);\n  fs.mkdirSync(path.join(DIR, String(id)), { recursive: true });\n  res.end();\n});\n", false, ""},
	{"review F-S3 rename to basename", "js-path-traversal-fs-ops", "app.post('/up', (req, res) => {\n  fs.renameSync(TMP_FILE, path.join(UP, path.basename(req.body.name)));\n  res.end();\n});\n", false, ""},
	{"review E-V1 fs.promises.lstat", "js-path-traversal-exists-probe", "app.get('/has', async (req, res) => {\n  try { await fs.promises.lstat(path.join(ROOT, req.query.f)); res.sendStatus(200); } catch { res.sendStatus(404); }\n});\n", true, ""},
	{"review E-V2 named import stat from fs/promises", "js-path-traversal-exists-probe", "import { stat } from 'fs/promises';\napp.get('/has', async (req, res) => {\n  try { await stat(path.join(ROOT, req.query.f)); res.sendStatus(200); } catch { res.sendStatus(404); }\n});\n", true, ""},
	{"review E-V3 koa ctx.params existsSync", "js-path-traversal-exists-probe", "router.get('/has/:f', async (ctx) => {\n  ctx.body = fs.existsSync(path.join(ROOT, ctx.params.f));\n});\n", true, ""},
	{"review E-S1 resolved and checked", "js-path-traversal-exists-probe", "const BASE = path.resolve(ROOT) + path.sep;\napp.get('/has', (req, res) => {\n  const p = path.resolve(BASE, String(req.query.f));\n  if (!p.startsWith(BASE)) return res.sendStatus(400);\n  res.json(fs.existsSync(p));\n});\n", false, ""},
	{"review E-S2 hashed name", "js-path-traversal-exists-probe", "app.get('/cached', (req, res) => {\n  const key = crypto.createHash('sha256').update(String(req.query.u)).digest('hex');\n  res.json(fs.existsSync(path.join(CACHE, key)));\n});\n", false, ""},
	{"review P-V1 promisified exec under another name", "js-cmdi-promisified-exec", "const run = util.promisify(require('child_process').exec);\napp.get('/ls', async (req, res) => {\n  const { stdout } = await run('ls ' + req.query.dir);\n  res.send(stdout);\n});\n", true, "a promisified exec kept under another name (const run = promisify(...)) is not followed"},
	{"review P-V2 koa ctx.query", "js-cmdi-promisified-exec", "const execAsync = promisify(exec);\nrouter.get('/ping', async (ctx) => {\n  ctx.body = (await execAsync('ping -c 1 ' + ctx.query.host)).stdout;\n});\n", true, ""},
	{"review P-V3 fastify request.headers", "js-cmdi-promisified-exec", "const execAsync = promisify(exec);\nfastify.get('/ping', async (request) => {\n  return (await execAsync('ping -c 1 ' + request.headers['x-target'])).stdout;\n});\n", true, ""},
	{"review P-S1 numeric value", "js-cmdi-promisified-exec", "const execAsync = promisify(exec);\napp.get('/log', async (req, res) => {\n  const n = parseInt(req.query.n, 10);\n  res.send((await execAsync('git log -n ' + n)).stdout);\n});\n", false, ""},
	{"review P-S2 execFile array", "js-cmdi-promisified-exec", "const execFileAsync = promisify(execFile);\napp.get('/log', async (req, res) => {\n  res.send((await execFileAsync('git', ['log', '--', String(req.query.f)])).stdout);\n});\n", false, ""},
	{"review S-V1 cmd.exe /C uppercase", "js-cmdi-spawn-sh-c", "app.get('/p', (req, res) => {\n  spawn('cmd.exe', ['/C', 'ping ' + req.query.host]);\n  res.end();\n});\n", true, ""},
	{"review S-V2 bash -ec", "js-cmdi-spawn-sh-c", "app.get('/p', (req, res) => {\n  spawn('bash', ['-ec', 'ping -c 1 ' + req.query.host]);\n  res.end();\n});\n", true, ""},
	{"review S-V3 argument list in a variable", "js-cmdi-spawn-sh-c", "app.get('/p', (req, res) => {\n  const args = ['-c', 'ping -c 1 ' + req.query.host];\n  spawn('sh', args);\n  res.end();\n});\n", true, "the argument list kept in a variable is not looked into for -c"},
	{"review S-V4 child_process.spawn double quotes", "js-cmdi-spawn-sh-c", "app.get('/p', (req, res) => {\n  child_process.spawn(\"/bin/sh\", [\"-c\", `ping -c 1 ${req.query.host}`]);\n  res.end();\n});\n", true, ""},
	{"review S-S1 git -c config option", "js-cmdi-spawn-sh-c", "app.get('/log', (req, res) => {\n  execFile('git', ['-c', 'core.quotepath=off', 'log', '--', String(req.query.path)], (e, out) => res.send(out));\n});\n", false, ""},
	{"review S-S2 grep -c count", "js-cmdi-spawn-sh-c", "app.get('/count', (req, res) => {\n  execFile('grep', ['-c', '--', String(req.query.word), 'words.txt'], (e, out) => res.send(out));\n});\n", false, ""},
	{"review S-S3 wc -c of a request file", "js-cmdi-spawn-sh-c", "app.get('/size', (req, res) => {\n  const p = spawnSync('wc', ['-c', path.join(DIR, path.basename(req.query.f))]);\n  res.send(p.stdout);\n});\n", false, ""},
	{"review Q-V1 WHATWG URL searchParams", "js-sqli-node-http-query", "http.createServer(async (req, res) => {\n  const id = new URL(req.url, 'http://localhost').searchParams.get('id');\n  const rows = await pool.query('SELECT * FROM t WHERE id = ' + id);\n  res.end(JSON.stringify(rows));\n});\n", true, ""},
	{"review Q-V2 querystring.parse of the URL query", "js-sqli-node-http-query", "http.createServer(async (req, res) => {\n  const q = querystring.parse(req.url.split('?')[1]);\n  const rows = await pool.query(`SELECT * FROM t WHERE name = '${q.name}'`);\n  res.end(JSON.stringify(rows));\n});\n", true, ""},
	{"review Q-S1 querystring.parse of a config file", "js-sqli-node-http-query", "const cfg = querystring.parse(fs.readFileSync('db.conf', 'utf8'));\nasync function init() {\n  await pool.query('CREATE TABLE IF NOT EXISTS ' + cfg.table + ' (id int)');\n}\n", false, ""},
	{"review Q-S2 parseInt", "js-sqli-node-http-query", "http.createServer(async (req, res) => {\n  const q = url.parse(req.url, true).query;\n  const rows = await pool.query('SELECT * FROM t WHERE id = ' + parseInt(q.id, 10));\n  res.end(JSON.stringify(rows));\n});\n", false, ""},
	{"review K-S1 fastify schema-less request.headers SSRF (header source missing)", "js-ssrf-http-request", "fastify.get('/p', async (request) => {\n  const r = await fetch(request.headers['x-target']);\n  return r.text();\n});\n", true, ""},
	{"review K-S3 hapi exec with request.headers (header source missing)", "js-cmdi-exec", "server.route({ method: 'GET', path: '/t', handler: (request) => execSync('traceroute ' + request.headers['x-target']).toString() });\n", true, ""},
	{"review K-S5 koa ctx.request.header (alias of ctx.headers)", "js-ssrf-http-request", "router.get('/p', async (ctx) => {\n  const r = await fetch(ctx.request.header['x-target']);\n  ctx.body = await r.text();\n});\n", true, ""},
	// cases from the review of #29 (reviewjs_repro_test.go)
	{"review R-V1 '/' alone is not a fixed prefix (koa)", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.redirect('/' + ctx.query.p);\n});\n", true, ""},
	{"review R-V2 host without trailing slash (koa)", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.redirect('https://example.com' + ctx.query.p);\n});\n", true, ""},
	{"review R-V3 fastify v4 reply.redirect(code, url)", "js-open-redirect-framework", "fastify.get('/go', (request, reply) => {\n  reply.redirect(302, request.query.to);\n});\n", true, ""},
	{"review R-V4 fastify v5 reply.redirect(url, code)", "js-open-redirect-framework", "fastify.get('/go', (request, reply) => {\n  reply.redirect(request.query.to, 302);\n});\n", true, ""},
	{"review R-V5 encodeURIComponent only after the input", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.redirect(ctx.query.next + '?ref=' + encodeURIComponent(ctx.query.ref));\n});\n", true, ""},
	{"review R-V6 koa ctx.response.redirect", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.response.redirect(ctx.query.next);\n});\n", true, ""},
	{"review R-V7 hapi h.redirect(...).permanent()", "js-open-redirect-framework", "server.route({ method: 'GET', path: '/go', handler: (request, h) => h.redirect(request.query.next).permanent() });\n", true, ""},
	{"review R-V8 koa template literal", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.redirect(`${ctx.request.body.returnTo}`);\n});\n", true, ""},
	{"review R-S1 host with trailing slash", "js-open-redirect-framework", "router.get('/go', async (ctx) => {\n  ctx.redirect('https://example.com/' + ctx.query.p);\n});\n", false, ""},
	{"review R-S2 allowlist with early return", "js-open-redirect-framework", "const OK = ['/', '/orders'];\nrouter.get('/go', async (ctx) => {\n  if (!OK.includes(ctx.query.next)) return ctx.redirect('/');\n  ctx.redirect(ctx.query.next);\n});\n", false, ""},
	{"review R-S3 login?next= original URL", "js-open-redirect-framework", "app.use(async (ctx, next) => {\n  if (!ctx.state.user) return ctx.redirect('/login?next=' + encodeURIComponent(ctx.originalUrl));\n  await next();\n});\n", false, ""},
	{"review R-S4 fastify fixed path + encoded value", "js-open-redirect-framework", "fastify.get('/u/:id', (request, reply) => {\n  reply.redirect('/users/' + encodeURIComponent(request.params.id));\n});\n", false, ""},
	{"review O-V1 CVE-2026-25651 own code req.header('host')", "js-open-redirect-host-header", "module.exports = function (req, res, next) {\n  if (!req.secure && req.header('x-forwarded-proto') != 'https') {\n    return res.redirect('https://' + req.header('host') + req.url);\n  }\n  next();\n};\n", true, ""},
	{"review O-V2 double-quoted req.get('host')", "js-open-redirect-host-header", "app.use((req, res, next) => {\n  if (!req.secure) return res.redirect(\"https://\" + req.get(\"host\") + req.originalUrl);\n  next();\n});\n", true, ""},
	{"review O-V3 template with req.headers.host", "js-open-redirect-host-header", "app.use((req, res, next) => {\n  if (!req.secure) return res.redirect(301, `https://${req.headers.host}${req.url}`);\n  next();\n});\n", true, ""},
	{"review O-V4 fastify request.hostname", "js-open-redirect-host-header", "fastify.addHook('onRequest', (request, reply, done) => {\n  if (request.protocol === 'http') return reply.redirect('https://' + request.hostname + request.url);\n  done();\n});\n", true, ""},
	{"review O-V5 writeHead Location", "js-open-redirect-host-header", "http.createServer((req, res) => {\n  res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });\n  res.end();\n}).listen(80);\n", true, "res.writeHead(code, { Location }) is not a sink yet: a fixed prefix inside an object literal is not judged"},
	{"review O-V6 koa ctx.get('host')", "js-open-redirect-host-header", "app.use(async (ctx, next) => {\n  if (!ctx.secure) return ctx.redirect('https://' + ctx.get('host') + ctx.url);\n  await next();\n});\n", true, ""},
	{"review O-S1 host checked against allowlist", "js-open-redirect-host-header", "const HOSTS = new Set(['example.com', 'www.example.com']);\napp.use((req, res, next) => {\n  if (!HOSTS.has(req.hostname)) return res.sendStatus(400);\n  if (!req.secure) return res.redirect('https://' + req.hostname + req.originalUrl);\n  next();\n});\n", false, ""},
	{"review L-V1 double-quoted Location", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.setHeader(\"Location\", req.query.to);\n  res.sendStatus(302);\n});\n", true, ""},
	{"review L-V2 res.set({ Location })", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.set({ Location: req.query.to });\n  res.sendStatus(302);\n});\n", true, "res.set({ Location }) is not a sink yet: a fixed prefix inside an object literal is not judged"},
	{"review L-V3 koa ctx.set('Location')", "js-open-redirect-location-header", "router.get('/j', async (ctx) => {\n  ctx.status = 302;\n  ctx.set('Location', ctx.query.to);\n});\n", true, ""},
	{"review L-V4 fastify reply.header('Location')", "js-open-redirect-location-header", "fastify.get('/j', (request, reply) => {\n  reply.code(302).header('Location', request.query.to).send();\n});\n", true, ""},
	{"review L-V5 '/' alone is not a fixed prefix", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.setHeader('Location', '/' + req.query.p);\n  res.sendStatus(302);\n});\n", true, ""},
	{"review L-V6 host without trailing slash", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.setHeader('Location', 'https://example.com' + req.query.p);\n  res.sendStatus(302);\n});\n", true, ""},
	{"review L-S1 host with trailing slash", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.setHeader('Location', 'https://example.com/' + req.query.p);\n  res.sendStatus(302);\n});\n", false, ""},
	{"review L-S2 Content-Location header", "js-open-redirect-location-header", "app.get('/j', (req, res) => {\n  res.setHeader('Content-Location', req.url);\n  res.end();\n});\n", false, ""},
	{"review L-S3 canonical host constant then req.url", "js-open-redirect-location-header", "const CANON = 'www.example.com';\nhttp.createServer((req, res) => {\n  res.statusCode = 301;\n  res.setHeader('Location', 'https://' + CANON + req.url);\n  res.end();\n});\n", false, "'https://' + a constant host is a fixed origin, but the strict prefix rule does not count a literal with a scheme"},
	{"review L-S4 allowlist", "js-open-redirect-location-header", "const OK = new Set(['/', '/docs']);\napp.get('/j', (req, res) => {\n  if (!OK.has(req.query.to)) return res.sendStatus(400);\n  res.setHeader('Location', req.query.to);\n  res.sendStatus(302);\n});\n", false, ""},
	{"review C-5 CVE-2021-23387 shape (u.parse alias)", "js-open-redirect-location-header", "var u = require('url');\nmodule.exports = function () {\n  return function (req, res, next) {\n    var url = u.parse(req.url);\n    url.pathname = url.pathname.slice(0, -1);\n    res.statusCode = 302;\n    res.setHeader('Location', u.format(url));\n    res.end();\n  };\n};\n", true, ""},
	{"review C-6 CVE-2021-23384 shape (helper function)", "js-open-redirect-framework", "function getPath(original, qs) { return qs.length ? original.slice(0, -qs.length - 1) : original; }\nmodule.exports = () => async function (ctx, next) {\n  let p = getPath(ctx.originalUrl, ctx.querystring);\n  if (p !== '/' && p.slice(-1) === '/') {\n    p = p.slice(0, -1);\n    ctx.status = 301;\n    ctx.redirect(p + (ctx.querystring ? '?' + ctx.querystring : ''));\n  }\n};\n", true, ""},
	{"review C-7 CVE-2018-3743 shape (koa v1 this)", "js-open-redirect-framework", "app.use(function* () {\n  if (exists(file + '.html')) {\n    this.status = 307;\n    this.redirect(this.request.url + '/' + query);\n  }\n});\n", true, ""},
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
