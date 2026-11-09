package engine

import "testing"

// TestHeldOut runs cases written apart from the rule samples, so the engine is not
// only tuned to them: vulnerable code written differently from any sample, and
// safe code that looks risky (a source only compared or logged, a sink with
// constant arguments). A case marked gap is a known miss: it is logged, not
// failed, and listed in the engine's known limits.
func TestHeldOut(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, src string
		vulnerable      bool
		gap             string
	}{
		// Vulnerable, written differently from the samples.
		{"php two assignments", "php", "<?php\n$a = $_GET['q'];\n$b = $a;\n$c = \"SELECT * FROM t WHERE x = '\" . $b . \"'\";\nmysqli_query($db, $c);\n", true, ""},
		{"php sprintf", "php", "<?php\n$sql = sprintf('DELETE FROM t WHERE id = %s', $_POST['id']);\n$pdo->query($sql);\n", true, ""},
		{"php .= query", "php", "<?php\n$sql = 'SELECT * FROM t';\n$sql .= \" WHERE n = '\" . $_REQUEST['n'] . \"'\";\nmysqli_query($db, $sql);\n", true, ""},
		{"php heredoc", "php", "<?php\n$q = $_GET['q'];\n$sql = <<<SQL\n  SELECT * FROM t WHERE a = '$q'\n  SQL;\n$pdo->query($sql);\n", true, ""},
		{"python format", "python", "@app.get('/ping')\ndef ping():\n    cmd = 'ping -c 1 {}'.format(request.args['host'])\n    os.system(cmd)\n    return 'ok'\n", true, ""},
		{"python dict hop", "python", "def dl(request):\n    params = request.GET\n    name = params['file']\n    return FileResponse(open(os.path.join('/srv', name), 'rb'))\n", true, ""},
		{"python try", "python", "@app.post('/calc')\ndef calc():\n    try:\n        expr = request.json['e']\n    except KeyError:\n        abort(400)\n    return str(eval(expr))\n", true, ""},
		{"js array join", "js", "app.get('/ls', (req, res) => {\n  const parts = ['ls', req.query.dir];\n  exec(parts.join(' '), () => res.end());\n});\n", true, ""},
		{"js destructuring", "js", "app.get('/f', (req, res) => {\n  const { file } = req.query;\n  res.sendFile(path.join(__dirname, 'files', file));\n});\n", true, ""},
		{"js +=", "js", "app.post('/q', async (req, res) => {\n  let sql = \"SELECT * FROM t WHERE a = '\";\n  sql += req.body.a + \"'\";\n  res.json(await pool.query(sql));\n});\n", true, ""},
		// Safe, but easy to report by mistake.
		{"php compared and logged", "php", "<?php\nif ($_GET['mode'] === 'csv') {\n    $rows = $pdo->query('SELECT * FROM t');\n}\nerror_log('mode ' . $_GET['mode']);\n", false, ""},
		{"php constant sink", "php", "<?php\n$name = $_GET['n'];\n$up = shell_exec('uptime');\necho htmlspecialchars($name) . $up;\n", false, ""},
		{"python logged only", "python", "@app.get('/s')\ndef s():\n    if request.args.get('debug') == '1':\n        log.info('debug %s', request.args['debug'])\n    cur.execute('SELECT 1')\n    return 'ok'\n", false, ""},
		{"python dict allowlist", "python", "@app.get('/s')\ndef s():\n    col = {'a': 'a', 'b': 'b'}.get(request.args['c'], 'a')\n    cur.execute(f'SELECT {col} FROM t')\n    return 'ok'\n", false,
			"a lookup in a constant dict ({...}.get(input, default)) is not recognised as an allowlist; the result stays tainted"},
		{"js condition only", "js", "app.get('/u', (req, res) => {\n  if (req.query.verbose === '1') console.log('verbose');\n  res.send(execSync('uptime').toString());\n});\n", false, ""},
		{"js parseInt", "js", "app.get('/i/:id', async (req, res) => {\n  const id = parseInt(req.params.id, 10);\n  res.json(await pool.query('SELECT * FROM t WHERE id = ' + id));\n});\n", false, ""},
		{"js ternary constants", "js", "app.get('/o', async (req, res) => {\n  const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC';\n  res.json(await knex.raw(`SELECT * FROM t ORDER BY id ${dir}`));\n});\n", false, ""},
		// Cases from the independent review of 24d77cd.
		{"L1 laravel DB::select concat", "php", "<?php\nclass C { public function show(Request $request) {\n  $id = $request->input('id');\n  return DB::select(\"SELECT * FROM users WHERE id = $id\");\n} }\n", true, "the rule has no DB::select sink (left to the weekly rule evolution)"},
		{"L2 laravel whereRaw", "php", "<?php\nclass C { public function idx(Request $request) {\n  $q = $request->input('q');\n  return User::whereRaw(\"name LIKE '%$q%'\")->get();\n} }\n", true, "no PHP rule has a whereRaw sink (left to the weekly rule evolution)"},
		{"L3 laravel orderBy allowlisted", "php", "<?php\nclass C { public function idx(Request $request) {\n  $sort = $request->input('sort');\n  if (!in_array($sort, ['name','email'], true)) { $sort = 'name'; }\n  return User::orderBy($sort)->get();\n} }\n", false, ""},
		{"W1 wp get_results interp", "php", "<?php\nfunction my_ajax() { global $wpdb;\n  $s = $_POST['s'];\n  $rows = $wpdb->get_results(\"SELECT * FROM {$wpdb->posts} WHERE post_title = '$s'\");\n}\n", true, ""},
		{"W2 wp prepare safe", "php", "<?php\nfunction my_ajax() { global $wpdb;\n  $s = sanitize_text_field($_POST['s']);\n  $rows = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM t WHERE a = %s\", $s));\n}\n", false, ""},
		{"W3 wp sanitizer on other var", "php", "<?php\nfunction f() { global $wpdb;\n  $id = $_GET['id']; $n = absint($_GET['n']);\n  $wpdb->query(\"DELETE FROM t WHERE id = $id LIMIT $n\");\n}\n", true, ""},
		{"P1 reassign kill", "php", "<?php\n$c = $_GET['c'];\n$c = 'ls';\nsystem($c);\n", false, ""},
		{"P2 reassign in branch only", "php", "<?php\n$c = $_GET['c'];\nif ($x) { $c = 'ls'; }\nsystem($c);\n", true, ""},
		{"P3 partial sanitizer", "php", "<?php\n$cmd = escapeshellarg($_GET['a']) . ' ' . $_GET['b'];\nexec('tar ' . $cmd);\n", true, ""},
		{"P4 sanitizer full", "php", "<?php\n$f = escapeshellarg($_GET['f']);\nexec(\"cat $f\");\n", false, ""},
		{"P5 loop accumulate", "php", "<?php\n$w = '';\nforeach ($_POST['ids'] as $id) { $w .= \"$id,\"; }\n$pdo->query(\"SELECT * FROM t WHERE id IN ($w 0)\");\n", true, ""},
		{"P6 closure use", "php", "<?php\n$q = $_GET['q'];\n$f = function() use ($q) { return mysqli_query($db, \"SELECT '$q'\"); };\n", true, ""},
		{"P7 interp array key", "php", "<?php\n$sql = \"SELECT * FROM t WHERE a = '{$_GET['a']}'\";\nmysqli_query($db, $sql);\n", true, ""},
		{"P8 interp ${}", "php", "<?php\n$a = $_GET['a'];\nmysqli_query($db, \"SELECT '${a}'\");\n", true, ""},
		{"P9 unserialize cookie", "php", "<?php\n$prefs = unserialize($_COOKIE['prefs']);\n", true, ""},
		{"P10 intval then use", "php", "<?php\n$id = intval($_GET['id']);\nmysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n", false, ""},
		{"P11 include lang", "php", "<?php\n$lang = $_GET['lang'];\ninclude __DIR__ . '/lang/' . $lang . '.php';\n", true, ""},
		{"P12 str_starts_with no sep", "php", "<?php\n$p = realpath('/var/www/data/' . $_GET['f']);\nif (str_starts_with($p, '/var/www/data')) { readfile($p); }\n", true, ""},
		{"P13 sanitizer in comment-like string", "php", "<?php\n$x = $_GET['x']; // intval($x)\nsystem($x);\n", true, ""},
		{"P14 list() destructure", "php", "<?php\n[$a, $b] = [$_GET['a'], 'x'];\nsystem($a);\n", true, ""},
		{"P15 compact array then sink", "php", "<?php\n$args = ['cmd' => $_GET['c']];\nsystem($args['cmd']);\n", true, ""},
		{"F1 flask f-string execute", "python", "@app.route('/u')\ndef u():\n    name = request.args.get('name')\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n", true, ""},
		{"F2 flask param safe", "python", "@app.route('/u')\ndef u():\n    name = request.args.get('name')\n    cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))\n", false, ""},
		{"F3 % formatting", "python", "@app.route('/u')\ndef u():\n    q = \"SELECT * FROM t WHERE id = %s\" % request.args['id']\n    db.engine.execute(q)\n", true, ""},
		{"F4 subprocess shell", "python", "@app.route('/p')\ndef p():\n    host = request.form['host']\n    subprocess.check_output('ping -c1 ' + host, shell=True)\n", true, ""},
		{"F5 subprocess list safe", "python", "@app.route('/p')\ndef p():\n    host = request.form['host']\n    subprocess.check_output(['ping', '-c1', '--', host])\n", false, ""},
		{"F6 jinja from_string", "python", "@app.route('/t')\ndef t():\n    tpl = request.args.get('t', '')\n    return env.from_string(tpl).render()\n", true, ""},
		{"F7 send_file join", "python", "@app.route('/d')\ndef d():\n    fn = request.args['f']\n    return send_file(os.path.join(UPLOAD, fn))\n", true, ""},
		{"F8 send_from_directory safe", "python", "@app.route('/d')\ndef d():\n    return send_from_directory(UPLOAD, request.args['f'])\n", false, ""},
		{"D1 django raw", "python", "def view(request):\n    q = request.GET.get('q')\n    return Item.objects.raw(\"SELECT * FROM item WHERE name = '%s'\" % q)\n", true, "no rule has an objects.raw sink (left to the weekly rule evolution)"},
		{"D2 django cursor", "python", "def view(request):\n    q = request.GET['q']\n    with connection.cursor() as c:\n        c.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n", true, ""},
		{"D3 yaml load default", "python", "def view(request):\n    data = yaml.load(request.body)\n", true, ""},
		{"D4 yaml SafeLoader positional", "python", "def view(request):\n    data = yaml.load(request.body, yaml.SafeLoader)\n", false, ""},
		{"D5 pickle b64", "python", "def view(request):\n    obj = pickle.loads(base64.b64decode(request.COOKIES['s']))\n", true, ""},
		{"Y1 py reassign kill", "python", "def v():\n    c = request.args['c']\n    c = 'ls'\n    os.system(c)\n", false, ""},
		{"Y2 py loop var", "python", "def v():\n    for n in request.args.getlist('n'):\n        os.system('echo ' + n)\n", true, ""},
		{"Y3 py partial quote", "python", "def v():\n    os.system('cp ' + shlex.quote(request.args['a']) + ' ' + request.args['b'])\n", true, ""},
		{"Y4 py quote other var", "python", "def v():\n    a = request.args['a']\n    b = shlex.quote(a)\n    os.system('cat ' + a)\n", true, ""},
		{"Y5 py nested def closure", "python", "def v():\n    c = request.args['c']\n    def run():\n        os.system(c)\n    run()\n", true, ""},
		{"Y6 py fstring format spec", "python", "def v():\n    c = request.args['c']\n    os.system(f'echo {c!r:>10}')\n", true, ""},
		{"Y7 py tarfile receiver", "python", "def v():\n    tf = tarfile.open(fileobj=request.files['a'])\n    tf.extractall('/tmp/x')\n", true, ""},
		{"Y8 py from import run", "python", "from subprocess import run\ndef v():\n    run(request.args['c'], shell=True)\n", true, ""},
		{"E1 exec template", "js", "app.get('/x', (req, res) => {\n  exec(`convert ${req.query.f} out.png`);\n});\n", true, ""},
		{"E2 child_process.exec", "js", "const cp = require('child_process');\napp.get('/x', (req, res) => { cp.exec('ls ' + req.query.d); });\n", true, ""},
		{"E3 mysql param safe", "js", "app.get('/u', (req, res) => {\n  db.query('SELECT * FROM u WHERE id = ?', [req.query.id], cb);\n});\n", false, ""},
		{"E4 knex raw interp", "js", "router.get('/u', async (req, res) => {\n  const { name } = req.body;\n  await knex.raw(`SELECT * FROM u WHERE name = '${name}'`);\n});\n", true, ""},
		{"E5 readFile promises", "js", "app.get('/f', async (req, res) => {\n  const data = await fs.promises.readFile(path.join(ROOT, req.query.f));\n  res.send(data);\n});\n", true, "the rule has no fs.promises.readFile sink (left to the weekly rule evolution)"},
		{"E6 sendFile root safe", "js", "app.get('/f', (req, res) => { res.sendFile(req.params.name, { root: PUBLIC }); });\n", false, ""},
		{"E7 js reassign kill", "js", "app.get('/x', (req, res) => {\n  let c = req.query.c;\n  c = 'ls';\n  exec(c);\n});\n", false, ""},
		{"E8 js if-branch partial kill", "js", "app.get('/x', (req, res) => {\n  let c = req.query.c;\n  if (a) { c = 'ls'; }\n  exec(c);\n});\n", true, ""},
		{"E9 js eval Function", "js", "app.post('/calc', (req, res) => {\n  const fn = new Function('return ' + req.body.expr);\n  res.json(fn());\n});\n", true, ""},
		{"E10 parseInt other var", "js", "app.get('/u', (req, res) => {\n  const id = req.query.id; const n = parseInt(id);\n  pool.query('SELECT * FROM t WHERE id = ' + id);\n});\n", true, ""},
		{"E11 template nested tpl", "js", "app.get('/u', (req, res) => {\n  pool.query(`SELECT * FROM t WHERE ${`a = '${req.query.a}'`}`);\n});\n", true, ""},
		{"E12 callback closure", "js", "app.get('/u', function (req, res) {\n  const d = req.query.d;\n  setImmediate(() => { exec('ls ' + d); });\n});\n", true, ""},
		{"E13 const arrow outer", "js", "const handler = async (req, res) => {\n  const sql = 'SELECT * FROM t WHERE n = \\'' + req.query.n + '\\'';\n  const [rows] = await conn.execute(sql);\n};\n", true, ""},
		{"E14 typeof check then use", "js", "app.get('/u', async (req, res) => {\n  if (typeof req.query.n !== 'string') return res.sendStatus(400);\n  await User.findOne({ where: { name: req.query.n } });\n});\n", false, ""},
		{"E15 regex-like division", "js", "app.get('/u', (req, res) => {\n  const r = a / 2; exec('x' + req.query.y); // / \n});\n", true, ""},
		{"E16 sanitizer partial", "js", "app.get('/u', (req, res) => {\n  pool.query('SELECT * FROM t WHERE id = ' + parseInt(req.query.id) + ' AND n = ' + req.query.n);\n});\n", true, ""},
		{"R1 py import subprocess as sp", "python", "import subprocess as sp\ndef v():\n    sp.run('ping ' + request.args['h'], shell=True)\n", true, ""},
		{"R2 py from subprocess import Popen", "python", "from subprocess import Popen\ndef v():\n    Popen('ping ' + request.args['h'], shell=True)\n", true, ""},
		{"R3 py create_subprocess_shell", "python", "def v():\n    asyncio.create_subprocess_shell('ping ' + request.args['h'])\n", true, ""},
		{"R4 js shell path", "js", "app.get('/x',(req,res)=>{ spawn('git', ['log', req.query.r], { shell: '/bin/bash' }); });\n", true, ""},
		{"R5 js options in a variable", "js", "const opts = { shell: true };\napp.get('/x',(req,res)=>{ spawn('git log ' + req.query.r, opts); });\n", true, "options passed in a variable ({ shell: true } assigned earlier) are not looked into"},
		{"R6 js shell expression", "js", "app.get('/x',(req,res)=>{ spawn('git log ' + req.query.r, { shell: process.platform !== 'win32' }); });\n", true, ""},
		{"R7 js safeLoad full schema", "js", "app.post('/y',(req,res)=>{ yaml.safeLoad(req.body, { schema: yaml.DEFAULT_FULL_SCHEMA }); });\n", true, ""},
		{"R8 js load full schema", "js", "app.post('/y',(req,res)=>{ yaml.load(req.body, { schema: yaml.DEFAULT_FULL_SCHEMA }); });\n", true, ""},
		{"R9 js require child_process exec", "js", "app.get('/x',(req,res)=>{ require('child_process').exec('ls ' + req.query.d); });\n", true, ""},
		{"R10 js child_process.execSync", "js", "app.get('/x',(req,res)=>{ child_process.execSync('ls ' + req.query.d); });\n", true, ""},
		// Review findings, one or more cases each.
		{"K1 js variable named fn", "js", "app.get('/x', (req, res) => {\n  const fn = req.query.f;\n  exec('cat ' + fn);\n});\n", true, ""},
		{"K2 py variable named fn", "python", "@app.get('/d')\ndef d():\n    fn = request.args['f']\n    return send_file(os.path.join(UPLOAD, fn))\n", true, ""},
		{"K3 js variable named use", "js", "app.get('/x', (req, res) => {\n  const use = req.query.u;\n  exec(use);\n});\n", true, ""},
		{"T1 php reassign in try", "php", "<?php\n$c = $_GET['c'];\ntry { $c = 'x' . g(); } catch (Exception $e) {}\nsystem($c);\n", true, ""},
		{"T2 js reassign in try", "js", "app.get('/x', (req, res) => {\n  let c = req.query.c;\n  try { c = 'x' + g(); } catch (e) {}\n  exec(c);\n});\n", true, ""},
		{"T3 py reassign in try", "python", "def v():\n    c = request.args['c']\n    try:\n        c = 'x' + g()\n    except Exception:\n        pass\n    os.system(c)\n", true, ""},
		{"T4 py try clean on all paths", "python", "def v():\n    c = request.args['c']\n    try:\n        c = 'x'\n    except Exception:\n        c = 'y'\n    os.system(c)\n", false, ""},
		{"S1 php switch one case cleans", "php", "<?php\n$a = $_GET['a'];\nswitch ($m) { case 1: $a = 'x'; break; default: break; }\nsystem($a);\n", true, ""},
		{"S2 js switch every case cleans", "js", "app.get('/x', (req, res) => {\n  let a = req.query.a;\n  switch (m) { case 1: a = 'x'; break; default: a = 'y'; }\n  exec(a);\n});\n", false, ""},
		{"S3 php switch falls through to the sink", "php", "<?php\nswitch ($m) {\n  case 1: $a = $_GET['a'];\n  case 2: system($a); break;\n}\n", true, ""},
		{"N1 py resolve only", "python", "@app.get('/d')\ndef d():\n    p = (Path(BASE) / request.args['f']).resolve()\n    return send_file(p)\n", true, ""},
		{"N2 js zip slip with resolve only", "js", "app.post('/i', (req, res) => {\n  for (const entry of new AdmZip(req.file.path).getEntries()) {\n    fs.writeFileSync(path.resolve(dest, entry.entryName), entry.getData());\n  }\n});\n", true, ""},
		{"N3 py resolve then startswith with separator", "python", "@app.get('/d')\ndef d():\n    p = os.path.realpath(os.path.join(BASE, request.args['f']))\n    if not p.startswith(BASE + os.sep):\n        abort(404)\n    return send_file(p)\n", false, "the rule lists os.path.join( as a sink, so a join that is checked afterwards is still reported (false positive, for E7)"},
		{"O1 js shell: false", "js", "app.get('/x', (req, res) => { spawn('git', ['log', req.query.r], { shell: false }); });\n", false, ""},
		{"O2 py shell=False", "python", "def v():\n    subprocess.run('ping ' + request.args['h'], shell=False)\n", false, ""},
		{"O3 py -- after the input", "python", "def v():\n    subprocess.run(['git', 'log', request.args['r'], '--'])\n", true, ""},
		{"O4 js root from the request", "js", "app.get('/f', (req, res) => { res.sendFile(req.params.name, { root: req.query.dir }); });\n", true, ""},
	}
	pass := 0
	for _, c := range cases {
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		ok := (len(fs) > 0) == c.vulnerable
		switch {
		case ok:
			pass++
			if c.gap != "" {
				t.Errorf("%s: marked as a known gap but now passes; remove the mark", c.name)
			}
		case c.gap != "":
			t.Logf("known gap, %s: %s", c.name, c.gap)
		case c.vulnerable:
			t.Errorf("%s: not reported", c.name)
		default:
			t.Errorf("%s: reported %+v", c.name, fs)
		}
	}
	t.Logf("held-out cases right: %d/%d", pass, len(cases))
}
