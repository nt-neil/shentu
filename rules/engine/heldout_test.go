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
