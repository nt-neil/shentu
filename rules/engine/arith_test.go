package engine

import (
	"slices"
	"testing"
)

// The result of arithmetic is a number, which carries no quote, keyword or tag
// into SQL or markup (usc-e-shop 2.9.6 classes/loglist.class.php:524:
// $from = ($current_page - 1) * $per; ... " LIMIT {$from}, ..."). A path rule
// still reports, and so do the operators that can give a string: PHP's + of
// two arrays, JavaScript's binary +, Python's * and %, bitwise operators.
func TestArithmeticIsNumber(t *testing.T) {
	e := engineForTest(t)
	const js = "const express = require('express');\nconst app = express();\n"
	const py = "from flask import Flask, request\napp = Flask(__name__)\n"
	for _, c := range []struct {
		name, lang, path, src string
		want                  []int
	}{
		{"usc-e-shop's page offset in LIMIT (no finding)", "php", "a.php",
			"<?php\n$p = max($_GET['paged'], 1);\n$from = ($p - 1) * 20;\n$wpdb->get_results(\"SELECT * FROM t LIMIT {$from}, 20\");\n", nil},
		{"PHP + next to a number (no finding)", "php", "a.php",
			"<?php\n$n = $_GET['n'] + 1;\nmysqli_query($c, \"SELECT * FROM t LIMIT $n\");\n", nil},
		{"PHP arithmetic echoed (no finding)", "php", "a.php",
			"<?php\necho '<p>' . $_GET['p'] * 2 . '</p>';\n", nil},
		{"JavaScript - in a query (no finding)", "js", "a.js",
			js + "app.get('/x', (req, res) => {\n  const n = req.query.n - 1;\n  pool.query('SELECT * FROM t LIMIT ' + n);\n});\n", nil},
		{"Python - inside a % format (no finding)", "python", "a.py",
			py + "@app.route('/x')\ndef x():\n    cur.execute('SELECT * FROM t LIMIT %s' % (request.args['n'] - 1))\n", nil},
		{"no arithmetic (control)", "php", "a.php",
			"<?php\n$n = $_GET['n'];\nmysqli_query($c, \"SELECT * FROM t LIMIT $n\");\n", []int{3}},
		{"a path rule still reports a number", "php", "a.php",
			"<?php\n$n = $_GET['n'] - 1;\n$t = file_get_contents('/var/logs/' . $n);\n", []int{3}},
		{"PHP + of two arrays is their union", "php", "a.php",
			"<?php\n$ids = implode(',', $_GET['a'] + $_GET['b']);\nmysqli_query($c, \"SELECT * FROM t WHERE id IN ($ids)\");\n", []int{3}},
		{"PHP | of two strings is a string", "php", "a.php",
			"<?php\n$n = $_GET['a'] | $_GET['b'];\nmysqli_query($c, \"SELECT * FROM t WHERE a = '$n'\");\n", []int{3}},
		{"PHP . with - is a string", "php", "a.php",
			"<?php\n$n = $_GET['a'] . 1 - 1;\nmysqli_query($c, \"SELECT * FROM t WHERE a = '$n'\");\n", []int{3}},
		{"JavaScript binary + joins strings", "js", "a.js",
			js + "app.get('/x', (req, res) => {\n  const n = req.query.n + 1;\n  pool.query('SELECT * FROM t WHERE a = ' + n);\n});\n", []int{5}},
		{"Python * repeats a string", "python", "a.py",
			py + "@app.route('/x')\ndef x():\n    q = request.args['q'] * 2\n    cur.execute(\"SELECT * FROM t WHERE a = '\" + q + \"'\")\n", []int{6}},
		{"Python - of two sets is their difference (N-247-1)", "python", "a.py",
			py + "@app.route('/x')\ndef x():\n    ids = set(request.args.getlist('id')) - {'0'}\n    cur.execute('SELECT * FROM t WHERE id IN (' + ','.join(ids) + ')')\n", []int{6}},
		{"Python - of two Counters keeps the input's keys", "python", "a.py",
			py + "from collections import Counter\n@app.route('/x')\ndef x():\n    c = Counter(request.args.getlist('id')) - Counter(['0'])\n    cur.execute('SELECT * FROM t WHERE id IN (' + ','.join(c) + ')')\n", []int{7}},
		{"Python unary - of a Counter keeps the input's keys", "python", "a.py",
			py + "from collections import Counter\n@app.route('/x')\ndef x():\n    c = -Counter(request.args.getlist('id'))\n    cur.execute('SELECT * FROM t WHERE id IN (' + ','.join(c) + ')')\n", []int{7}},
	} {
		t.Run(c.name, func(t *testing.T) {
			own, _, _ := e.ScanTimed(c.lang, c.path, []byte(c.src))
			var got []int
			for _, f := range own {
				got = append(got, f.Line)
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported lines %v (%v), want %v", got, own, c.want)
			}
		})
	}
}
