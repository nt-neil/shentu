package engine

import (
	"slices"
	"testing"
)

// Each SQL injection line is reported by the one rule that owns it, and by
// one at least: an ORDER BY identifier is php-sqli-orderby-identifier's
// (unless_after), $wpdb's queries php-sqli-wpdb-unprepared's (not_receiver
// $wpdb in php-sqli-string-concat), SQL text into sequelize.query()
// js-sqli-raw-interpolation's, a Sequelize.literal() js-sqli-sequelize-literal's,
// text() python-sqli-sqlalchemy-text's, SQL text into execute()
// python-sqli-dbapi-format's.
func TestSQLiOwner(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, src string
		want            []string
	}{
		{"wpdb ORDER BY interpolated", "php", "<?php\n$col = $_GET['orderby'];\n$rows = $wpdb->get_results(\"SELECT * FROM {$wpdb->posts} ORDER BY $col\");\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb ORDER BY concatenated", "php", "<?php\n$rows = $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . $_GET['orderby']);\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb ORDER BY from get_query_var", "php", "<?php\n$o = get_query_var('o');\n$rows = $wpdb->get_results(\"SELECT * FROM t ORDER BY $o\");\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb input before ORDER BY", "php", "<?php\n$id = $_GET['id'];\n$col = $_GET['orderby'];\n$rows = $wpdb->get_results(\"SELECT * FROM t WHERE id = $id ORDER BY $col\");\n",
			[]string{"php-sqli-orderby-identifier", "php-sqli-wpdb-unprepared"}},
		{"wpdb WHERE only", "php", "<?php\n$id = $_GET['id'];\n$rows = $wpdb->get_results(\"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"wpdb query concatenated", "php", "<?php\n$wpdb->query(\"DELETE FROM t WHERE id IN (\" . implode(',', $_POST['ids']) . \")\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"wpdb query from a cookie", "php", "<?php\n$wpdb->query(\"DELETE FROM t WHERE k = '\" . $_COOKIE['k'] . \"'\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"another db's query", "php", "<?php\n$db->query(\"DELETE FROM t WHERE id = \" . $_GET['id']);\n",
			[]string{"php-sqli-string-concat"}},
		{"prepare ORDER BY in the format", "php", "<?php\n$col = $_GET['sort'];\n$rows = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM t ORDER BY $col LIMIT %d\", 10));\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"prepare WHERE in the format", "php", "<?php\n$id = $_GET['id'];\n$rows = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM t WHERE id = $id LIMIT %d\", 10));\n",
			[]string{"php-sqli-prepare-query-text"}},
		{"sequelize.query", "js", "router.get('/p', async (req, res) => {\n  const t = req.query.tag;\n  res.json(await sequelize.query(`SELECT * FROM items WHERE tag = '${t}'`));\n});\n",
			[]string{"js-sqli-raw-interpolation"}},
		{"Sequelize.literal in a where", "js", "router.get('/p', async (req, res) => {\n  const b = req.query.before;\n  res.json(await Message.findAll({ where: Sequelize.where(Sequelize.literal(`d < '${b}'`), true) }));\n});\n",
			[]string{"js-sqli-sequelize-literal"}},
		{"an object from the query in a where", "js", "router.get('/p', async (req, res) => {\n  res.json(await Message.findAll({ where: req.query.filter }));\n});\n",
			[]string{"js-sqli-object-input"}},
		{"execute(f-string)", "python", "@app.route('/u')\ndef u():\n    name = request.args.get('name', '')\n    cur = db.cursor()\n    cur.execute(f\"SELECT id FROM users WHERE name = '{name}'\")\n    return jsonify(cur.fetchall())\n",
			[]string{"python-sqli-dbapi-format"}},
		{"execute(text(f-string))", "python", "@app.get('/s')\ndef s():\n    col = request.args.get('column', 'price')\n    row = db.session.execute(text(f\"SELECT max({col}) FROM orders\")).scalar()\n    return {'max': row}\n",
			[]string{"python-sqli-sqlalchemy-text"}},
		{"Django input in text()", "python", "def s(request):\n    col = request.GET.get('column')\n    row = db.session.execute(text(f\"SELECT max({col}) FROM orders\")).scalar()\n    return JsonResponse({'max': row})\n",
			[]string{"python-sqli-sqlalchemy-text"}},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "a."+map[string]string{"php": "php", "js": "js", "python": "py"}[c.lang], []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.CWE == "CWE-89" && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: SQL injection reported by %v, want %v", c.name, got, c.want)
		}
	}
}
