package engine

// Second round of the PR #20 review, on d97489b. Same conventions as
// review20_test.go: a failing case is a reproduced issue.

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// Calls whose result is taken as "not the input" in output rules.
func TestR20bOpaque(t *testing.T) {
	r20run(t, []r20case{
		{"BO01 get_ wrapper returning input", "php", "php-xss", "<?php\nfunction get_q() { return $_GET['q']; }\necho '<p>' . get_q() . '</p>';\n", true},
		{"BO02 get_ wrapper with argument", "php", "php-xss", "<?php\nfunction get_val($k) { return $_REQUEST[$k]; }\necho '<p>' . get_val('q') . '</p>';\n", true},
		{"BO03 render_ helper building markup from its arg", "php", "php-xss", "<?php\nfunction render_input($v) { return '<input value=\"' . $v . '\">'; }\necho render_input($_GET['v']);\n", true},
		{"BO04 method of a clean object returning its arg", "php", "php-xss", "<?php\nclass V { function show($x) { return $x; } }\n$v = new V();\necho '<p>' . $v->show($_GET['q']) . '</p>';\n", true},
		{"BO05 static helper Arr::get($_GET)", "php", "php-xss", "<?php\necho '<p>' . Arr::get($_GET, 'q') . '</p>';\n", true},
		{"BO06 $wp_query->get('s') after set from request", "php", "php-xss", "<?php\n$wp_query->set('s', $_GET['s']);\necho '<p>' . $wp_query->get('s') . '</p>';\n", true},
		{"BO07 get_query_var (a source)", "php", "php-xss", "<?php\necho '<p>' . get_query_var('s') . '</p>';\n", true},
		{"BO08 get_search_query(false) (raw search)", "php", "php-xss", "<?php\necho '<p>' . get_search_query(false) . '</p>';\n", true},
		{"BO09 date() with request format", "php", "php-xss", "<?php\necho date($_GET['f']);\n", true},
		{"BO10 is_ wrapper returning input", "php", "php-xss", "<?php\nfunction is_q() { return $_GET['q']; }\necho '<p>' . is_q() . '</p>';\n", true},
		{"BO11 js lodash _.get(req.query)", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<p>' + _.get(req.query, 'q') + '</p>');\n});\n", true},
		{"BO12 py Template.substitute(request.GET)", "python", "python-xss", "def v(request):\n    return HttpResponse(string.Template('<p>$q</p>').substitute(request.GET))\n", true},
		{"BO13 js method on clean object returning arg", "js", "js-xss", "const fmt = { id: (s) => s };\napp.get('/x', (req, res) => {\n  res.send('<p>' + fmt.id(req.query.q) + '</p>');\n});\n", true},
		{"BO14 py helper get_ returning request value", "python", "python-xss", "def get_q(request):\n    return request.GET['q']\n\ndef v(request):\n    return HttpResponse('<p>' + get_q(request) + '</p>')\n", true},
		{"BO15 WP REST ->get_param on $req", "php", "php-xss", "<?php\nfunction cb($req) { echo '<p>' . $req->get_param('q') . '</p>'; }\n", true},
		{"BO16 WP REST ->get_param on $request", "php", "php-xss", "<?php\nfunction cb($request) { echo '<p>' . $request->get_param('q') . '</p>'; }\n", true},
		{"BO17 Laravel $request->input()", "php", "php-xss", "<?php\nclass C { function s(Request $request) { echo '<p>' . $request->input('q') . '</p>'; } }\n", true},
		// safe
		{"BO50 safe: get_the_title($_GET['id'])", "php", "php-xss", "<?php\necho '<h1>' . get_the_title($_GET['id']) . '</h1>';\n", false},
		{"BO51 safe: selected()", "php", "php-xss", "<option <?php selected($_GET['o'], 'a'); ?>>a</option>\n<?php echo '<p>' . selected($_GET['o'], 'a', false) . '</p>';\n", false},
		{"BO52 safe: count($_GET['a'])", "php", "php-xss", "<?php\necho '<p>' . count($_GET['a']) . '</p>';\n", false},
	})
}

// Input only inside an array argument.
func TestR20bArrays(t *testing.T) {
	r20run(t, []r20case{
		{"BA01 join(array_map)", "php", "php-xss", "<?php\necho '<p>' . join(',', array_map('trim', $_GET['tags'])) . '</p>';\n", true},
		{"BA02 vsprintf with array", "php", "php-xss", "<?php\necho vsprintf('<p>%s</p>', array($_GET['q']));\n", true},
		{"BA03 http_build_query", "php", "php-xss", "<?php\necho '<p>' . urldecode(http_build_query(array('q' => $_GET['q']))) . '</p>';\n", true},
		{"BA04 current($_GET['a'])", "php", "php-xss", "<?php\necho '<p>' . current($_GET['a']) . '</p>';\n", true},
		{"BA05 reset / end", "php", "php-xss", "<?php\necho '<p>' . end($_GET['a']) . '</p>';\n", true},
		{"BA06 max of request array", "php", "php-xss", "<?php\necho '<p>' . max($_GET['a']) . '</p>';\n", true},
		{"BA07 strtr with request map", "php", "php-xss", "<?php\necho strtr('<p>{q}</p>', array('{q}' => $_GET['q']));\n", true},
		{"BA08 call_user_func_array sprintf", "php", "php-xss", "<?php\necho call_user_func_array('sprintf', array('<p>%s</p>', $_GET['q']));\n", true},
		{"BA09 sprintf spread", "php", "php-xss", "<?php\necho sprintf('<p>%s</p>', ...$_GET['a']);\n", true},
		{"BA10 wp_sprintf with array", "php", "php-xss", "<?php\necho wp_sprintf('<p>%l</p>', $_GET['a']);\n", true},
		{"BA11 js [x].join", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<p>' + [req.query.q].join('') + '</p>');\n});\n", true},
		{"BA12 js Object.values(req.query).join", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<p>' + Object.values(req.query).join(',') + '</p>');\n});\n", true},
		{"BA13 py ''.join(list)", "python", "python-xss", "def v(request):\n    return HttpResponse('<p>' + ''.join([request.GET['q']]) + '</p>')\n", true},
		{"BA14 py next(iter(values))", "python", "python-xss", "def v(request):\n    return HttpResponse('<p>' + next(iter(request.GET.values())) + '</p>')\n", true},
		{"BA15 array_values()[0]", "php", "php-xss", "<?php\necho '<p>' . array_values($_GET)[0] . '</p>';\n", true},
		{"BA16 extract then echo", "php", "php-xss", "<?php\nextract($_GET);\necho '<p>' . $q . '</p>';\n", true},
	})
}

// A || B || C and $x === clean.
func TestR20bEquality(t *testing.T) {
	r20run(t, []r20case{
		{"BE01 !== clean: true branch keeps taint", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x !== get_option('a')) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE02 === clean then reassigned", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === get_option('a')) { $x = $_GET['y']; echo '<p>' . $x . '</p>'; }\n", true},
		{"BE03 loose == clean (php)", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x == get_option('a')) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE04 === only in else", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === get_option('a')) { } else { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE05 === esc_html($x), then href (javascript:)", "php", "php-xss", "<?php\n$u = $_GET['u'];\nif ($u === esc_html($u)) { echo '<a href=\"' . $u . '\">x</a>'; }\n", true},
		{"BE06 === strip_tags($x) then script", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === strip_tags($x)) { echo '<script>var a = ' . $x . ';</script>'; }\n", true},
		{"BE07 sqli: === esc_sql($x) then unquoted", "php", "php-sqli", "<?php\n$id = $_GET['id'];\nif ($id === esc_sql($id)) { $wpdb->query(\"DELETE FROM t WHERE id = $id\"); }\n", true},
		{"BE08 || with other variable", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === 'a' || $y === 'b') { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE09 || with loose ==", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === 'a' || $x == 0) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE10 || with != ", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x !== 'a' || $x !== 'b') { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE11 || then assignment in cond", "php", "php-xss", "<?php\n$x = 'a';\nif ($x === 'a' || ($x = $_GET['y'])) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE12 || reassigned after", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === 'a' || $x === 'b') { $x .= $_GET['z']; echo '<p>' . $x . '</p>'; }\n", true},
		{"BE13 || negated whole, else branch", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif (!($x === 'a' || $x === 'b')) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BE14 === array element vs whole", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x['k'] === get_option('a')) { echo '<p>' . $x['j'] . '</p>'; }\n", true},
		{"BE15 py == clean but custom", "python", "python-xss", "def v(request):\n    x = request.GET['x']\n    if x != settings.DEFAULT:\n        return HttpResponse('<p>' + x + '</p>')\n", true},
		{"BE16 js === clean, else", "js", "js-xss", "app.get('/x', (req, res) => {\n  const x = req.query.x;\n  if (x === cfg.def) { res.end(); } else { res.send('<p>' + x + '</p>'); }\n});\n", true},
		{"BE17 === another request value", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === $_COOKIE['y']) { echo '<p>' . $x . '</p>'; }\n", true},
		// safe
		{"BE50 safe: === get_option", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === get_option('a')) { echo '<p>' . $x . '</p>'; }\n", false},
		{"BE51 safe: || of literals", "php", "php-xss", "<?php\n$x = $_GET['x'];\nif ($x === 'a' || $x === 'b' || $x === 'c') { echo '<p>' . $x . '</p>'; }\n", false},
	})
}

// The eight-context table and the HTML scanner.
func TestR20bContexts(t *testing.T) {
	r20run(t, []r20case{
		{"BC01 json_encode JSON_UNESCAPED_SLASHES in script", "php", "php-xss", "<script>var d = <?php echo json_encode($_GET['d'], JSON_UNESCAPED_SLASHES); ?>;</script>\n", true},
		{"BC02 wp_json_encode JSON_UNESCAPED_SLASHES", "php", "php-xss", "<script>var d = <?php echo wp_json_encode($_GET['d'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;</script>\n", true},
		{"BC03 esc_js in template literal", "php", "php-xss", "<script>var a = `<?php echo esc_js($_GET['a']); ?>`;</script>\n", true},
		{"BC04 apostrophe in a JS comment, then code", "php", "php-xss", "<script>\n// don't cache\nvar id = <?php echo esc_js($_GET['id']); ?>;\n</script>\n", true},
		{"BC05 quote in a regex literal, then code", "php", "php-xss", "<script>\nvar r = /'/;\nvar id = <?php echo esc_js($_GET['id']); ?>;\n</script>\n", true},
		{"BC06 markup built by earlier echo statements", "php", "php-xss", "<?php\necho '<a href=\"';\necho esc_attr($_GET['u']);\necho '\">x</a>';\n", true},
		{"BC07 <script> opened by an echo", "php", "php-xss", "<?php echo '<script>'; ?>\nvar id = <?php echo esc_html($_GET['id']); ?>;\n<?php echo '</script>'; ?>\n", true},
		{"BC08 py quote(safe=':/') in href", "python", "python-xss", "def v(request):\n    return HttpResponse('<a href=\"' + quote(request.GET['u'], safe=':/') + '\">x</a>')\n", true},
		{"BC09 text/template holds markup with href", "php", "php-xss", "<script type=\"text/template\"><a href=\"<?php echo esc_attr($_GET['u']); ?>\">x</a></script>\n", true},
		{"BC10 escaped quote in handler, then code", "php", "php-xss", "<a onclick=\"var s = 'it\\'s'; go(<?php echo esc_js($_GET['x']); ?>)\">x</a>\n", true},
		{"BC11 urlencode in unquoted script code", "php", "php-xss", "<script>var a = <?php echo esc_attr($_GET['a']); ?>;</script>\n", true},
		{"BC12 style attribute esc_attr", "php", "php-xss", "<div style=\"color: <?php echo esc_attr($_GET['c']); ?>\">x</div>\n", true},
		{"BC13 entity-quoted JS string in handler", "php", "php-xss", "<a onclick=\"go(&#39;<?php echo esc_attr($_GET['x']); ?>&#39;)\">x</a>\n", true},
		{"BC14 js template literal in res.send, esc", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<script>var a = `' + jsesc(req.query.a) + '`;</script>');\n});\n", true},
		{"BC15 uppercase HREF", "php", "php-xss", "<A HREF=\"<?php echo esc_attr($_GET['u']); ?>\">x</A>\n", true},
		{"BC16 svg xlink:href", "php", "php-xss", "<svg><a xlink:href=\"<?php echo esc_attr($_GET['u']); ?>\"><text>x</text></a></svg>\n", true},
		{"BC17 iframe src data:", "php", "php-xss", "<iframe src=\"data:text/html,<?php echo esc_attr($_GET['h']); ?>\"></iframe>\n", true},
		// safe
		{"BC50 safe: esc_js in single-quoted script string", "php", "php-xss", "<script>var a = '<?php echo esc_js($_GET['a']); ?>';</script>\n", false},
		{"BC51 safe: esc_url href after echo-built tag", "php", "php-xss", "<?php\necho '<a href=\"' . esc_url($_GET['u']) . '\">x</a>';\n", false},
		{"BC52 safe: esc_attr single-quoted", "php", "php-xss", "<input value='<?php echo esc_attr($_GET['v']); ?>'>\n", false},
		{"BC53 safe: href=#fragment esc_attr", "php", "php-xss", "<a href=\"#<?php echo esc_attr($_GET['h']); ?>\">x</a>\n", false},
		{"BC54 safe: htmlspecialchars ENT_QUOTES single", "php", "php-xss", "<input value='<?php echo htmlspecialchars($_GET['v'], ENT_QUOTES); ?>'>\n", false},
		{"BC55 safe: py escape in text", "python", "python-xss", "def v(request):\n    return HttpResponse(f\"<p>{escape(request.GET['q'])}</p>\")\n", false},
		{"BC56 safe: wp_json_encode default in script", "php", "php-xss", "<script>var d = <?php echo wp_json_encode($_GET['d']); ?>;</script>\n", false},
		{"BC57 safe: esc_attr in a data- attribute", "php", "php-xss", "<div data-id=\"<?php echo esc_attr($_GET['id']); ?>\"></div>\n", false},
	})
}

// Controls for round 2.
func TestR20bControls(t *testing.T) {
	r20run(t, []r20case{
		{"BK01 assignment in condition", "php", "php-xss", "<?php\n$x = 'a';\nif ($x = $_GET['y']) { echo '<p>' . $x . '</p>'; }\n", true},
		{"BK02 get_query_var direct", "php", "php-xss", "<?php\necho get_query_var('s');\n", true},
		{"BK03 get_query_var via variable", "php", "php-xss", "<?php\n$s = get_query_var('s');\necho '<p>' . $s . '</p>';\n", true},
		{"BK04 plain-named wrapper returning input", "php", "php-xss", "<?php\nfunction q() { return $_GET['q']; }\necho '<p>' . q() . '</p>';\n", true},
		{"BK05 esc_attr in href, one statement", "php", "php-xss", "<?php\necho '<a href=\"' . esc_attr($_GET['u']) . '\">x</a>';\n", true},
		{"BK06 py plain wrapper", "python", "python-xss", "def q(request):\n    return request.GET['q']\n\ndef v(request):\n    return HttpResponse('<p>' + q(request) + '</p>')\n", true},
		{"BK07 js raw join receiver", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<p>' + req.query.q + '</p>');\n});\n", true},
		{"BK09 get_param in a non-output rule", "php", "php-open-redirect", "<?php\nfunction cb($request) { wp_redirect($request->get_param('u')); exit; }\n", true},
		{"BK10 get_query_var in a non-output rule", "php", "php-open-redirect", "<?php\nwp_redirect(get_query_var('u'));\nexit;\n", true},
		{"BK08 esc_js in plain script code", "php", "php-xss", "<script>var a = <?php echo esc_js($_GET['a']); ?>;</script>\n", true},
	})
}

// Prefix fixes, nonce fixes: bypasses of the new rules.
func TestR20bPrefixNonce(t *testing.T) {
	r20run(t, []r20case{
		{"BP01 Location: /\\ . input", "php", "php-open-redirect", "<?php\nheader('Location: /\\\\' . $_GET['u']);\nexit;\n", true},
		{"BP03 home_url($path) variable", "php", "php-open-redirect", "<?php\n$p = '';\nwp_redirect(home_url($p) . $_GET['u']);\nexit;\n", true},
		{"BP04 constant host without slash", "php", "php-ssrf", "<?php\ndefine('API', 'https://api.example.com');\n$r = wp_remote_get(API . $_GET['p']);\n", true},
		{"BP05 sprintf('https://%s/', input)", "php", "php-ssrf", "<?php\n$r = wp_remote_get(sprintf('https://%s/x', $_GET['h']));\n", true},
		{"BP06 trailingslashit(home_url()) . '/' . input", "php", "php-open-redirect", "<?php\nwp_redirect(trailingslashit(home_url()) . '/' . $_GET['u']);\nexit;\n", true},
		{"BP07 check_ajax_referer third arg 0", "php", "php-open-redirect", "<?php\ncheck_ajax_referer('a', 'n', 0);\nif (!current_user_can('x')) { wp_die(); }\nwp_redirect($_GET['u']);\nexit;\n", true},
		{"BP09 check_admin_referer(-1)", "php", "php-xss", "<?php\ncheck_admin_referer(-1);\necho $_GET['q'];\n", true},
		// safe
		{"BP50 safe: check_ajax_referer + cap", "php", "php-open-redirect", "<?php\ncheck_ajax_referer('a', 'n');\nif (!current_user_can('x')) { wp_die(); }\nwp_redirect($_GET['u']);\nexit;\n", false},
		{"BP51 safe: home_url('/x/') . input", "php", "php-open-redirect", "<?php\nwp_redirect(home_url('/account/') . $_GET['u']);\nexit;\n", false},
		{"BP52 safe: Location: /account/ . input", "php", "php-open-redirect", "<?php\nheader('Location: /account/' . $_GET['u']);\nexit;\n", false},
	})
}

// Minified: the new rule (8 KB, half of the non-blank bytes in long lines).
func TestR20bMinified(t *testing.T) {
	rs, _ := rules.Load()
	e, _ := New(rs)
	hand := strings.Repeat("function f(a) { return a + 1; }\n", 40)
	cases := []struct{ id, src string }{
		{"BM01 vuln line padded with a long comment", hand + "app.get('/x', (req, res) => { exec(req.query.c); }); /* " + strings.Repeat("x", 9000) + " */\n"},
		{"BM02 vuln line padded with a long string", hand + "app.get('/x', (req, res) => { exec(req.query.c); const pad = '" + strings.Repeat("y", 9000) + "'; });\n"},
		{"BM03 long template literal opener, vuln after", "const tpl = `" + strings.Repeat("x", 9000) + "\n`;\napp.get('/x', (req, res) => {\n  exec(req.query.c);\n});\n"},
		{"BM04 long line opening a block comment, vuln after", "var a = 1; /* " + strings.Repeat("z", 9000) + "\n*/ app.get('/x', (req, res) => {\n  exec(req.query.c);\n});\n"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			fs, err := e.Scan("js", "app.js", []byte(c.src))
			n := 0
			for _, f := range fs {
				if strings.HasPrefix(f.RuleID, "js-cmdi") {
					n++
				}
			}
			t.Logf("minified=%v err=%v cmdi=%d", Minified([]byte(c.src)), err, n)
			if n == 0 {
				t.Errorf("%s: exec(req.query.c) not reported (err %v)", c.id, err)
			}
		})
	}
}
