package engine

// Independent review of PR #20 (p1-classes @ e36505f). Each case states what a
// correct scanner should do; a failing case is a reproduced issue. Cases whose
// rule family is not loaded (on the base 236234a, the nine new classes) are
// skipped, so the same file runs on both trees.

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// r20Known are cases the engine does not handle yet; they are known limits,
// listed in PR #20 and the rules README, not regressions.
var r20Known = map[string]string{
	"O02": "a check on a value derived from the file name (its extension) cleans the whole name; also on the base",
	"O03": "a check on a value derived from the file name (its extension) cleans the whole name; also on the base",
}

type r20case struct {
	id, lang, prefix, src string
	want                  bool // true: a finding of a rule whose id starts with prefix is expected
}

func r20run(t *testing.T, cases []r20case) {
	t.Helper()
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	have := func(prefix string) bool {
		for _, r := range rs {
			if strings.HasPrefix(r.ID, prefix) {
				return true
			}
		}
		return false
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if !have(c.prefix) {
				t.Skipf("no rule %s* in this tree", c.prefix)
			}
			if why, ok := r20Known[c.id[:3]]; ok {
				t.Skipf("known limit, listed in PR #20: %s", why)
			}
			fs, err := e.Scan(c.lang, "t."+c.lang, []byte(c.src))
			got := false
			var ids []string
			for _, f := range fs {
				ids = append(ids, f.RuleID)
				if strings.HasPrefix(f.RuleID, c.prefix) {
					got = true
				}
			}
			if got != c.want {
				t.Errorf("%s: want reported=%v, got %v (findings %v, err %v)", c.id, c.want, got, ids, err)
			}
		})
	}
}

// 1a. Nonce and capability checks.
func TestR20Nonce(t *testing.T) {
	r20run(t, []r20case{
		{"N01 named arg die:false", "php", "php-open-redirect", "<?php\ncheck_ajax_referer('go', 'n', die: false);\nwp_redirect($_GET['to']);\nexit;\n", true},
		{"N02 third arg variable false", "php", "php-open-redirect", "<?php\n$die = false;\ncheck_ajax_referer('go', 'n', $die);\nwp_redirect($_GET['to']);\nexit;\n", true},
		{"N03 nopriv ajax: wp_verify_nonce only", "php", "php-open-redirect", "<?php\nadd_action('wp_ajax_nopriv_go', function () {\n  if (!wp_verify_nonce($_GET['n'], 'go')) { wp_die(); }\n  wp_redirect($_GET['to']);\n  exit;\n});\n", true},
		{"N04 check in loop body", "php", "php-xss-echo-html", "<?php\nforeach ($items as $i) { check_admin_referer('x'); }\necho $_GET['q'];\n", true},
		{"N05 check in one switch case", "php", "php-xss-echo-html", "<?php\nswitch ($_GET['a']) {\n case 'save': check_admin_referer('s'); break;\n}\necho $_GET['q'];\n", true},
		{"N06 exit only inside closure", "php", "php-xss-echo-html", "<?php\nif (!wp_verify_nonce($_POST['n'], 'a')) { $f = function () { wp_die(); }; }\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", true},
		{"N07 check after sink", "php", "php-xss-echo-html", "<?php\necho $_GET['q'];\ncheck_admin_referer('x');\n", true},
		{"N08 inverted result", "php", "php-xss-echo-html", "<?php\nif (wp_verify_nonce($_POST['n'], 'a')) { wp_die(); }\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", true},
		{"N09 result unused", "php", "php-xss-echo-html", "<?php\nwp_verify_nonce($_POST['n'], 'a');\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", true},
		{"N10 one branch only", "php", "php-xss-echo-html", "<?php\nif (isset($_POST['save'])) { check_admin_referer('s'); }\necho $_GET['q'];\n", true},
		{"N11 no exit in failing branch", "php", "php-xss-echo-html", "<?php\nif (!wp_verify_nonce($_POST['n'], 'a')) { echo 'bad nonce'; }\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", true},
		{"N12 throw caught", "php", "php-xss-echo-html", "<?php\ntry {\n  if (!wp_verify_nonce($_POST['n'], 'a')) { throw new Exception('x'); }\n} catch (Exception $e) {}\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", true},
		{"N13 ajax nonce without cap (xss)", "php", "php-xss-echo-html", "<?php\ncheck_ajax_referer('a', 'n');\necho $_GET['q'];\n", true},
		{"N14 check_admin_referer() with no action (-1: referer-only)", "php", "php-xss-echo-html", "<?php\ncheck_admin_referer();\necho $_GET['q'];\n", true},
		{"N15 cap check || nonce check", "php", "php-xss-echo-html", "<?php\nif (!wp_verify_nonce($_POST['n'], 'a') && !current_user_can('manage_options')) { wp_die(); }\necho $_GET['q'];\n", true},
		// should stay safe (false-positive side)
		{"N50 safe: isset || verify then die", "php", "php-xss-echo-html", "<?php\nif (!isset($_POST['n']) || !wp_verify_nonce($_POST['n'], 'a')) { wp_die(); }\nif (!current_user_can('edit_posts')) { wp_die(); }\necho $_GET['q'];\n", false},
		{"N51 safe: admin referer", "php", "php-xss-echo-html", "<?php\ncheck_admin_referer('save');\necho $_GET['q'];\n", false},
	})
}

// 1b. if ($x) false => $x empty.
func TestR20IfFalse(t *testing.T) {
	r20run(t, []r20case{
		{"F01 refill in falsy branch", "php", "php-cmdi", "<?php\n$x = $_GET['a'];\nif (!$x) { $x = $_GET['b']; }\nsystem($x);\n", true},
		{"F02 else of truthy", "php", "php-cmdi", "<?php\n$x = $_GET['a'];\nif ($x) { log_it(); } else { $x = $_POST['b']; }\nsystem($x);\n", true},
		{"F03 py not x refill", "python", "python-cmdi", "@app.get('/r')\ndef r():\n    x = request.args.get('a')\n    if not x:\n        x = request.args.get('b')\n    os.system(x)\n    return 'ok'\n", true},
		{"F04 js falsy refill", "js", "js-cmdi", "app.get('/r', (req, res) => {\n  let x = req.query.a;\n  if (!x) { x = req.query.b; }\n  exec(x);\n  res.end();\n});\n", true},
		{"F05 truthy branch keeps taint", "php", "php-cmdi", "<?php\n$x = $_GET['a'];\nif ($x) { system($x); }\n", true},
		{"F06 sub key tainted, container falsy check on other key", "php", "php-cmdi", "<?php\n$d = $_GET;\nif (!$d['flag']) { system($d['cmd']); }\n", true},
	})
}

// 1c. preg_replace / re.sub with a negated class.
func TestR20StripAll(t *testing.T) {
	r20run(t, []r20case{
		{"S01 array keys survive preg_replace", "php", "php-sqli", "<?php\n$f = preg_replace('/[^a-z0-9_]/', '', $_POST['fields']);\nforeach ($f as $col => $v) { mysqli_query($db, \"UPDATE t SET $col = 1\"); }\n", true},
		{"S02 x flag", "php", "php-cmdi", "<?php\n$x = preg_replace('/[^a-z0-9] # c/x', '', $_GET['x']);\nsystem('ls ' . $x);\n", true},
		{"S03 class with dot", "php", "php-path-traversal", "<?php\n$f = preg_replace('/[^a-z0-9.\\/]/', '', $_GET['f']);\ninclude 'pages/' . $f;\n", true},
		{"S04 4th arg limit", "php", "php-cmdi", "<?php\n$x = preg_replace('/[^a-z]/', '', $_GET['x'], 1);\nsystem('ls ' . $x);\n", true},
		{"S05 not negated", "php", "php-cmdi", "<?php\n$x = preg_replace('/[a-z]/', '', $_GET['x']);\nsystem('ls ' . $x);\n", true},
		{"S06 py count kw", "python", "python-cmdi", "@app.get('/r')\ndef r():\n    x = re.sub(r'[^a-z]', '', request.args['x'], count=1)\n    os.system('ls ' + x)\n    return 'ok'\n", true},
		{"S07 non-empty replacement", "php", "php-cmdi", "<?php\n$x = preg_replace('/[^a-z]/', ';', $_GET['x']);\nsystem('ls ' . $x);\n", true},
		{"S50 safe: strip with i,u", "php", "php-cmdi", "<?php\n$x = preg_replace('/[^a-z0-9_-]/iu', '', $_GET['x']);\nsystem('ls ' . $x);\n", false},
		{"S51 safe: py re.sub", "python", "python-cmdi", "@app.get('/r')\ndef r():\n    x = re.sub(r'[^\\w-]', '', request.args['x'])\n    os.system('ls ' + x)\n    return 'ok'\n", false},
	})
}

// 1d. Fixed prefixes.
func TestR20Prefix(t *testing.T) {
	r20run(t, []r20case{
		{"R01 Location: / . input (//evil)", "php", "php-open-redirect", "<?php\nheader('Location: /' . $_GET['u']);\nexit;\n", true},
		{"R02 wp_redirect('/' . input)", "php", "php-open-redirect", "<?php\nwp_redirect('/' . $_GET['u']);\nexit;\n", true},
		{"R03 home_url() . input (@evil)", "php", "php-open-redirect", "<?php\nwp_redirect(home_url() . $_GET['u']);\nexit;\n", true},
		{"R04 untrailingslashit(home_url('/')) . input", "php", "php-open-redirect", "<?php\nwp_redirect(untrailingslashit(home_url('/')) . $_GET['u']);\nexit;\n", true},
		{"R05 rtrim(site_url(), '/') . input", "php", "php-open-redirect", "<?php\nwp_redirect(rtrim(site_url(), '/') . $_GET['u']);\nexit;\n", true},
		{"R06 ssrf home_url() . input", "php", "php-ssrf", "<?php\n$r = wp_remote_get(home_url() . $_GET['p']);\n", true},
		{"R07 untrailingslashit(literal host/) . input", "php", "php-ssrf", "<?php\n$r = wp_remote_get(untrailingslashit('https://api.example.com/') . $_GET['p']);\n", true},
		{"R08 rtrim(input)", "php", "php-open-redirect", "<?php\nwp_redirect(rtrim($_GET['x'], '/'));\nexit;\n", true},
		{"R09 py redirect('/' + next)", "python", "python-open-redirect", "@app.get('/login')\ndef login():\n    return redirect('/' + request.args['next'])\n", true},
		{"R10 js res.redirect('/' + next)", "js", "js-open-redirect", "app.get('/l', (req, res) => {\n  res.redirect('/' + req.query.next);\n});\n", true},
		{"R11 py urljoin absolute override", "python", "python-ssrf", "@app.get('/p')\ndef p():\n    return requests.get(urljoin('https://api.example.com/', request.args['u'])).text\n", true},
		{"R12 js new URL(input, base)", "js", "js-ssrf", "app.get('/p', async (req, res) => {\n  const r = await fetch(new URL(req.query.p, 'https://api.example.com/'));\n  res.end();\n});\n", true},
		{"R13 add_query_arg(k, v, input)", "php", "php-open-redirect", "<?php\nwp_redirect(add_query_arg('a', 'b', $_GET['u']));\nexit;\n", true},
		{"R14 apply_filters on raw input", "php", "php-open-redirect", "<?php\nwp_redirect(apply_filters('my_redirect', $_GET['u']));\nexit;\n", true},
		// should stay safe
		{"R50 safe: admin_url('x' . input)", "php", "php-open-redirect", "<?php\nwp_redirect(admin_url('admin.php?page=' . $_GET['p']));\nexit;\n", false},
		{"R51 safe: fixed host with path", "php", "php-ssrf", "<?php\n$r = wp_remote_get('https://api.example.com/v1/' . $_GET['p']);\n", false},
		{"R52 safe: py fixed host", "python", "python-ssrf", "@app.get('/p')\ndef p():\n    return requests.get(f\"https://api.example.com/items/{request.args['id']}\").text\n", false},
		{"R53 safe: py module constant base", "python", "python-ssrf", "API = 'https://api.example.com/v1/'\n\n@app.get('/p')\ndef p():\n    return requests.get(API + request.args['id']).text\n", false},
	})
}

// Old classes: fixedHost now short-circuits notScheme for every leading rule.
func TestR20PrefixOld(t *testing.T) {
	r20run(t, []r20case{
		{"O01 include from fixed remote host", "php", "php-path-traversal", "<?php\ninclude 'http://cdn.example.com/' . $_GET['f'];\n", true},
		{"O02 ext check then raw name (php path traversal)", "php", "php-path-traversal", "<?php\n$f = $_FILES['c'];\nif (!in_array(strtolower(pathinfo($f['name'], PATHINFO_EXTENSION)), ['pem', 'crt'], true)) { wp_die('no'); }\nmove_uploaded_file($f['tmp_name'], WP_CONTENT_DIR . '/certs/' . $f['name']);\n", true},
		{"O03 ext check then raw name (py path traversal)", "python", "python-path-traversal", "@app.post('/u')\ndef u():\n    f = request.files['file']\n    if os.path.splitext(f.filename)[1].lower() not in {'.png', '.jpg'}:\n        abort(400)\n    f.save('/srv/app/uploads/' + f.filename)\n    return 'ok'\n", true},
		{"O04 if-false: sqli still reported after truthy check", "php", "php-sqli", "<?php\n$id = $_GET['id'];\nif (!$id) { $id = $_GET['alt']; }\nmysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n", true},
		{"O05 nonce does not make sqli safe", "php", "php-sqli", "<?php\ncheck_admin_referer('del');\nmysqli_query($db, \"DELETE FROM t WHERE id = \" . $_GET['id']);\n", true},
	})
}

// 1e. XSS output contexts.
func TestR20XSS(t *testing.T) {
	long := strings.Repeat("var pad = 1;\n", 170) // > 2048 bytes of script before the echo
	r20run(t, []r20case{
		{"X01 attribute-name position, esc_attr", "php", "php-xss", "<div <?php echo esc_attr($_GET['a']); ?>>x</div>\n", true},
		{"X02 unquoted attribute value, esc_attr", "php", "php-xss", "<input value=<?php echo esc_attr($_GET['v']); ?>>\n", true},
		{"X03 unquoted JS, esc_js", "php", "php-xss", "<script>var id = <?php echo esc_js($_GET['id']); ?>;</script>\n", true},
		{"X04 json in double-quoted onclick", "php", "php-xss", "<button onclick=\"go(<?php echo wp_json_encode($_GET['x']); ?>)\">go</button>\n", true},
		{"X05 echo not first statement in <script>", "php", "php-xss", "<script>var q = <?php $q = esc_html($_GET['q']); echo $q; ?>;</script>\n", true},
		{"X06 echo after if in href", "php", "php-xss", "<a href=\"<?php if ($show) echo esc_html($_GET['u']); ?>\">x</a>\n", true},
		{"X07 <script> opened >2048 bytes earlier", "php", "php-xss", "<script>\n" + long + "var id = <?php echo esc_html($_GET['id']); ?>;\n</script>\n", true},
		{"X08 srcdoc after markup, esc_attr", "php", "php-xss", "<iframe srcdoc=\"<b><?php echo esc_attr($_GET['h']); ?>\"></iframe>\n", true},
		{"X09 opaque call mb_strtolower", "php", "php-xss", "<?php\necho '<p>' . mb_strtolower($_GET['q']) . '</p>';\n", true},
		{"X10 opaque call esc_sql", "php", "php-xss", "<?php\necho '<p>' . esc_sql($_GET['q']) . '</p>';\n", true},
		{"X11 py href html.escape (javascript:)", "python", "python-xss", "def v(request):\n    return HttpResponse('<a href=\"' + escape(request.GET['u']) + '\">x</a>')\n", true},
		{"X12 py unquoted script escape", "python", "python-xss", "def v(request):\n    return HttpResponse('<script>var id = ' + escape(request.GET['id']) + ';</script>')\n", true},
		{"X13 py json.dumps in script", "python", "python-xss", "def v(request):\n    return HttpResponse('<script>var d = ' + json.dumps(request.GET['d']) + ';</script>')\n", true},
		{"X14 js encodeURIComponent unquoted script", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<script>var a = ' + encodeURIComponent(req.query.a) + ';</script>');\n});\n", true},
		{"X15 js JSON.stringify in script", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<script>var a = ' + JSON.stringify(req.query.a) + ';</script>');\n});\n", true},
		{"X16 js normalize() opaque", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<p>' + req.query.a.normalize() + '</p>');\n});\n", true},
		{"X17 raw in <style>", "php", "php-xss", "<style>.a{color:<?php echo $_GET['c']; ?>}</style>\n", true},
		{"X18 href javascript: prefix, esc_attr", "php", "php-xss", "<a href=\"javascript:<?php echo esc_attr($_GET['c']); ?>\">x</a>\n", true},
		{"X19 onclick, esc_attr", "php", "php-xss", "<a onclick=\"f('<?php echo esc_attr($_GET['c']); ?>')\">x</a>\n", true},
		// should stay safe (false positives)
		{"X50 safe esc_html text", "php", "php-xss", "<p><?php echo esc_html($_GET['q']); ?></p>\n", false},
		{"X51 safe esc_url href", "php", "php-xss", "<a href=\"<?php echo esc_url($_GET['u']); ?>\">x</a>\n", false},
		{"X52 safe esc_attr value", "php", "php-xss", "<input value=\"<?php echo esc_attr($_GET['v']); ?>\">\n", false},
		{"X53 safe wp_json_encode in script", "php", "php-xss", "<script>var d = <?php echo wp_json_encode($_GET['d']); ?>;</script>\n", false},
		{"X54 safe printf esc_html", "php", "php-xss", "<?php\nprintf('<p>%s</p>', esc_html($_GET['q']));\n", false},
		{"X55 safe (int) cast", "php", "php-xss", "<?php\necho '<p>' . (int) $_GET['n'] . '</p>';\n", false},
		{"X56 safe absint attr", "php", "php-xss", "<input value=\"<?php echo absint($_GET['n']); ?>\">\n", false},
		{"X57 safe esc_html__ literal", "php", "php-xss", "<?php\necho esc_html__('Saved', 'td');\n", false},
		{"X58 safe js escapeHtml template", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send(`<p>${escapeHtml(req.query.q)}</p>`);\n});\n", false},
		{"X59 safe js json object", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send({ q: req.query.q });\n});\n", false},
		{"X60 safe py escape text", "python", "python-xss", "def v(request):\n    return HttpResponse('<p>' + escape(request.GET['q']) + '</p>')\n", false},
		{"X61 safe py json response", "python", "python-xss", "def v(request):\n    return HttpResponse(json.dumps({'q': request.GET['q']}), content_type=\"application/json\")\n", false},
		{"X62 safe sanitize_text_field + esc_attr", "php", "php-xss", "<?php $v = sanitize_text_field(wp_unslash($_POST['v'])); ?>\n<input value=\"<?php echo esc_attr($v); ?>\">\n", false},
	})
}

// 2. Other new classes: misses and false positives on common code.
func TestR20Other(t *testing.T) {
	r20run(t, []r20case{
		// false positives
		{"C50 js Array.find with arrow", "js", "js-nosqli", "app.get('/u', (req, res) => {\n  const u = users.find(x => x.name === req.query.name);\n  res.json(u);\n});\n", false},
		{"C51 laravel Eloquent find", "php", "php-nosqli", "<?php\nclass C { public function show(Request $request) {\n  return $this->users->find($request->input('id'));\n} }\n", false},
		{"C52 libxmljs noent:false", "js", "js-xxe", "const doc = libxmljs.parseXml(xml, { noent: false });\n", false},
		{"C53 md5 cache key", "php", "php-weak-crypto", "<?php\n$key = md5($_GET['page'] . 'v2');\n", false},
		{"C54 hashlib md5 etag", "python", "python-weak-crypto", "def v(request):\n    etag = hashlib.md5(request.GET['q'].encode()).hexdigest()\n    return etag\n", false},
		{"C55 secret from env", "python", "python-hardcoded-secret", "import os\ntok = jwt.encode(payload, os.environ['JWT_SECRET'], algorithm='HS256')\n", false},
		{"C56 empty password", "php", "php-hardcoded-secret", "<?php\n$db = new mysqli('localhost', 'root', '', 'app');\n", false},
		{"C57 sanitize_file_name with wp_check_filetype", "php", "php-file-upload", "<?php\n$f = $_FILES['f'];\n$t = wp_check_filetype($f['name'], array('jpg' => 'image/jpeg'));\nif (!$t['ext']) { wp_die(); }\nmove_uploaded_file($f['tmp_name'], $dir . '/' . wp_unique_filename($dir, $f['name']));\n", false},
		{"C58 py secure_filename + allowed_file", "python", "python-file-upload", "@app.post('/u')\ndef u():\n    f = request.files['file']\n    if f and allowed_file(f.filename):\n        f.save(os.path.join(UPLOAD, secure_filename(f.filename)))\n    return 'ok'\n", false},
		// misses
		{"C01 py secure_filename alone keeps .html/.py", "python", "python-file-upload", "@app.post('/u')\ndef u():\n    f = request.files['file']\n    f.save(os.path.join(UPLOAD, secure_filename(f.filename)))\n    return 'ok'\n", true},
		{"C02 php md5 name + client extension", "php", "php-file-upload", "<?php\n$f = $_FILES['f'];\n$ext = pathinfo($f['name'], PATHINFO_EXTENSION);\nmove_uploaded_file($f['tmp_name'], $dir . '/' . md5($f['name']) . '.' . $ext);\n", true},
		{"C03 noent via variable", "php", "php-xxe", "<?php\n$o = LIBXML_NOENT;\n$x = simplexml_load_string($_POST['x'], 'SimpleXMLElement', $o);\n", true},
		{"C04 nosqli findOne body", "js", "js-nosqli", "app.post('/l', async (req, res) => {\n  const u = await User.findOne({ email: req.body.email, pass: req.body.pass });\n  res.json(u);\n});\n", true},
		{"C05 ldap php filter", "php", "php-ldapi", "<?php\n$r = ldap_search($c, 'dc=x', '(uid=' . $_GET['u'] . ')');\n", true},
	})
}

// Controls: the same shapes without the construct under test must be reported,
// so a failing case above is the construct, not an unsupported shape.
func TestR20Controls(t *testing.T) {
	r20run(t, []r20case{
		{"K01 open-redirect raw", "php", "php-open-redirect", "<?php\nwp_redirect($_GET['to']);\nexit;\n", true},
		{"K02 Location raw", "php", "php-open-redirect", "<?php\nheader('Location: ' . $_GET['u']);\nexit;\n", true},
		{"K03 py redirect raw", "python", "python-open-redirect", "@app.get('/login')\ndef login():\n    return redirect(request.args['next'])\n", true},
		{"K04 js redirect raw", "js", "js-open-redirect", "app.get('/l', (req, res) => {\n  res.redirect(req.query.next);\n});\n", true},
		{"K05 ssrf raw", "php", "php-ssrf", "<?php\n$r = wp_remote_get($_GET['p']);\n", true},
		{"K06 php pt raw name", "php", "php-path-traversal", "<?php\n$f = $_FILES['c'];\nmove_uploaded_file($f['tmp_name'], WP_CONTENT_DIR . '/certs/' . $f['name']);\n", true},
		{"K07 py pt raw name", "python", "python-path-traversal", "@app.post('/u')\ndef u():\n    f = request.files['file']\n    f.save('/srv/app/uploads/' + f.filename)\n    return 'ok'\n", true},
		{"K08 attr raw unquoted", "php", "php-xss", "<input value=<?php echo $_GET['v']; ?>>\n", true},
		{"K09 script raw", "php", "php-xss", "<script>var id = <?php echo $_GET['id']; ?>;</script>\n", true},
		{"K10 href raw after if", "php", "php-xss", "<a href=\"<?php echo $_GET['u']; ?>\">x</a>\n", true},
		{"K11 py href raw", "python", "python-xss", "def v(request):\n    return HttpResponse('<a href=\"' + request.GET['u'] + '\">x</a>')\n", true},
		{"K12 js script raw", "js", "js-xss", "app.get('/x', (req, res) => {\n  res.send('<script>var a = ' + req.query.a + ';</script>');\n});\n", true},
		{"K13 php p raw", "php", "php-xss", "<?php\necho '<p>' . $_GET['q'] . '</p>';\n", true},
		{"K14 sqli keys raw", "php", "php-sqli", "<?php\n$f = $_POST['fields'];\nforeach ($f as $col => $v) { mysqli_query($db, \"UPDATE t SET $col = 1\"); }\n", true},
		{"K15 esc_html in script (quoted)", "php", "php-xss", "<script>var q = '<?php echo esc_html($_GET['q']); ?>';</script>\n", true},
		{"K16 include fixed remote host (base semantics)", "php", "php-path-traversal", "<?php\ninclude 'http://cdn.example.com' . $_GET['f'];\n", true},
	})
}
