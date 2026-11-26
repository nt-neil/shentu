package engine

import (
	"strconv"
	"testing"
)

// PHP extract() of an array that is not written out defines a variable for
// each key the array holds, and by default overwrites the variables already
// defined (EXTR_OVERWRITE). After extract() of input, every variable of the
// scope may hold the input: one defined before (a template loader's own
// $template_name, overwritten by extract($args)) and one never assigned here
// (extract($opts) then $team_id). wp_parse_args($in, $defaults) keeps every
// key of $in, so extract(wp_parse_args($atts, [...])) is the same.
// shortcode_atts() keeps only the default keys and stays as it was.
// EXTR_SKIP (and the EXTR_PREFIX_* flags) do not overwrite. Fixtures are
// neutral; the shapes are those of lifterlms 7.x llms_get_template(),
// joomsport getplayers and CVE-2023-6996.
func TestExtractNonLiteral(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
		rule  string
		line  int
		want  bool
	}{
		{"wp_parse_args of shortcode atts, a key named in the defaults",
			map[string]string{"a.php": "<?php\nadd_shortcode('show', 'show_cb');\nfunction show_cb($atts) {\n    extract(wp_parse_args($atts, array('fn' => 'esc_html', 'id' => 0)));\n    return call_user_func($fn, $id);\n}\n"},
			"a.php", "php-code-eval-dynamic-callback", 5, true},
		{"wp_parse_args of request input, a key not in the defaults",
			map[string]string{"a.php": "<?php\nextract(wp_parse_args($_GET, array('id' => 0)));\ninclude __DIR__ . '/views/' . $view;\n"},
			"a.php", "php-path-traversal-file-include", 3, true},
		{"extract($args) overwrites a parameter (template loader, two files)",
			map[string]string{
				"a.php": "<?php\nrequire 'b.php';\nmy_get_template('form.php', $_POST);\n",
				"b.php": "<?php\nfunction my_get_template($name, $args = array()) {\n    if ($args && is_array($args)) {\n        extract($args);\n    }\n    include dirname(__FILE__) . '/templates/' . $name;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, true},
		{"extract($opts) defines a variable never assigned here",
			map[string]string{"a.php": "<?php\nfunction players($opts) {\n    global $wpdb;\n    extract($opts);\n    return $wpdb->get_results(\"SELECT * FROM t WHERE team = \" . $team_id);\n}\nplayers($_GET);\n"},
			"a.php", "php-sqli-wpdb-unprepared", 5, true},
		{"a branch that assigns the variable joins the path that does not (CVE-2023-6996 shape)",
			map[string]string{"a.php": "<?php\nclass V {\n  function init() { add_shortcode('show', array($this, 'show')); }\n  function show($atts = array()) {\n    extract(wp_parse_args($atts, array('fn' => '', 'kind' => '')));\n    if ($kind === 'query') {\n      $fn = isset($_GET[$fn]) ? (int) $_GET[$fn] : false;\n    }\n    if ($kind === 'callable' && ! empty($fn)) {\n      $fn = (int) call_user_func($fn);\n    }\n  }\n}\n"},
			"a.php", "php-code-eval-dynamic-callback", 10, true},
		{"extract of input at the top level",
			map[string]string{"a.php": "<?php\n$page = 'home.php';\nextract($_REQUEST);\ninclude __DIR__ . '/pages/' . $page;\n"},
			"a.php", "php-path-traversal-file-include", 4, true},
		{"a key of an array extract() set is still the input",
			map[string]string{"a.php": "<?php\nfunction t($vars) {\n    global $wpdb;\n    extract($vars);\n    $wpdb->get_results(\"SELECT * FROM t WHERE a = \" . $f['a']);\n}\nt($_GET);\n"},
			"a.php", "php-sqli-wpdb-unprepared", 5, true},
		{"shortcode_atts of a defaults variable: its keys are defined",
			map[string]string{"a.php": "<?php\nadd_shortcode('show', 'show_cb');\nfunction show_cb($atts) {\n    $defaults = array('tpl' => 'list.php');\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/views/' . $tpl;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, true},
		{"EXTR_IF_EXISTS overwrites a variable defined before (review X1)",
			map[string]string{"a.php": "<?php\n$page = 'home.php';\nextract($_GET, EXTR_IF_EXISTS);\ninclude __DIR__ . '/pages/' . $page;\n"},
			"a.php", "php-path-traversal-file-include", 4, true},
		{"EXTR_PREFIX_ALL defines prefix_key (review X4)",
			map[string]string{"a.php": "<?php\nextract($_GET, EXTR_PREFIX_ALL, 'p');\ninclude __DIR__ . '/pages/' . $p_view;\n"},
			"a.php", "php-path-traversal-file-include", 3, true},
		{"EXTR_PREFIX_SAME defines a name not defined before",
			map[string]string{"a.php": "<?php\nextract($_GET, EXTR_PREFIX_SAME, 'p');\ninclude __DIR__ . '/pages/' . $view;\n"},
			"a.php", "php-path-traversal-file-include", 3, true},
		{"a closure's use (...) variable holds what extract() set",
			map[string]string{"a.php": "<?php\nextract($_GET);\n$f = function () use ($view) { include __DIR__ . '/v/' . $view; };\n$f();\n"},
			"a.php", "php-path-traversal-file-include", 3, true},
		{"a key named 'defaults' in written-out defaults is set (review X20)",
			map[string]string{"a.php": "<?php\nadd_shortcode('s', 's_cb');\nfunction s_cb($atts) {\n    $defaults = array('defaults' => 'a.php');\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $defaults;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, true},
		// counterexamples: hold before and after
		{"EXTR_PREFIX_ALL with a prefix not written out may define any prefix_key (review S-261-4)",
			map[string]string{"a.php": "<?php\nextract($_GET, EXTR_PREFIX_ALL, $px);\ninclude __DIR__ . '/v/' . $p_view;\n"},
			"a.php", "php-path-traversal-file-include", 3, true},
		{"preg_match writing its own subject keeps the input (review S-261-7)",
			map[string]string{"a.php": "<?php\n$m = $_GET['x'];\npreg_match('/(.*)/', $m, $m);\ninclude __DIR__ . '/v/' . $m[1];\n"},
			"a.php", "php-path-traversal-file-include", 4, true},
		{"parse_str writing its own subject keeps the input (review S-261-7)",
			map[string]string{"a.php": "<?php\n$q = $_GET['q'];\nparse_str($q, $q);\ninclude __DIR__ . '/v/' . $q['f'];\n"},
			"a.php", "php-path-traversal-file-include", 4, true},
		{"usc-e-shop shape: preg_match of another variable rewrites $cf, then esc_sql in quotes (review S-261-7)",
			map[string]string{"a.php": "<?php\nfunction up() {\n    global $wpdb;\n    $row = $_POST['cf'];\n    $cf = explode('=', $row);\n    preg_match('/^([^=]+)=(.*)$/', $row, $cf);\n    $wpdb->query(\"INSERT INTO t VALUES ('\" . esc_sql($cf[1]) . \"')\");\n}\nup();\n"},
			"a.php", "php-sqli-wpdb-unprepared", 7, false},
		{"another function before it gives $defaults other keys (review N-261-4, L12)",
			map[string]string{"a.php": "<?php\nfunction g() { $defaults = array('tpl' => 1); return $defaults; }\nadd_shortcode('s', 's_cb');\nfunction s_cb($atts) {\n    $defaults = array('id' => 0);\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $tpl;\n}\n"},
			"a.php", "php-path-traversal-file-include", 7, false},
		{"another function after it gives $defaults other keys (review N-261-4, L13)",
			map[string]string{"a.php": "<?php\nadd_shortcode('s', 's_cb');\nfunction s_cb($atts) {\n    $defaults = array('id' => 0);\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $tpl;\n}\nfunction g() { $defaults = array('tpl' => 1); return $defaults; }\n"},
			"a.php", "php-path-traversal-file-include", 6, false},
		{"the file's top level gives $defaults other keys (review N-261-4, R1)",
			map[string]string{"a.php": "<?php\n$defaults = array('tpl' => 1);\nadd_shortcode('s', 's_cb');\nfunction s_cb($atts) {\n    $defaults = array('id' => 0);\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $tpl;\n}\n"},
			"a.php", "php-path-traversal-file-include", 7, false},
		{"a named function inside a function that gives $defaults other keys (review N-261-4, R5)",
			map[string]string{"a.php": "<?php\nfunction setup() {\n    $defaults = array('tpl' => 1);\n    if (!function_exists('s_cb')) {\n        function s_cb($atts) {\n            $defaults = array('id' => 0);\n            extract(shortcode_atts($defaults, $atts));\n            include __DIR__ . '/v/' . $tpl;\n        }\n    }\n    add_shortcode('s', 's_cb');\n}\n"},
			"a.php", "php-path-traversal-file-include", 8, false},
		{"another function before it: a variable assigned before extract() keeps its value (review N-261-4, L14)",
			map[string]string{"a.php": "<?php\nfunction g() { $defaults = array('x' => 1); return $defaults; }\nadd_shortcode('s', 's_cb');\nfunction s_cb($atts) {\n    $table = 'wp_posts';\n    $defaults = array('id' => 0);\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $table;\n}\n"},
			"a.php", "php-path-traversal-file-include", 8, false},
		{"EXTR_IF_EXISTS creates no variable (review X2)",
			map[string]string{"a.php": "<?php\nextract($_GET, EXTR_IF_EXISTS);\ninclude __DIR__ . '/pages/' . $view;\n"},
			"a.php", "php-path-traversal-file-include", 3, false},
		{"EXTR_PREFIX_ALL sets no unprefixed name (review X3)",
			map[string]string{"a.php": "<?php\nextract($_GET, EXTR_PREFIX_ALL, 'p');\ninclude __DIR__ . '/pages/' . $view;\n"},
			"a.php", "php-path-traversal-file-include", 3, false},
		{"EXTR_PREFIX_IF_EXISTS overwrites nothing and creates no unprefixed name",
			map[string]string{"a.php": "<?php\n$page = 'home.php';\nextract($_GET, EXTR_PREFIX_IF_EXISTS, 'p');\ninclude __DIR__ . '/pages/' . $page . $view;\n"},
			"a.php", "php-path-traversal-file-include", 4, false},
		{"$defaults = apply_filters(..., array(...)) is still left as it was (review N-261-2)",
			map[string]string{"a.php": "<?php\nadd_shortcode('h', 'h_cb');\nfunction h_cb($atts) {\n    global $wpdb;\n    $defaults = apply_filters('h_defaults', array('orderby' => 'modified'));\n    $r = shortcode_atts($defaults, $atts);\n    extract($r);\n    $orderby = in_array($orderby, array('modified', 'id')) ? $orderby : $defaults['orderby'];\n    return $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . esc_sql($orderby));\n}\n"},
			"a.php", "php-sqli-orderby-identifier", 9, false},
		{"$defaults = get_option(...) is still left as it was (review N-261-2)",
			map[string]string{"a.php": "<?php\nadd_shortcode('h', 'h_cb');\nfunction h_cb($atts) {\n    global $wpdb;\n    $defaults = get_option('h_defaults');\n    $r = shortcode_atts($defaults, $atts);\n    extract($r);\n    $orderby = in_array($orderby, array('modified', 'id')) ? $orderby : $defaults['orderby'];\n    return $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . esc_sql($orderby));\n}\n"},
			"a.php", "php-sqli-orderby-identifier", 9, false},
		{"$defaults = $this->defaults() is still left as it was (review N-261-2)",
			map[string]string{"a.php": "<?php\nclass H {\n  function init() { add_shortcode('h', array($this, 'h')); }\n  function h($atts) {\n    global $wpdb;\n    $defaults = $this->defaults();\n    extract(shortcode_atts($defaults, $atts));\n    $orderby = in_array($orderby, array('modified', 'id')) ? $orderby : $defaults['orderby'];\n    return $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . esc_sql($orderby));\n  }\n}\n"},
			"a.php", "php-sqli-orderby-identifier", 9, false},
		{"$defaults read straight after extract() (review Y1)",
			map[string]string{"a.php": "<?php\nadd_shortcode('h', 'h_cb');\nfunction h_cb($atts) {\n    $defaults = get_option('h_defaults');\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/v/' . $defaults;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, false},
		{"a closure's parameter is the caller's value (review Y5)",
			map[string]string{"a.php": "<?php\nextract($_GET);\n$f = function ($view) { include __DIR__ . '/v/' . $view; };\n$f('a.php');\n"},
			"a.php", "php-path-traversal-file-include", 3, false},
		{"a closure without use sees no variable extract() set (review X11)",
			map[string]string{"a.php": "<?php\nextract($_GET);\n$f = function () { include __DIR__ . '/v/' . $view; };\n$f();\n"},
			"a.php", "php-path-traversal-file-include", 3, false},
		{"an arrow function's parameter is the caller's value",
			map[string]string{"a.php": "<?php\nextract($_GET);\n$f = fn ($cb) => call_user_func($cb);\n$f('trim');\n"},
			"a.php", "php-code-eval-dynamic-callback", 3, false},
		{"preg_match's $m after extract() is what the call set (review X22)",
			map[string]string{"a.php": "<?php\nextract($_GET);\nif (preg_match('/^(a|b)$/', 'a', $m)) {\n    include __DIR__ . '/v/' . $m[1];\n}\n"},
			"a.php", "php-path-traversal-file-include", 4, false},
		{"parse_str's output after extract() is what the call set (review Y7)",
			map[string]string{"a.php": "<?php\nextract($_GET);\nparse_str('v=a.php', $out);\ninclude __DIR__ . '/v/' . $out['v'];\n"},
			"a.php", "php-path-traversal-file-include", 4, false},
		{"a catch variable is the exception (review X26)",
			map[string]string{"a.php": "<?php\nextract($_GET);\ntry {\n    run();\n} catch (Exception $e) {\n    include __DIR__ . '/v/' . $e;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, false},
		{"$r = shortcode_atts($defaults, $atts); extract($r) leaves $defaults (newsletters-lite history())",
			map[string]string{"a.php": "<?php\nadd_shortcode('h', 'h_cb');\nfunction h_cb($atts) {\n    global $wpdb;\n    $defaults = array('orderby' => 'modified', 'order' => 'DESC');\n    $r = shortcode_atts($defaults, $atts);\n    extract($r);\n    $orderby = in_array($orderby, array('modified', 'id')) ? $orderby : $defaults['orderby'];\n    return $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . esc_sql($orderby));\n}\n"},
			"a.php", "php-sqli-orderby-identifier", 9, false},
		{"$defaults given another array elsewhere in the file: extract($r) still leaves $defaults (newsletters-lite helpers/shortcode.php:1186)",
			map[string]string{"a.php": "<?php\nadd_shortcode('t', 't_cb');\nfunction t_cb($atts) {\n    $defaults = array('id' => false);\n    extract(shortcode_atts($defaults, $atts));\n    return (int) $id;\n}\nadd_shortcode('h', 'h_cb');\nfunction h_cb($atts) {\n    global $wpdb;\n    $defaults = array('orderby' => 'modified', 'order' => 'DESC');\n    $r = shortcode_atts($defaults, $atts);\n    extract($r);\n    $orderby = in_array($orderby, array('modified', 'id')) ? $orderby : $defaults['orderby'];\n    return $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . esc_sql($orderby));\n}\n"},
			"a.php", "php-sqli-orderby-identifier", 15, false},
		{"shortcode_atts of a defaults variable: a name not among its keys is not set",
			map[string]string{"a.php": "<?php\nadd_shortcode('show', 'show_cb');\nfunction show_cb($atts) {\n    $view = 'list.php';\n    $defaults = array('id' => 0);\n    extract(shortcode_atts($defaults, $atts));\n    include __DIR__ . '/views/' . $view;\n}\n"},
			"a.php", "php-path-traversal-file-include", 7, false},
		{"a property of a global object after extract() (motors shape): input sets no object",
			map[string]string{"a.php": "<?php\nfunction t($vars) {\n    global $wpdb;\n    extract($vars);\n    $wpdb->get_results(\"SELECT ID FROM {$wpdb->prefix}posts WHERE post_status = 'publish'\");\n}\nt($_GET);\n"},
			"a.php", "php-sqli-wpdb-unprepared", 5, false},
		{"a property of a variable extract() may have defined",
			map[string]string{"a.php": "<?php\nfunction t($vars) {\n    global $wpdb;\n    extract($vars);\n    $wpdb->get_results(\"SELECT * FROM \" . $tbl->name);\n}\nt($_GET);\n"},
			"a.php", "php-sqli-wpdb-unprepared", 5, false},
		{"EXTR_SKIP keeps a variable defined before",
			map[string]string{"a.php": "<?php\nfunction t($args) {\n    $name = 'a.php';\n    extract($args, EXTR_SKIP);\n    include __DIR__ . '/t/' . $name;\n}\nt($_GET);\n"},
			"a.php", "php-path-traversal-file-include", 5, false},
		{"a variable assigned after extract() holds what it was given",
			map[string]string{"a.php": "<?php\nextract($_GET);\n$page = 'home.php';\ninclude __DIR__ . '/pages/' . $page;\n"},
			"a.php", "php-path-traversal-file-include", 4, false},
		{"extract() of a clean array",
			map[string]string{"a.php": "<?php\n$cfg = array('page' => 'home.php');\nextract($cfg);\ninclude __DIR__ . '/pages/' . $page;\n"},
			"a.php", "php-path-traversal-file-include", 4, false},
		{"shortcode_atts keeps the default keys only",
			map[string]string{"a.php": "<?php\nadd_shortcode('show', 'show_cb');\nfunction show_cb($atts) {\n    $view = 'list.php';\n    extract(shortcode_atts(array('id' => 0), $atts));\n    include __DIR__ . '/views/' . $view;\n}\n"},
			"a.php", "php-path-traversal-file-include", 6, false},
		{"a number cast after extract()",
			map[string]string{"a.php": "<?php\nextract(wp_parse_args($_GET, array('id' => 0)));\n$id = (int) $id;\n$wpdb->get_results(\"SELECT * FROM t WHERE id = \" . $id);\n"},
			"a.php", "php-sqli-wpdb-unprepared", 4, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var paths []string
			for p := range c.files {
				paths = append(paths, p)
			}
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(c.files[p]), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, p := range paths {
				for _, f := range auditPath(t, e, pr, p, []byte(c.files[p])) {
					all = append(all, f.Path+":"+strconv.Itoa(f.Line)+" "+f.RuleID)
					got = got || f.RuleID == c.rule && f.Line == c.line && (len(c.files) == 1 || f.Path != c.scan)
				}
			}
			if got != c.want {
				t.Errorf("%s at line %d: reported %v, want %v; all: %v", c.rule, c.line, got, c.want, all)
			}
		})
	}
}
