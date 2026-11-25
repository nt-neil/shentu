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
		// counterexamples: hold before and after
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
