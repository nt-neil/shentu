package engine

import (
	"strconv"
	"testing"
)

// $wpdb kept in a property ($this->x = $wpdb, self::$x =& $wpdb) is $wpdb
// wherever the file uses that property as an object; only an assignment the
// file shows counts, never the property's name (wpdbProps).
func TestWpdbProperty(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-sqli-wpdb-unprepared"
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
		line  int
		want  bool
	}{
		{"$this->wpdb = $wpdb (mp-timetable, notificationx shape)",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct() { global $wpdb; $this->wpdb = $wpdb; }\n  function rows() {\n    return $this->wpdb->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n  }\n}\n"},
			"a.php", 5, true},
		{"self::$mysqli =& $wpdb (wp-easycart shape)",
			map[string]string{"a.php": "<?php\nclass D {\n  protected static $mysqli;\n  function __construct() { global $wpdb; self::$mysqli =& $wpdb; }\n  function rows() {\n    return self::$mysqli->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n  }\n}\n"},
			"a.php", 6, true},
		{"$this->db = &$wpdb",
			map[string]string{"a.php": "<?php\nclass R {\n  function __construct() { global $wpdb; $this->db = &$wpdb; }\n  function one() {\n    return $this->db->get_var(\"SELECT n FROM t WHERE id = \" . $_POST['id']);\n  }\n}\n"},
			"a.php", 5, true},
		{"called from another file with request input",
			map[string]string{
				"a.php": "<?php\nrequire 'b.php';\n$e = new Events();\n$e->data($_GET['ids']);\n",
				"b.php": "<?php\nclass Events {\n  function __construct() { global $wpdb; $this->wpdb = $wpdb; }\n  function data($ids) {\n    return $this->wpdb->get_results(\"SELECT * FROM t WHERE id IN (\" . $ids . \")\");\n  }\n}\n"},
			"a.php", 5, true},
		{"prepare() through the property is still a sanitizer",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct() { global $wpdb; $this->wpdb = $wpdb; }\n  function rows() {\n    return $this->wpdb->get_results($this->wpdb->prepare(\"SELECT * FROM t WHERE id = %d\", $_GET['id']));\n  }\n}\n"},
			"a.php", 5, false},
		{"a property named wpdb the file never gives $wpdb",
			map[string]string{"a.php": "<?php\nclass M {\n  function rows() {\n    return $this->wpdb->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n  }\n}\n"},
			"a.php", 4, false},
		{"a property also given another object",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct($db = null) { global $wpdb; $this->db = $wpdb; if ($db) { $this->db = $db; } }\n  function rows() {\n    return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n  }\n}\n"},
			"a.php", 5, false},
		{"a property given $wpdb in a parent class's file is not seen",
			map[string]string{
				"base.php": "<?php\nclass Base {\n  function __construct() { global $wpdb; $this->db = $wpdb; }\n}\n",
				"a.php":    "<?php\nrequire 'base.php';\nclass Repo extends Base {\n  function rows() {\n    return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n  }\n}\n"},
			"a.php", 5, false},
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
					got = got || f.RuleID == rule && f.Line == c.line && (len(c.files) == 1 || f.Path != c.scan)
				}
			}
			if got != c.want {
				t.Errorf("%s at line %d: reported %v, want %v; all: %v", rule, c.line, got, c.want, all)
			}
		})
	}
}
