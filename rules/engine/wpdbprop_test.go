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
		{"another class of the file gives its db property a PDO (review X2)",
			map[string]string{"a.php": "<?php\nclass A {\n  function __construct() { global $wpdb; $this->db = $wpdb; }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\nclass B {\n  function __construct() { $this->db = new PDO('sqlite::memory:'); }\n}\n"},
			"a.php", 4, true},
		{"another class of the file gives its db property $wpdb (review X3)",
			map[string]string{"a.php": "<?php\nclass A {\n  function __construct() { global $wpdb; $this->db = $wpdb; }\n}\nclass B extends Other {\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 6, false},
		{"another class's $wpdb does not move ->query to the wpdb rule (review X4)",
			map[string]string{"a.php": "<?php\nclass A {\n  function __construct() { global $wpdb; $this->db = $wpdb; }\n}\nclass B extends Other {\n  function rows() { return $this->db->query(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 6, false},
		{"static properties of two classes (review X5)",
			map[string]string{"a.php": "<?php\nclass A {\n  static $db;\n  static function init() { global $wpdb; self::$db =& $wpdb; }\n  static function rows() { return self::$db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\nclass B {\n  static $db;\n  static function init() { self::$db = new PDO('sqlite::memory:'); }\n}\n"},
			"a.php", 5, true},
		{"a trait of the file the class uses gives it $wpdb (review T2)",
			map[string]string{"a.php": "<?php\ntrait HasDb {\n  function init_db() { global $wpdb; $this->db = $wpdb; }\n}\nclass Repo {\n  use HasDb;\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 7, true},
		{"a class of 70 traits, one of the file giving $wpdb",
			map[string]string{"a.php": "<?php\ntrait HasDb {\n  function init_db() { global $wpdb; $this->db = $wpdb; }\n}\nclass Repo {\n  use U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16, U17, U18, U19, U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, U32, U33, U34, U35, U36, U37, U38, U39, U40, U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51, U52, U53, U54, U55, U56, U57, U58, U59, U60, U61, U62, U63, U64, U65, U66, U67, U68, U69, HasDb;\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 7, true},
		{"self:: assigns, static:: queries (review T4)",
			map[string]string{"a.php": "<?php\nclass D {\n  static $db;\n  static function init() { global $wpdb; self::$db = $wpdb; }\n  static function rows() { return static::$db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 5, true},
		{"also given another value by destructuring (review C4)",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct($pdo) { global $wpdb; $this->db = $wpdb; [$this->db] = [$pdo]; }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 4, false},
		{"also given another value by list() (review C5)",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct($a) { global $wpdb; $this->db = $wpdb; list($x, $this->db) = $a; }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 4, false},
		{"also written through a reference (review C6)",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct($pdo) { global $wpdb; $this->db = $wpdb; $r = &$this->db; $r = $pdo; }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 4, false},
		{"also a foreach target (review C10)",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct($xs) { global $wpdb; $this->db = $wpdb; foreach ($xs as $this->db) {} }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 4, false},
		{"the property as an index is read, not written",
			map[string]string{"a.php": "<?php\nclass M {\n  function __construct() { global $wpdb; $this->db = $wpdb; $seen[$this->db] = 1; }\n  function rows() { return $this->db->get_results(\"SELECT * FROM t WHERE id = \" . $_GET['id']); }\n}\n"},
			"a.php", 4, true},
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
