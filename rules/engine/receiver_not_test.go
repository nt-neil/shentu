package engine

import "testing"

// php-sqli-string-concat's ->query( does not count on WordPress's query
// classes (an arguments array, the SQL built and escaped by WordPress), made
// in place or assigned to the name; it still counts on $wpdb, on a receiver
// the file says nothing about, and on a name the file binds any other way.
func TestNotReceiver(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"new WP_Query in place", "<?php\n$r = (new WP_Query($args))->query(array('s' => $_GET['x']));\n", false},
		{"assigned WP_Query", "<?php\n$q = new WP_Query;\n$r = $q->query(array('s' => $_GET['x']));\n", false},
		{"namespaced", "<?php\n$q = new \\WP_Comment_Query();\n$r = $q->query(array('search' => $_GET['x']));\n", false},
		{"$wpdb", "<?php\nglobal $wpdb;\n$wpdb->query(\"DELETE FROM t WHERE id = \" . $_GET['x']);\n", true},
		{"receiver of unknown type", "<?php\nfunction f($db, $sql) {\n\treturn $db->query($sql . $_GET['x']);\n}\n", true},
		{"assigned a query class and something else", "<?php\n$q = new WP_Query;\nif ($raw) { $q = $db; }\n$q->query('SELECT ' . $_GET['x']);\n", true},
		// Not surely a query class: each of these may be a database connection.
		{"ternary naming $wpdb", "<?php\nglobal $wpdb;\n$q = $c ? $wpdb : new WP_Query;\n$wpdb->query('DELETE FROM t WHERE id = ' . $_GET['x']);\n", true},
		{"parameter of the same name", "<?php\n$q = new WP_Query;\nfunction f($q) {\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"global of the same name", "<?php\n$q = new WP_Query;\nfunction f() {\n\tglobal $q;\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"foreach as", "<?php\n$q = new WP_Query;\nforeach ($dbs as $q) { $q->query('SELECT ' . $_GET['x']); }\n", true},
		{"a member of the object", "<?php\n$q = new WP_Query();\n$q->db->query('SELECT ' . $_GET['x']);\n", true},
		{"new of a member", "<?php\n$r = (new WP_Query())->db->query('SELECT ' . $_GET['x']);\n", true},
		{"a class of a longer name", "<?php\n$q = new WP_QueryX;\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"a class under its namespace", "<?php\n$q = new WP_Query\\Db;\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"by reference", "<?php\n$q = new WP_Query;\n$q = &$db;\n$q->query('SELECT ' . $_GET['x']);\n", true},
	} {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		got := false
		for _, f := range fs {
			if f.RuleID == "php-sqli-string-concat" {
				got = true
			}
		}
		if err != nil || got != c.want {
			t.Errorf("%s: reported %v (err %v), want %v", c.name, got, err, c.want)
		}
	}
}
