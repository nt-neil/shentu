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
		{"also passed to a call", "<?php\n$q = new WP_Query();\n$r = $q->query(array('s' => $_GET['x']));\nupdate_post_thumbnail_cache($q);\n$this->log($q, 1);\n", false},
		// Not surely a query class: each of these may be a database connection.
		{"ternary naming $wpdb", "<?php\nglobal $wpdb;\n$q = $c ? $wpdb : new WP_Query;\n$wpdb->query('DELETE FROM t WHERE id = ' . $_GET['x']);\n", true},
		{"parameter of the same name", "<?php\n$q = new WP_Query;\nfunction f($q) {\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"global of the same name", "<?php\n$q = new WP_Query;\nfunction f() {\n\tglobal $q;\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"foreach as", "<?php\n$q = new WP_Query;\nforeach ($dbs as $q) { $q->query('SELECT ' . $_GET['x']); }\n", true},
		{"a member of the object", "<?php\n$q = new WP_Query();\n$q->db->query('SELECT ' . $_GET['x']);\n", true},
		{"new of a member", "<?php\n$r = (new WP_Query())->db->query('SELECT ' . $_GET['x']);\n", true},
		{"a class of a longer name", "<?php\n$q = new WP_QueryX;\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"a class under its namespace", "<?php\n$q = new WP_Query\\Db;\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"passed to a function of the file taking it by reference", "<?php\nfunction swap(&$x) { global $db; $x = $db; }\n$q = new WP_Query();\nswap($q);\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"passed to a method of the file taking it by reference", "<?php\nclass C { function pick($a, &$x) { $x = $a; } }\n$q = new WP_Query();\n$c->pick($db, $q);\n$q->query('SELECT ' . $_GET['x']);\n", true},
		{"closure use of the same name", "<?php\n$q = new WP_Query;\n$f = function () use ($q) { return 1; };\nfunction g($db) { $q = $db; return $q->query('SELECT ' . $_GET['x']); }\n", true},
		{"a parameter declared by reference", "<?php\n$q = new WP_Query;\nfunction g(&$q) {\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"a parameter's default value", "<?php\nfunction run($q = new WP_Query()) {\n\treturn $q->query('SELECT ' . $_GET['x']);\n}\n", true},
		{"assigned from another name", "<?php\n$a = new WP_Query;\n$q = $a;\n$q->query('SELECT ' . $_GET['x']);\n", true},
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

// A function using a query class, reached from a caller in another file: the
// callee's file says what $q is, in either order of the files and on its own.
func TestNotReceiverAcrossFiles(t *testing.T) {
	files := map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nb_run($_GET['x']);\n",
		"b.php": "<?php\nfunction b_run($v) {\n\t$q = new WP_Query;\n\treturn $q->query(\"s=\" . $v);\n}\n",
	}
	count := func(fs []Finding) int {
		n := 0
		for _, f := range fs {
			if f.RuleID == "php-sqli-string-concat" {
				n++
			}
		}
		return n
	}
	e := engineForTest(t)
	if fs, _ := e.Scan("php", "b.php", []byte(files["b.php"])); count(fs) != 0 {
		t.Errorf("b.php on its own: %v", fs)
	}
	for _, order := range [][]string{{"a.php", "b.php"}, {"b.php", "a.php"}} {
		e := engineForTest(t)
		pr := e.NewProject(order, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
		n := 0
		for _, p := range order {
			fs, _ := pr.ScanCalls(p, []byte(files[p]))
			n += count(fs)
		}
		if n != 0 {
			t.Errorf("order %v: %d reports, want none", order, n)
		}
	}
	// The same flow into $wpdb is still followed across the files.
	files["b.php"] = "<?php\nfunction b_run($v) {\n\tglobal $wpdb;\n\treturn $wpdb->query(\"s=\" . $v);\n}\n"
	e = engineForTest(t)
	pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	n := 0
	for _, p := range []string{"a.php", "b.php"} {
		fs, _ := pr.ScanCalls(p, []byte(files[p]))
		n += count(fs)
	}
	if n == 0 {
		t.Error("$wpdb->query across files: not reported")
	}
}
