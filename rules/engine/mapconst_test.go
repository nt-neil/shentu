package engine

import "testing"

// A placeholder list built by array_map with a callback returning a constant
// (fn($v) => '%d') holds no input: the prepare() format stays fixed. A
// callback returning its argument, or a string holding it, still passes the
// input on.
func TestMapConstCallback(t *testing.T) {
	e := engineForTest(t)
	q := func(cb string) string {
		return "<?php\nglobal $wpdb;\n$ids = $_GET['ids'];\n$in = implode(',', array_map(" + cb + ", $ids));\n" +
			"$wpdb->get_results($wpdb->prepare(\"SELECT * FROM t WHERE id IN ($in)\", $ids));\n"
	}
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"fn returning '%d'", q("fn($v) => '%d'"), false},
		{"function returning '%s'", q("function ($v) { return '%s'; }"), false},
		{"fn returning its argument", q("fn($v) => $v"), true},
		{"fn returning a string with it", q("fn($v) => \"'$v'\""), true},
		{"function doing more", q("function ($v) { log_it($v); return '%d'; }"), true},
	} {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		if err != nil || (len(fs) > 0) != c.want {
			t.Errorf("%s: %v (err %v), want reported %v", c.name, fs, err, c.want)
		}
	}
}
