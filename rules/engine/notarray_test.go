package engine

import (
	"strconv"
	"testing"
)

// maybe_unserialize() unserializes strings only: given an array it returns it
// as is, so an argument that is an array on every path is not reported
// (not_array, v0.5.8 v058-array-fp-cheap). One value of it, a string made from
// it, or a path that gives a string still is.
func TestNotArrayMaybeUnserialize(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-deserialization-wp-maybe-unserialize"
	wrap := func(body string) string {
		return "<?php\nadd_action('wp_ajax_x', function () {\n" + body + "\n});\n"
	}
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"the input itself", "$c = maybe_unserialize(wp_unslash($_POST['c']));", true},
		{"array() of it", "$a = array('k' => $_POST['c']);\nmaybe_unserialize($a);", false},
		{"[...] of it, inline", "maybe_unserialize([$_POST['c']]);", false},
		{"written by key", "$a = [];\n$a['k'] = $_POST['c'];\nmaybe_unserialize($a);", false},
		{"written by key, one value of it", "$a = [];\n$a['k'] = $_POST['c'];\nmaybe_unserialize($a['k']);", true},
		{"appended", "$a = [];\n$a[] = $_POST['c'];\nmaybe_unserialize($a);", false},
		{"explode()", "$a = explode(',', $_POST['c']);\nmaybe_unserialize($a);", false},
		{"explode(), one value of it", "$a = explode(',', $_POST['c']);\nmaybe_unserialize($a[0]);", true},
		{"(array) cast", "$a = (array) $_POST['c'];\nmaybe_unserialize($a);", false},
		{"(string) cast of an array", "$a = (string) array($_POST['c']);\nmaybe_unserialize($a);", true},
		{"foreach over an array", "foreach (array($_POST['c']) as $v) {\n  maybe_unserialize($v);\n}", true},
		{"list() of an array", "list($x) = array($_POST['c']);\nmaybe_unserialize($x);", true},
		{"[...] destructuring", "[$x] = [$_POST['c']];\nmaybe_unserialize($x);", true},
		{"implode() of an array", "$a = array($_POST['c']);\nmaybe_unserialize(implode(',', $a));", true},
		{"concatenated", "$a = array($_POST['c']);\nmaybe_unserialize($a . '');", true},
		{"ternary, a string on one side", "$a = isset($_POST['x']) ? array($_POST['c']) : $_POST['c'];\nmaybe_unserialize($a);", true},
		{"ternary, arrays on both sides", "$a = isset($_POST['x']) ? array($_POST['c']) : explode(',', $_POST['c']);\nmaybe_unserialize($a);", false},
		{"if/else, a string on one path", "if (isset($_POST['x'])) {\n  $a = array($_POST['c']);\n} else {\n  $a = $_POST['c'];\n}\nmaybe_unserialize($a);", true},
		{"a string written by key", "$a = $_POST['c'];\n$a['k'] = 1;\nmaybe_unserialize($a);", true},
		{"appended to as a string", "$a = array($_POST['c']);\n$a .= 'x';\nmaybe_unserialize($a);", true},
		{"replaced by one value", "$a = array($_POST['c']);\n$a = $a[0];\nmaybe_unserialize($a);", true},
		{"array_pop() of an array", "$a = array_pop(explode(',', $_POST['c']));\nmaybe_unserialize($a);", true},
		{"current() of an array", "$a = current(array($_POST['c']));\nmaybe_unserialize($a);", true},
		{"apply_filters() of an array", "$a = apply_filters('x', array($_POST['c']));\nmaybe_unserialize($a);", true},
		{"written by key, then given a string", "$a = [];\n$a[] = $_POST['c'];\n$a = $_POST['s'];\nmaybe_unserialize($a);", true},
		{"a reference, then a string through it", "$a = array($_POST['c']);\n$r = &$a;\n$r = $_POST['s'];\nmaybe_unserialize($a);", true},
		{"a by-reference parameter", "function set_s(&$x) {\n  $x = $_POST['s'];\n}\n$a = array($_POST['c']);\nset_s($a);\nmaybe_unserialize($a);", true},
		{"extract() after it", "$a = array($_POST['c']);\nextract($_POST);\nmaybe_unserialize($a);", true},
		{"array_map()", "$a = array_map('trim', $_POST['c']);\nmaybe_unserialize($a);", false},
		{"array_map() callback of an array", "array_map(function ($x) {\n  return maybe_unserialize($x);\n}, explode(',', $_POST['c']));", true},
		{"array_walk() callback of an array", "$a = [$_POST['c']];\narray_walk($a, function ($x) {\n  maybe_unserialize($x);\n});", true},
		{"spread into the sink", "maybe_unserialize(...[$_POST['c']]);", true},
		{"a property of an array's value", "$a = array($_POST['c']);\nmaybe_unserialize($a->c);", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := wrap(c.body)
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(src), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", []byte(src))) {
				all = append(all, strconv.Itoa(f.Line)+" "+f.RuleID)
				got = got || f.RuleID == rule
			}
			if got != c.want {
				t.Errorf("%s reported: %v, want %v; all: %v", rule, got, c.want, all)
			}
		})
	}
}

// The same across functions and files: a callee whose maybe_unserialize()
// takes its parameter as is (sinkArr) is not reached by an array, and is by a
// string, one value of the array, or what the callee makes of it.
func TestNotArrayAcrossFiles(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-deserialization-wp-maybe-unserialize"
	lib := "<?php\nfunction m($p) {\n  return maybe_unserialize($p);\n}\nfunction m0($p) {\n  return maybe_unserialize($p[0]);\n}\nfunction mj($p) {\n  $x = implode(',', $p);\n  return maybe_unserialize($x);\n}\n"
	for _, c := range []struct {
		name, caller, at string
		want             bool
	}{
		{"a string", "m($_POST['c']);", "lib.php:3", true},
		{"array()", "m(array($_POST['c']));", "lib.php:3", false},
		{"an array written by key", "$a = [];\n$a['k'] = $_POST['c'];\nm($a);", "lib.php:3", false},
		{"explode()", "m(explode(',', $_POST['c']));", "lib.php:3", false},
		{"the callee reads one value", "m0(array($_POST['c']));", "lib.php:6", true},
		{"the callee makes a string of it", "mj(array($_POST['c']));", "lib.php:10", true},
		{"spread into the callee", "m(...array($_POST['c']));", "lib.php:3", true},
		{"an array on one path only", "$a = isset($_POST['x']) ? array($_POST['c']) : $_POST['c'];\nm($a);", "lib.php:3", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{
				"a.php":   "<?php\nrequire 'lib.php';\nadd_action('wp_ajax_x', function () {\n" + c.caller + "\n});\n",
				"lib.php": lib,
			}
			paths := []string{"a.php", "lib.php"}
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, p := range paths {
				for _, f := range taintOnly(auditPath(t, e, pr, p, []byte(files[p]))) {
					at := f.Path + ":" + strconv.Itoa(f.Line)
					all = append(all, at+" "+f.RuleID)
					got = got || at == c.at && f.RuleID == rule
				}
			}
			if got != c.want {
				t.Errorf("%s at %s: %v, want %v; all: %v", rule, c.at, got, c.want, all)
			}
		})
	}
}
