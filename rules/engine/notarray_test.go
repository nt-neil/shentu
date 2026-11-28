package engine

import (
	"strconv"
	"strings"
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

// An array the analysis cannot follow every write of is not trusted
// (N-284-1): a global another file's function writes, a $$name or ${...}, a
// method or a function of another file that takes it by reference. Each is a
// string by the time maybe_unserialize() reads it.
func TestNotArrayUnseenWrites(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-deserialization-wp-maybe-unserialize"
	ajax := func(body string) string {
		return "<?php\nrequire 'lib.php';\nadd_action('wp_ajax_x', function () {\n" + body + "\n});\n"
	}
	lib := "<?php\nfunction set_x() {\n  global $x;\n  $x = $_POST['b'];\n}\n" +
		"function fill2(&$v) {\n  $v = $_POST['b'];\n}\n" +
		"function keep($v) {\n  return count($v);\n}\n" +
		"function m($p) {\n  return maybe_unserialize($p);\n}\n" +
		"class Helper {\n  static function fill(&$v) {\n    $v = $_POST['b'];\n  }\n  function put(&$v) {\n    $v = $_POST['b'];\n  }\n}\n"
	for _, c := range []struct {
		name, a, at string
		want        bool
	}{
		{"B1 a global another file's function writes", "<?php\nrequire 'lib.php';\n$x = [$_POST['a']];\nset_x();\nmaybe_unserialize($x);\n", "a.php:5", true},
		{"B1 a global declared in the closure", ajax("global $x;\n$x = [$_POST['a']];\nset_x();\nmaybe_unserialize($x);"), "a.php:7", true},
		{"B2 $GLOBALS written", "<?php\nrequire 'lib.php';\nfunction g() {\n  $GLOBALS['x'] = $_POST['b'];\n}\n$x = [$_POST['a']];\ng();\nmaybe_unserialize($x);\n", "a.php:8", true},
		{"B3 a static method of another file", ajax("$x = [$_POST['a']];\nHelper::fill($x);\nmaybe_unserialize($x);"), "a.php:6", true},
		{"B4 a method of another file", ajax("$x = [$_POST['a']];\n$h = new Helper();\n$h->put($x);\nmaybe_unserialize($x);"), "a.php:7", true},
		{"B5 a function of another file", ajax("$x = [$_POST['a']];\nfill2($x);\nmaybe_unserialize($x);"), "a.php:6", true},
		{"B6 $$k", ajax("$x = [$_POST['a']];\n$k = 'x';\n$$k = $_POST['b'];\nmaybe_unserialize($x);"), "a.php:7", true},
		{"B7 ${'x'}", ajax("$x = [$_POST['a']];\n${'x'} = $_POST['b'];\nmaybe_unserialize($x);"), "a.php:6", true},
		{"a function of another file by reference, the sink there too", ajax("$x = [$_POST['a']];\nfill2($x);\nm($x);"), "lib.php:13", true},
		{"settype()", ajax("$x = [$_POST['a']];\nsettype($x, 'string');\nmaybe_unserialize($x);"), "a.php:6", true},
		{"a computed callee", ajax("$x = [$_POST['a']];\n$f = 'fill2';\n$f($x);\nmaybe_unserialize($x);"), "a.php:7", true},
		{"a function of another file by value, the sink there", ajax("$x = [$_POST['a']];\nkeep($x);\nm($x);"), "lib.php:13", false},
		{"count() and is_array() read it", ajax("$x = [$_POST['a']];\nif (is_array($x) && count($x)) {\n  maybe_unserialize($x);\n}"), "a.php:7", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": c.a, "lib.php": lib}
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

// The file scanned on its own (ScanTimed, no project) cannot read another
// file's function, so passing the array to one this file does not declare
// keeps maybe_unserialize() reported there: the pass that follows calls may
// be cut, or not reach the file.
func TestNotArrayFileAlone(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-deserialization-wp-maybe-unserialize"
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"a function no file here declares", "$x = [$_POST['a']];\nfill2($x);\nmaybe_unserialize($x);", true},
		{"a PHP function that takes it by value", "$x = [$_POST['a']];\ncount($x);\nmaybe_unserialize($x);", false},
		{"a function of this file by value", "$x = [$_POST['a']];\nkeep($x);\nmaybe_unserialize($x);\n}\nfunction keep($v) {\n  return 1;", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "<?php\nadd_action('wp_ajax_x', function () {\n" + c.body + "\n});\n"
			if strings.Contains(c.body, "function keep") {
				src = "<?php\nadd_action('wp_ajax_x', 'run');\nfunction run() {\n" + c.body + "\n}\n"
			}
			own, _, err := e.ScanTimed("php", "a.php", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, f := range taintOnly(own) {
				got = got || f.RuleID == rule
			}
			if got != c.want {
				t.Errorf("%s reported: %v, want %v", rule, got, c.want)
			}
		})
	}
}

// Every function wp_byvalue.txt lets through says why it takes its arguments
// by value, and none is a PHP internal function (php_refparams.txt rules those).
func TestWPByValueList(t *testing.T) {
	n := 0
	for _, l := range strings.Split(wpByValueList, "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		n++
		name, why, ok := strings.Cut(l, " # ")
		if !ok || strings.TrimSpace(why) == "" || strings.ContainsAny(name, " \t") {
			t.Errorf("%q: want <function> # <why it takes its arguments by value>", l)
		}
		if phpBuiltins[name] {
			t.Errorf("%s is a PHP internal function", name)
		}
	}
	if n != len(wpByValue) || n == 0 {
		t.Errorf("%d lines, %d functions", n, len(wpByValue))
	}
}

// A member of an object, or what a call returned, keeps no arr mark: the
// object may be shared or rewritten where the analysis does not follow. Only a
// variable of the function, or an index of it, does.
func TestNotArrayMembers(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-deserialization-wp-maybe-unserialize"
	ajax := func(body string) string { return "<?php\nadd_action('wp_ajax_x', function () {\n" + body + "\n});\n" }
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"$this->x rewritten by a method", "<?php\nclass C {\n  function run() {\n    $this->x = [$_POST['a']];\n    $this->setx();\n    maybe_unserialize($this->x);\n  }\n  function setx() {\n    $this->x = $_POST['b'];\n  }\n}\nadd_action('wp_ajax_x', [new C, 'run']);\n", true},
		{"an object copied, then its property written", ajax("$o = new stdClass();\n$o->p = [$_POST['a']];\n$q = $o;\n$q->p = $_POST['b'];\nmaybe_unserialize($o->p);"), true},
		{"a method of the object", ajax("$o = new Box();\n$o->p = [$_POST['a']];\n$o->fill();\nmaybe_unserialize($o->p);"), true},
		{"$this->x an array, nothing else", "<?php\nclass C {\n  function run() {\n    $this->x = [$_POST['a']];\n    maybe_unserialize($this->x);\n  }\n}\nadd_action('wp_ajax_x', [new C, 'run']);\n", true},
		{"a static property", "<?php\nclass C {\n  static $x;\n  function run() {\n    self::$x = [$_POST['a']];\n    maybe_unserialize(self::$x);\n  }\n}\nadd_action('wp_ajax_x', [new C, 'run']);\n", true},
		{"an index of a local array", ajax("$a = [];\n$a['k'] = [$_POST['a']];\nmaybe_unserialize($a['k']);"), false},
		{"an index of an object made with new (ArrayAccess)", ajax("$o = new Bag();\n$o['k'] = [$_POST['a']];\nmaybe_unserialize($o['k']);"), true},
		{"a local array", ajax("$a = [$_POST['a']];\nmaybe_unserialize($a);"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(c.src), nil }, ProjectOptions{})
			got := false
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", []byte(c.src))) {
				got = got || f.RuleID == rule
			}
			if got != c.want {
				t.Errorf("%s reported: %v, want %v", rule, got, c.want)
			}
		})
	}
}
