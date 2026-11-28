package engine

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The neutral extract() fixtures in testdata/extfx, on the product path: an
// immediately called closure gets its arguments in its parameters (c, e as b,
// the helper function), parse_str($q) with one argument sets variables as
// extract() with no flags does (d), and extract()'s flags keep their meaning
// (f).
func TestExtractFixtures(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		dir  string
		want []int
	}{
		{"a", []int{7}},  // extract() of a shortcode's $atts, then include
		{"b", []int{7}},  // the same through a helper function
		{"c", []int{8}},  // the helper's extract() inside a closure called where it is written
		{"d", []int{11}}, // $_SERVER['QUERY_STRING'] is not this rule's source: parse_str($q) of one it has, below
		{"e", []int{6}},  // a closure called where it is written, its parameter from the shortcode
		{"f", []int{16}}, // EXTR_SKIP and EXTR_PREFIX_ALL keep $file; EXTR_OVERWRITE does not
	} {
		t.Run(c.dir, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "extfx", c.dir, "a.php"))
			if err != nil {
				t.Fatal(err)
			}
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return src, nil }, ProjectOptions{})
			var got []int
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", src)) {
				t.Logf("%s:%d %s", f.Path, f.Line, f.RuleID)
				if !slices.Contains(got, f.Line) {
					got = append(got, f.Line)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("lines %v, want %v", got, c.want)
			}
		})
	}
}

// parse_str($q) with one argument sets variables of the scope from the input
// as extract() with no flags; with a result array, as a method, or of no input
// it sets none.
func TestParseStrScope(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"parse_str of input", "parse_str($_SERVER['REQUEST_URI']);", true},
		{"parse_str of $_GET's value", "parse_str($_GET['q']);", true},
		{"mb_parse_str of input", "mb_parse_str($_GET['q']);", true},
		{"a result array", "parse_str($_GET['q'], $out);", false},
		{"a method of that name", "$o->parse_str($_GET['q']);", false},
		{"a static method of that name", "Q::parse_str($_GET['q']);", false},
		{"no input", "parse_str('file=a.php');", false},
		{"parse_str with @", "@parse_str($_GET['q']);", true},
		{"parse_str of the global namespace", "\\parse_str($_GET['q']);", true},
		{"parse_str in capitals", "PARSE_STR($_GET['q']);", true},
		{"parse_str whose result is assigned", "$r = parse_str($_GET['q']);", true},
		{"a result array, the result assigned", "$r = parse_str($_GET['q'], $out);", false},
		{"extract whose result is assigned", "$n = extract($_GET);", true},
		{"extract with @, \\ and capitals", "@\\EXTRACT($_GET);", true},
		{"extract whose result is assigned, EXTR_SKIP", "$n = extract($_GET, EXTR_SKIP);", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := []byte("<?php\nfunction f() {\n  $file = 'default.php';\n  " + c.body + "\n  include $file;\n}\n")
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return src, nil }, ProjectOptions{})
			got := false
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", src)) {
				got = got || f.RuleID == "php-path-traversal-file-include" && f.Line == 5
			}
			if got != c.want {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}

// A closure called where it is written gets each argument in the parameter of
// its place, and nothing else.
func TestImmediateClosureArgs(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"input in its parameter", "(function ($a) {\n  require_once $a;\n})($_GET['f']);", true},
		{"input in the second place, the second parameter included", "(function ($x, $a) {\n  require_once $a;\n})('safe.php', $_GET['f']);", true},
		{"input in the second place, the first parameter included", "(function ($a, $x) {\n  require_once $a;\n})('safe.php', $_GET['f']);", false},
		{"no input passed", "(function ($a) {\n  require_once $a;\n})('safe.php');", false},
		{"a static closure", "(static function ($a) {\n  require_once $a;\n})($_GET['f']);", true},
		{"more parentheses around", "((function ($a) {\n  require_once $a;\n}))($_GET['f']);", true},
		{"a static closure, more parentheses around", "((static function ($a) {\n  require_once $a;\n}))($_GET['f']);", true},
		{"a closure given to a call whose result is called", "wrap(function ($a) {\n  require_once $a;\n})($_GET['f']);", false},
		{"returned and then called (not followed)", "(function () {\n  return function ($a) {\n    require_once $a;\n  };\n})()($_GET['f']);", false},
		{"input in a use variable, a constant passed", "$p = $_GET['f'];\n(function ($a) use ($p) {\n  require_once $a;\n})('safe.php');", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := []byte("<?php\nfunction f() {\n" + c.body + "\n}\n")
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return src, nil }, ProjectOptions{})
			got := false
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", src)) {
				got = got || f.RuleID == "php-path-traversal-file-include"
			}
			if got != c.want {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}
