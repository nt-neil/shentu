package engine

import (
	"slices"
	"testing"
)

// c2: the callable a call passes where the callee calls its parameter, when it
// is written as a value: a function name ('run_cmd', 'Cmd::run'), an array
// callable ([Cmd::class, 'run'], [$this, 'run']) or a first-class callable
// (run_cmd(...)); and a callable handed to a builtin that calls it
// (array_map($cb, $items)). On the code audit's path.
func TestCallableValues(t *testing.T) {
	e := engineForTest(t)
	helper := "<?php\nfunction tap2($value, $callback) {\n    $callback($value);\n    return $value;\n}\nfunction run_cmd($s) {\n    system($s);\n}\nclass Cmd {\n    public static function run($s) {\n        system($s);\n    }\n}\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
		want  []string
	}{
		{"a function name", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'run_cmd');\n"}, "a.php", []string{"b.php:7:php-cmdi-shell-exec"}},
		{"Cls::method as a string", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'Cmd::run');\n"}, "a.php", []string{"b.php:11:php-cmdi-shell-exec"}},
		{"[Cls::class, 'method']", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2($_GET['x'], [Cmd::class, 'run']);\n"}, "a.php", []string{"b.php:11:php-cmdi-shell-exec"}},
		{"a first-class callable", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2($_GET['x'], run_cmd(...));\n"}, "a.php", []string{"b.php:7:php-cmdi-shell-exec"}},
		{"[$this, 'method'] in a class", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\nclass Job {\n    public function go() {\n        tap2($_GET['x'], [$this, 'exec1']);\n    }\n    public function exec1($s) {\n        system($s);\n    }\n}\n"}, "a.php", []string{"a.php:8:php-cmdi-shell-exec"}},
		{"a function name with no input (control)", map[string]string{"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2('ls', 'run_cmd');\n"}, "a.php", nil},
		{"a parameter handed to array_map is called with the items", map[string]string{
			"b.php": "<?php\nfunction map2($items, $cb) {\n    return array_map($cb, $items);\n}\n",
			"a.php": "<?php\nrequire 'b.php';\nmap2($_GET['a'], function ($v) {\n    system($v);\n});\n"}, "a.php", []string{"a.php:4:php-cmdi-shell-exec"}},
		{"a closure literal handed to array_map", map[string]string{
			"a.php": "<?php\narray_map(function ($v) {\n    system($v);\n}, $_GET['a']);\n"}, "a.php", []string{"a.php:3:php-cmdi-shell-exec"}},
		{"a closure literal handed to usort, items without input (control)", map[string]string{
			"a.php": "<?php\n$a = ['b', 'a'];\nusort($a, function ($x, $y) {\n    system($x);\n    return 0;\n});\n"}, "a.php", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var paths []string
			for p := range c.files {
				paths = append(paths, p)
			}
			slices.Sort(paths)
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(c.files[p]), nil }, ProjectOptions{})
			src := []byte(c.files[c.scan])
			var got []string
			for _, f := range auditPath(t, e, pr, c.scan, src) {
				p := f.Path
				if p == "" {
					p = c.scan
				}
				got = append(got, p+":"+itoa(f.Line)+":"+f.RuleID)
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}
