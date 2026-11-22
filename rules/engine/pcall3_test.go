package engine

import (
	"slices"
	"testing"
)

// c3: a callable given as the name of a PHP builtin is no unknown function.
// A sink of the rule reports where the name is written, a sanitizer or any
// other builtin passes, and a name neither the project nor PHP defines (an
// outside library) is cut as callable-param. On the code audit's path.
func TestBuiltinNameCallables(t *testing.T) {
	e := engineForTest(t)
	helper := "<?php\nfunction tap2($value, $callback) {\n    $callback($value);\n    return $value;\n}\n"
	for _, c := range []struct {
		name string
		a    string
		want []string
		cut  bool
	}{
		{"array_map('system', input)", "<?php\narray_map('system', $_GET['x']);\n", []string{"a.php:2:php-cmdi-shell-exec"}, false},
		{"array_map('exec', input) on a later line", "<?php\n$x = $_GET['x'];\n$out = array_map(\n    'exec',\n    $x\n);\n", []string{"a.php:4:php-cmdi-shell-exec"}, false},
		{"call_user_func('passthru', input)", "<?php\ncall_user_func('passthru', $_POST['c']);\n", []string{"a.php:2:php-cmdi-shell-exec"}, false},
		{"array_map('\\system', input): the global name", "<?php\narray_map('\\system', $_GET['x']);\n", []string{"a.php:2:php-cmdi-shell-exec"}, false},
		{"array_map('SYSTEM', input): names are case-insensitive", "<?php\narray_map('SYSTEM', $_GET['x']);\n", []string{"a.php:2:php-cmdi-shell-exec"}, false},
		{"a helper calling '\\system'", "<?php\nrequire 'b.php';\ntap2($_GET['x'], '\\system');\n", []string{"a.php:3:php-cmdi-shell-exec"}, false},
		{"array_map('escapeshellarg', input)", "<?php\narray_map('escapeshellarg', $_GET['x']);\n", nil, false},
		{"a helper calling 'system'", "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'system');\n", []string{"a.php:3:php-cmdi-shell-exec"}, false},
		{"a helper calling 'urlencode'", "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'urlencode');\n", nil, false},
		{"a helper calling 'intval'", "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'intval');\n", nil, false},
		{"a helper calling a function no one defines (cut)", "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'vendor_lib_run');\n", nil, true},
		{"a helper calling a variable callable (cut)", "<?php\nrequire 'b.php';\ntap2($_GET['x'], $cb);\n", nil, true},
		{"'system' with no input (control)", "<?php\nrequire 'b.php';\ntap2('ls', 'system');\narray_map('system', ['ls']);\n", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": c.a, "b.php": helper}
			pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			src := []byte(c.a)
			own, _, err1 := e.ScanTimed("php", "a.php", src)
			part, err2 := pr.ScanCallsPart("a.php", src, nil)
			var got []string
			for _, f := range append(own, part.Found...) {
				if f.RuleID != "php-cmdi-shell-exec" {
					continue
				}
				p := f.Path
				if p == "" {
					p = "a.php"
				}
				got = append(got, p+":"+itoa(f.Line)+":"+f.RuleID)
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported %v, want %v", got, c.want)
			}
			if cut := (CutOf(err1)|CutOf(err2))&CutCallableParam != 0; cut != c.cut {
				t.Errorf("cut as callable-param %v, want %v (%v, %v)", cut, c.cut, err1, err2)
			}
		})
	}
}

// TestStrNamesSkipKeys: an array key names no callable, so it keeps no rule
// in the scan; the same name as a value does.
func TestStrNamesSkipKeys(t *testing.T) {
	for _, c := range []struct {
		src  string
		want bool
	}{
		{"<?php\n$n = $info['filesize'];\n", false},
		{"<?php\n$info = ['filesize' => 0];\n", false},
		{"<?php\n$n = array_map('filesize', $_GET['f']);\n", true},
		{"<?php\n$cbs['k'] = 'filesize';\n", true},
		{"<?php\n$n = array_map('\\FileSize', $_GET['f']);\n", true},
	} {
		var strs map[string]bool
		if got := strNames(lex("php", c.src, newBudget(DefaultLimits)), &strs)["filesize"]; got != c.want {
			t.Errorf("%q: 'filesize' named %v, want %v", c.src, got, c.want)
		}
	}
}
