package engine

import (
	"slices"
	"testing"
)

// A function that calls its parameter (tap($value, $callback)) is followed at
// its caller with the callable passed there (summary.pcall, pcallSeeds): a
// closure literal is run with the input the callee gives it, the caller's own
// parameter moves the effect up a level, and anything else with input is cut
// as callable-param. The function's own $callback(...) is no other file's
// $callback, so it is not cut there. On the code audit's path.
func TestParamCalls(t *testing.T) {
	e := engineForTest(t)
	helper := "<?php\nfunction tap2($value, $callback) {\n    $callback($value);\n    return $value;\n}\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
		want  []string // findings, as path:line:rule
		cut   Cut      // the cut the scanned file's calls pass must name (0: none of CutCallableVar|CutCallableParam|CutAmbiguous)
	}{
		{"a closure literal is called with the input passed beside it", map[string]string{
			"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2($_GET['x'], function ($v) {\n    system($v);\n});\n",
		}, "a.php", []string{"a.php:4:php-cmdi-shell-exec"}, 0},
		{"no input beside it: the closure is run clean (control)", map[string]string{
			"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\ntap2('ls', function ($v) {\n    system($v);\n});\n",
		}, "a.php", nil, 0},
		{"the effect moves up through the caller's own parameter", map[string]string{
			"b.php": helper,
			"c.php": "<?php\nrequire 'b.php';\nfunction each2($items, $fn) {\n    return tap2($items, $fn);\n}\n",
			"a.php": "<?php\nrequire 'c.php';\neach2($_GET['x'], function ($v) {\n    system($v);\n});\n",
		}, "a.php", []string{"a.php:4:php-cmdi-shell-exec"}, 0},
		{"the helper's own $callback(...) is not cut by other files' $callback closures", map[string]string{
			"b.php": helper,
			"d.php": "<?php\n$callback = function ($v) {\n    exec($v);\n};\n",
			"e.php": "<?php\n$callback = fn ($v) => system($v);\n",
		}, "b.php", nil, 0},
		{"input of its own given to the callable, with no return value", map[string]string{
			"b.php": "<?php\nfunction each_input($cb) {\n    $cb($_GET['x']);\n}\n",
			"a.php": "<?php\nrequire 'b.php';\neach_input(function ($v) {\n    system($v);\n});\n",
		}, "a.php", []string{"a.php:4:php-cmdi-shell-exec"}, 0},
		// (a file with a sink of the rule: one with none is not analysed for it)
		{"a closure calling its own parameter with input: cut as callable-param", map[string]string{
			"a.php": "<?php\nfunction run() {\n    system('ls');\n    $f = function ($cb) {\n        $cb($_GET['x']);\n    };\n    return $f;\n}\n",
		}, "a.php", nil, CutCallableParam},
		{"named arguments are put in the callee's places (#182 review N-1)", map[string]string{
			"b.php": "<?php\nfunction tap_value($value, $callback) {\n    $callback($value);\n    return $value;\n}\n",
			"a.php": "<?php\nrequire 'b.php';\ntap_value(callback: function ($v) {\n    system($v);\n}, value: $_GET['c']);\n",
		}, "a.php", []string{"a.php:4:php-cmdi-shell-exec"}, 0},
		{"a named argument no parameter has, with input: cut as callable-param", map[string]string{
			"b.php": "<?php\nfunction tap_value($value, $callback) {\n    $callback($value);\n    return $value;\n}\n",
			"a.php": "<?php\nrequire 'b.php';\ntap_value(cb: function ($v) {\n    system($v);\n}, value: $_GET['c']);\n",
		}, "a.php", nil, CutCallableParam},
		{"a parameter assigned again before its call: cut as callable-param (#182 review S-1)", map[string]string{
			"b.php": "<?php\nfunction wrap_call($v, $cb) {\n    $cb = wrap($cb);\n    $cb($v);\n}\n",
			"a.php": "<?php\nrequire 'b.php';\nwrap_call($_GET['x'], function ($s) {\n    system($s);\n});\n",
		}, "a.php", nil, CutCallableParam},
		{"a parameter destructured again before its call: cut as callable-param", map[string]string{
			"b.php": "<?php\nfunction swap_call($v, $cb) {\n    [$cb] = [wrap($cb)];\n    $cb($v);\n}\n",
			"a.php": "<?php\nrequire 'b.php';\nswap_call($_GET['x'], function ($s) {\n    system($s);\n});\n",
		}, "a.php", nil, CutCallableParam},
		{"a parameter reused as a foreach target: cut as callable-param", map[string]string{
			"b.php": "<?php\nfunction loop_call($v, $cb) {\n    foreach (handlers() as $cb) {\n        $cb($v);\n    }\n}\n",
			"a.php": "<?php\nrequire 'b.php';\nloop_call($_GET['x'], function ($s) {\n    system($s);\n});\n",
		}, "a.php", nil, CutCallableParam},
		{"a callable the call site does not show, with input: cut as callable-param", map[string]string{
			"b.php": helper,
			"a.php": "<?php\nrequire 'b.php';\n$h = make_handler();\ntap2($_GET['x'], $h);\n",
		}, "a.php", nil, CutCallableParam},
	} {
		t.Run(c.name, func(t *testing.T) {
			var paths []string
			for p := range c.files {
				paths = append(paths, p)
			}
			slices.Sort(paths)
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(c.files[p]), nil }, ProjectOptions{})
			src := []byte(c.files[c.scan])
			_, _, err1 := e.ScanTimed(LangOf(c.scan), c.scan, src)
			_, err := pr.ScanCallsPart(c.scan, src, nil)
			got := (CutOf(err1) | CutOf(err)) & (CutCallableVar | CutCallableParam | CutAmbiguous)
			if got != c.cut {
				t.Errorf("cut %q (%v, %v), want %q", got, err1, err, c.cut)
			}
			if c.cut != 0 {
				return // calls not all followed: auditPath says so with ErrCalls
			}
			var found []string
			for _, f := range auditPath(t, e, pr, c.scan, src) {
				p := f.Path
				if p == "" {
					p = c.scan
				}
				found = append(found, p+":"+itoa(f.Line)+":"+f.RuleID)
			}
			slices.Sort(found)
			found = slices.Compact(found)
			if !slices.Equal(found, c.want) {
				t.Errorf("reported %v, want %v", found, c.want)
			}
		})
	}
}
