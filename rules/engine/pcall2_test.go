package engine

import (
	"slices"
	"testing"
)

// c2: the callable a call passes where the callee calls its parameter, when it
// is written as a value: a function name ('run_cmd', 'Cmd::run'), an array
// callable ([Cmd::class, 'run'], [$this, 'run']) or a first-class callable
// (run_cmd(...)). On the code audit's path.
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

// A callable value whose summary is still being worked out (a cycle through
// the value, which is no edge of the call graph) is cut as callable-param, not
// taken for a function the rule finds nothing in (#184 review N-1).
func TestCallableValueBusy(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
	}{
		{"a function passing its own name to a helper that calls it", map[string]string{
			"a.php": "<?php\nfunction tap2($value, $callback) {\n    $callback($value);\n    return $value;\n}\nfunction step($s) {\n    tap2($s, 'step');\n    system($s);\n}\nstep($_GET['x']);\n",
		}, "a.php"},
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
			_, err2 := pr.ScanCallsPart(c.scan, src, nil)
			if (CutOf(err1)|CutOf(err2))&CutCallableParam == 0 {
				t.Errorf("not cut as callable-param: %v (%v), %v (%v)", err1, CutOf(err1), err2, CutOf(err2))
			}
		})
	}
}

// #184 review probe d17: f and g pass each other by name in b.php, and a.php
// asks for f's summary first (f('ls')), so g is worked out while f is busy.
// The call of g with input must then be reported or cut, never neither;
// without the f('ls') line it is reported (control).
func TestCallableValueBusyAcrossFiles(t *testing.T) {
	e := engineForTest(t)
	b := "<?php\nfunction tap2($v, $cb) { $cb($v); return $v; }\nfunction f($s) { system($s); tap2($s, 'g'); }\nfunction g($s) { tap2($s, 'f'); }\n"
	for _, c := range []struct {
		name, a string
		first   bool // f('ls') asked first
	}{
		{"f asked first (d17)", "<?php\nrequire 'b.php';\nf('ls');\ntap2($_GET['x'], 'g');\n", true},
		{"without f('ls') (control)", "<?php\nrequire 'b.php';\ntap2($_GET['x'], 'g');\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": c.a, "b.php": b}
			pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			src := []byte(c.a)
			own, _, err1 := e.ScanTimed("php", "a.php", src)
			part, err2 := pr.ScanCallsPart("a.php", src, nil)
			reported := false
			for _, f := range append(own, part.Found...) {
				if f.Path == "b.php" && f.Line == 3 && f.RuleID == "php-cmdi-shell-exec" {
					reported = true
				}
			}
			cut := (CutOf(err1)|CutOf(err2))&CutCallableParam != 0
			if !reported && !cut {
				t.Errorf("neither reported b.php:3 nor cut as callable-param (%v, %v)", err1, err2)
			}
			if !c.first && !reported {
				t.Errorf("control: b.php:3 not reported (%v, %v)", err1, err2)
			}
		})
	}
}
