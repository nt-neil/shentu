package engine

import (
	"slices"
	"testing"
)

// new $class(...) makes an object of the class $class names: it calls no
// callable, so a function doing it is no function calling its parameter
// (c1's pcall), and a caller passing a variable there is not cut as
// callable-param (Freemius's fs_get_entity($entity, $class)). On the code
// audit's path.
func TestNewVarIsNoCall(t *testing.T) {
	e := engineForTest(t)
	caller := "<?php\nrequire 'b.php';\n$c = get_option('cls');\necho get_entity($_GET['a'], $c);\n"
	for _, c := range []struct {
		name, b string
		want    []string
		cut     bool
	}{
		{"new $class($e)", "<?php\nfunction get_entity($e, $class) {\n    return new $class($e);\n}\n", nil, false},
		{"NEW $class($e)", "<?php\nfunction get_entity($e, $class) {\n    return NEW $class($e);\n}\n", nil, false},
		{"new Foo($e) (control)", "<?php\nfunction get_entity($e, $class) {\n    return new Foo($e);\n}\n", nil, false},
		{"$class($e) calls the parameter (control: cut)", "<?php\nfunction get_entity($e, $class) {\n    return $class($e);\n}\n", []string{"a.php:4:php-xss-echo-html"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": caller, "b.php": c.b}
			pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			src := []byte(caller)
			own, _, err1 := e.ScanTimed("php", "a.php", src)
			part, err2 := pr.ScanCallsPart("a.php", src, nil)
			var got []string
			for _, f := range append(own, part.Found...) {
				if f.RuleID != "php-xss-echo-html" {
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
