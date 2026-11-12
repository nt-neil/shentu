package engine

import (
	"fmt"
	"slices"
	"sort"
	"testing"
)

// Names declared in several files: which one a call reaches (the WordPress
// coverage work, P1-P3). Each case is run with the sink reached (vulnerable)
// and with it escaped (safe); either way the caller is followed to the end.
func TestProjectPreferredDeclaration(t *testing.T) {
	const bad, good = "system('ls ' . $x);", "system('ls ' . escapeshellarg($x));"
	cases := []struct {
		name  string
		files func(sink string) map[string]string
		at    string // where the vulnerable variant reports
	}{
		{"P1 an empty stub is no candidate", func(sink string) map[string]string {
			return map[string]string{
				"a.php":    "<?php\nrun_it($_GET['x']);\n",
				"noop.php": "<?php\nfunction run_it() {}\n",
				"real.php": "<?php\nfunction run_it($x) {\n\t" + sink + "\n}\n",
			}
		}, "real.php:3"},
		{"P2 a function under !function_exists is a fallback", func(sink string) map[string]string {
			return map[string]string{
				"a.php":      "<?php\nrun_it($_GET['x']);\n",
				"compat.php": "<?php\nif ( ! function_exists( 'run_it' ) ) :\n\tfunction run_it($x) {\n\t\tsystem('ls ' . escapeshellarg($x));\n\t}\nendif;\n",
				"main.php":   "<?php\nfunction run_it($x) {\n\t" + sink + "\n}\n",
			}
		}, "main.php:3"},
		{"P2 a class under !class_exists is a fallback", func(sink string) map[string]string {
			return map[string]string{
				"a.php":      "<?php\nRunner::go($_GET['x']);\n",
				"compat.php": "<?php\nif (!class_exists('Runner')) {\n\tclass Runner {\n\t\tstatic function go($x) {\n\t\t\tsystem('ls ' . escapeshellarg($x));\n\t\t}\n\t}\n}\n",
				"main.php":   "<?php\nclass Runner {\n\tstatic function go($x) {\n\t\t" + sink + "\n\t}\n}\n",
			}
		}, "main.php:4"},
		{"P3 declared twice in one file (if/else) is that file's", func(sink string) map[string]string {
			return map[string]string{
				"a.php":      "<?php\nrun_it($_GET['x']);\n",
				"compat.php": "<?php\nif (PHP_VERSION_ID < 80000) {\n\tfunction run_it($x) {\n\t\t" + sink + "\n\t}\n} else {\n\tfunction run_it($x) {\n\t\t" + sink + "\n\t}\n}\n",
			}
		}, "compat.php:4"},
	}
	for _, c := range cases {
		files := c.files(bad)
		var order []string
		for p := range files {
			order = append(order, p)
		}
		sort.Strings(order)
		found, errs := scanProject(t, files, order...)
		var at []string
		for _, f := range found {
			at = append(at, fmt.Sprintf("%s:%d", f.Path, f.Line))
		}
		if !slices.Contains(at, c.at) || errs["a.php"] != nil {
			t.Errorf("%s, vulnerable: %v %v, want %s and a.php followed to the end", c.name, at, errs["a.php"], c.at)
		}
		files = c.files(good)
		found, errs = scanProject(t, files, order...)
		if len(found) != 0 || errs["a.php"] != nil {
			t.Errorf("%s, safe: %v %v", c.name, found, errs["a.php"])
		}
	}
}

// Without anything to prefer, several files declaring a name still leave the
// call unsure (the result says its calls were not followed to the end).
func TestProjectStillAmbiguous(t *testing.T) {
	files := map[string]string{
		"a.php": "<?php\nrun_it($_GET['x']);\n",
		"b.php": "<?php\nfunction run_it($x) {\n\tsystem('ls ' . $x);\n}\n",
		"c.php": "<?php\nfunction run_it($x) {\n\tsystem('ls ' . escapeshellarg($x));\n}\n",
	}
	_, errs := scanProject(t, files, "a.php", "b.php", "c.php")
	if errs["a.php"] == nil {
		t.Error("two full declarations, neither guarded: the call should stay unsure")
	}
}
