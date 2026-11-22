package engine

import (
	"slices"
	"strconv"
	"testing"
)

// TestPHPNamesAnyCase: PHP matches function and method names in any case, so
// SYSTEM($x) runs system() and EscapeShellArg($x) cleans as escapeshellarg()
// does. A method that happens to be called system is still no sink, and
// JavaScript and Python names keep their case. On the code audit's path.
func TestPHPNamesAnyCase(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, path, rule, src string
		files                 map[string]string
		want                  []string // path:line
	}{
		{"System(", "a.php", "php-cmdi-shell-exec", "<?php\nSystem($_GET['x']);\n", nil, []string{"a.php:2"}},
		{"SYSTEM(", "a.php", "php-cmdi-shell-exec", "<?php\nSYSTEM($_GET['x']);\n", nil, []string{"a.php:2"}},
		{`\SYSTEM(`, "a.php", "php-cmdi-shell-exec", "<?php\n\\SYSTEM($_GET['x']);\n", nil, []string{"a.php:2"}},
		{"System( in a namespace: the global function", "a.php", "php-cmdi-shell-exec", "<?php\nnamespace App\\Jobs;\n\nSystem($_GET['x']);\n", nil, []string{"a.php:4"}},
		{"Shell_Exec( in a function a call reaches", "a.php", "php-cmdi-shell-exec", "<?php\nrequire 'b.php';\nrun_it($_GET['x']);\n",
			map[string]string{"b.php": "<?php\nfunction run_it($c) {\n    return Shell_Exec($c);\n}\n"}, []string{"b.php:3"}},
		{"EscapeShellArg( cleans a lower-case sink", "a.php", "php-cmdi-shell-exec", "<?php\nsystem('ls ' . EscapeShellArg($_GET['x']));\n", nil, nil},
		{"EscapeShellArg( cleans", "a.php", "php-cmdi-shell-exec", "<?php\nSYSTEM('ls ' . EscapeShellArg($_GET['x']));\n", nil, nil},
		{"a method named system (control)", "a.php", "php-cmdi-shell-exec", "<?php\n$o->system($_GET['x']);\n$o->System($_GET['x']);\n", nil, nil},
		{"a static method named system (control)", "a.php", "php-cmdi-shell-exec", "<?php\nTask::SYSTEM($_GET['x']);\n", nil, nil},
		{"lower case still reports (control)", "a.php", "php-cmdi-shell-exec", "<?php\nsystem($_GET['x']);\n", nil, []string{"a.php:2"}},
		{"JavaScript keeps its case (control)", "a.js", "js-cmdi-exec", "const cp = require('child_process')\ncp.EXEC(req.query.c)\n", nil, nil},
		{"Python keeps its case (control)", "a.py", "python-cmdi-shell", "import os\nfrom flask import request\nos.SYSTEM(request.args['c'])\n", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{c.path: c.src}
			for p, s := range c.files {
				files[p] = s
			}
			var paths []string
			for p := range files {
				paths = append(paths, p)
			}
			slices.Sort(paths)
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			var got []string
			for _, f := range auditPath(t, e, pr, c.path, []byte(c.src)) {
				if f.RuleID == c.rule {
					p := f.Path
					if p == "" {
						p = c.path
					}
					got = append(got, p+":"+strconv.Itoa(f.Line))
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("%s lines %v, want %v", c.rule, got, c.want)
			}
		})
	}
}
