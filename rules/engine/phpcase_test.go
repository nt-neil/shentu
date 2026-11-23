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
		{"new File( builds a class, it calls no file()", "a.php", "php-path-traversal-file-read", "<?php\n$a = new File($_GET['x']);\n$b = new \\File($_GET['x']);\n$c = new A\\File($_GET['x']);\n$d = new file($_GET['x']);\n", nil, nil},
		{"new System( builds a class", "a.php", "php-cmdi-shell-exec", "<?php\n$a = new System($_GET['x']);\n", nil, nil},
		{"a function of a namespace is not file()", "a.php", "php-path-traversal-file-read", "<?php\nnamespace App;\n\n$a = Storage\\File($_GET['x']);\n$b = Storage\\file($_GET['x']);\n$c = namespace\\file($_GET['x']);\n", nil, nil},
		{"NEW File( and Namespace\\file( in a namespace are no file()", "a.php", "php-path-traversal-file-read", "<?php\nNamespace App;\n\n$a = NEW File($_GET['x']);\n$b = Namespace\\file($_GET['y']);\n", nil, nil},
		{`namespace\file( in a global namespace block is file()`, "a.php", "php-path-traversal-file-read", "<?php\nnamespace A {\n}\nnamespace {\n    $c = namespace\\file($_GET['x']);\n}\n", nil, []string{"a.php:5"}},
		{`namespace\file( with no namespace declared is file()`, "a.php", "php-path-traversal-file-read", "<?php\n$c = namespace\\file($_GET['x']);\n", nil, []string{"a.php:2"}},
		{`do \system( is PHP's`, "a.php", "php-cmdi-shell-exec", "<?php\ndo \\system($_GET['x']); while (false);\n", nil, []string{"a.php:2"}},
		{`yield from \File( is PHP's`, "a.php", "php-path-traversal-file-read", "<?php\nfunction g() {\n    yield from \\File($_GET['x']);\n}\n", nil, []string{"a.php:3"}},
		{`\file( and return \SYSTEM( are PHP's`, "a.php", "php-cmdi-shell-exec", "<?php\nfunction f() {\n    return \\SYSTEM($_GET['x']);\n}\n", nil, []string{"a.php:3"}},
		{`\File( is PHP's file()`, "a.php", "php-path-traversal-file-read", "<?php\n$a = \\File($_GET['x']);\n", nil, []string{"a.php:2"}},
		{`echo \system(, $a and \system(, case 1: \system( are PHP's`, "a.php", "php-cmdi-shell-exec",
			"<?php\necho \\system($_GET['x']);\n$a and \\system($_GET['y']);\nswitch ($k) {\n    case 1: \\system($_GET['z']);\n}\n", nil, []string{"a.php:2", "a.php:3", "a.php:5"}},
		{`throw \File( is PHP's`, "a.php", "php-path-traversal-file-read", "<?php\nthrow \\File($_GET['x']);\n", nil, []string{"a.php:2"}},
		{`x ?: \file( is PHP's`, "a.php", "php-path-traversal-file-read", "<?php\n$a = $b ?: \\file($_GET['y']);\n", nil, []string{"a.php:2"}},
		{`echo\system( and return\SYSTEM( with no space are PHP's (PHP 7 reads the keyword)`, "a.php", "php-cmdi-shell-exec",
			"<?php\necho\\system($_GET['x']);\nfunction f() {\n    return\\SYSTEM($_GET['y']);\n}\n", nil, []string{"a.php:2", "a.php:4"}},
		{`A\file( and A\B\file( are a namespace's, with no namespace declared`, "a.php", "php-path-traversal-file-read",
			"<?php\n$a = A\\file($_GET['x']);\n$b = A\\B\\file($_GET['y']);\n", nil, nil},
		{"Key( names a class, though PHP has key() (control)", "a.php", "php-hardcoded-secret-credentials", "<?php\nuse Firebase\\JWT\\Key;\n$k = new Key('change-me-jwt-key', 'HS256');\n", nil, []string{"a.php:3"}},
		{"a class pattern still matches after new (control)", "a.php", "php-ssrf-url-readers", "<?php\n$a = new SoapClient($_GET['x']);\n$b = new soapclient($_GET['x']);\n", nil, []string{"a.php:2", "a.php:3"}},
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
