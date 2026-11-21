package engine

import (
	"errors"
	"slices"
	"testing"
)

// A call is not ambiguous (CutAmbiguous: "calls not followed") when the other
// files declaring its name cannot be what it reaches: a module inside a
// package, away from the importing file, for an absolute import; a stub that
// only returns a constant (WordPress's noop.php); a closure assigned to a
// variable inside another file's function. It stays ambiguous when one of them
// may be: a top-level closure variable of the same name in a file not
// included, a module beside the importing file (#174 review S-1). Only a call one of whose
// candidates matters to the rule is ever unsure. On the code audit's path.
func TestAmbiguousCalls(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name   string
		files  map[string]string
		scan   string
		want   []string // findings, as path:line:rule
		unsure bool     // the call stays cut as ambiguous: no file can be ruled out
	}{
		// A closure assigned to a variable inside a method is that method's
		// variable: no other file reaches it, so it is no candidate.
		{"$callback(...) of a method's parameter, with method-local $callback closures in other files", map[string]string{
			"a.php": "<?php\nclass A {\n    public function each($callback) {\n        return $callback($_GET['x']);\n    }\n}\n",
			"b.php": "<?php\nclass B {\n    public function run() {\n        $callback = function ($v) { exec($v); };\n        return $callback('x');\n    }\n}\n",
			"c.php": "<?php\nclass C {\n    public function run() {\n        $callback = fn ($v) => system($v);\n        return $callback('y');\n    }\n}\n",
		}, "a.php", nil, false},
		// A top-level closure is global: another file reaches it when it is
		// included, so with none included the call stays unsure (#174 review S-1).
		{"$callback(...) with top-level $callback closures in files not included: unsure", map[string]string{
			"a.php": "<?php\nclass A {\n    public function each($callback) {\n        return $callback($_GET['x']);\n    }\n}\n",
			"b.php": "<?php\n$callback = function ($v) {\n    exec($v);\n};\n",
			"c.php": "<?php\n$callback = fn ($v) => system($v);\n",
		}, "a.php", nil, true},
		// global $callback; inside a function makes the closure it assigns
		// global, as a top-level one is: still a candidate, still unsure.
		// A closure that leaves its function stays a candidate (#178 review
		// N-1): returned (r1), static (r2), assigned through use (&$runner)
		// (r3), packed by compact (r8). Each was followed before #178.
		{"r1: a local closure returned", map[string]string{
			"a.php": "<?php\nrequire 'b.php';\n$runner = make_runner();\n$runner($_GET['x']);\n",
			"b.php": "<?php\nfunction make_runner() {\n    $runner = function ($v) { exec($v); };\n    return $runner;\n}\n",
		}, "a.php", []string{"b.php:3:php-cmdi-shell-exec"}, false},
		{"r2: a static local closure", map[string]string{
			"a.php": "<?php\nrequire 'b.php';\nget_runner();\n$runner($_GET['x']);\n",
			"b.php": "<?php\nfunction get_runner() {\n    static $runner;\n    $runner = function ($v) { exec($v); };\n    return 1;\n}\n",
		}, "a.php", []string{"b.php:4:php-cmdi-shell-exec"}, false},
		{"r3: a closure assigned through use (&$runner)", map[string]string{
			"a.php": "<?php\nrequire 'b.php';\n$runner = setup();\n$runner($_GET['x']);\n",
			"b.php": "<?php\nfunction setup() {\n    $runner = null;\n    $init = function () use (&$runner) {\n        $runner = function ($v) { exec($v); };\n    };\n    $init();\n    return 1;\n}\n",
		}, "a.php", []string{"b.php:5:php-cmdi-shell-exec"}, false},
		{"r8: a local closure packed by compact", map[string]string{
			"a.php": "<?php\nrequire 'b.php';\nextract(pack_runner());\n$runner($_GET['x']);\n",
			"b.php": "<?php\nfunction pack_runner() {\n    $runner = function ($v) { exec($v); };\n    return compact('runner');\n}\n",
		}, "a.php", []string{"b.php:3:php-cmdi-shell-exec"}, false},
		{"r10: local closures handed out by get_defined_vars", map[string]string{
			"a.php": "<?php\nrequire 'b.php';\nextract(all_vars());\n$runner($_GET['x']);\n",
			"b.php": "<?php\nfunction all_vars() {\n    $runner = function ($v) { exec($v); };\n    return get_defined_vars();\n}\n",
		}, "a.php", []string{"b.php:3:php-cmdi-shell-exec"}, false},
		{"$callback(...) with closures assigned to a global $callback inside functions: unsure", map[string]string{
			"a.php": "<?php\nclass A {\n    public function each($callback) {\n        return $callback($_GET['x']);\n    }\n}\n",
			"b.php": "<?php\nfunction init() {\n    global $callback;\n    $callback = function ($v) { exec($v); };\n}\n",
			"c.php": "<?php\nfunction boot() {\n    if (true) {\n        global $other, $callback;\n    }\n    $callback = fn ($v) => system($v);\n}\n",
		}, "a.php", nil, true},
		{"import json beside two package modules named json.py", map[string]string{
			"app/__init__.py":       "",
			"app/utils/__init__.py": "",
			"app/utils/json.py":     "def loads(s):\n    return s\n",
			"app/core/__init__.py":  "",
			"app/core/json.py":      "def loads(s):\n    return s\n",
			"app/views.py":          "import json\nimport os\nfrom flask import request\n\ndef view():\n    data = json.loads(request.args['x'])\n    os.system(data)\n",
		}, "app/views.py", []string{"app/views.py:7:python-cmdi-shell"}, false},
		// A module beside the importing file may be loaded when that file runs
		// as a script: still unsure (#174 review S-1).
		{"import json beside a package's json.py in the importing file's directory", map[string]string{
			"app/__init__.py":       "",
			"app/json.py":           "import os\n\ndef loads(s):\n    os.system(s)\n",
			"app/tools/__init__.py": "",
			"app/tools/json.py":     "def loads(s):\n    return s\n",
			"app/run.py":            "import json\nfrom flask import request\n\ndef view():\n    json.loads(request.args['x'])\n",
		}, "app/run.py", nil, true},
		// One top-level helpers.py elsewhere and a package's beside the
		// importing file: either may be loaded, so unsure (#174 review 2 S-1).
		{"import helpers with one top-level helpers.py and a package's beside the importer", map[string]string{
			"lib/helpers.py":  "def run(s):\n    return s\n",
			"app/__init__.py": "",
			"app/helpers.py":  "import os\n\ndef run(s):\n    os.system(s)\n",
			"app/views.py":    "import helpers\nfrom flask import request\n\ndef view():\n    helpers.run(request.args['x'])\n",
		}, "app/views.py", nil, true},
		// A top-level json.py (the project root on sys.path, no __init__.py
		// beside it) does shadow the standard library: it is followed.
		{"import json with a top-level json.py beside a package's", map[string]string{
			"json.py":               "import os\n\ndef loads(s):\n    os.system(s)\n",
			"app/__init__.py":       "",
			"app/utils/__init__.py": "",
			"app/utils/json.py":     "def loads(s):\n    return s\n",
			"views.py":              "import json\nfrom flask import request\n\ndef view():\n    json.loads(request.args['x'])\n",
		}, "views.py", []string{"json.py:4:python-cmdi-shell"}, false},
		// A relative import names its file by path: not touched (control).
		// (from . import json resolves to the package's __init__.py, before
		// and after: a gap of its own, in the plan's backlog.)
		{"from .json import loads inside a package", map[string]string{
			"app/__init__.py": "",
			"app/json.py":     "import os\n\ndef loads(s):\n    os.system(s)\n",
			"app/views.py":    "from .json import loads\nfrom flask import request\n\ndef view():\n    loads(request.args['x'])\n",
			"lib/__init__.py": "",
			"lib/json.py":     "def loads(s):\n    return s\n",
		}, "app/views.py", []string{"app/json.py:4:python-cmdi-shell"}, false},
		// The function with a body is followed, not the stub: where the stub is
		// what runs (noop.php for load-scripts.php), this reports more, never less.
		{"a function with a body beside a stub returning a constant", map[string]string{
			"wp-includes/load.php":       "<?php\nfunction pick($v) {\n    system($v);\n}\n",
			"wp-admin/includes/noop.php": "<?php\nfunction pick() {\n    return true;\n}\n",
			"wp-content/plugins/p/p.php": "<?php\npick($_GET['x']);\n",
		}, "wp-content/plugins/p/p.php", []string{"wp-includes/load.php:3:php-cmdi-shell-exec"}, false},
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
			part, err2 := pr.ScanCallsPart(c.scan, src, nil)
			amb := CutOf(err1)&CutAmbiguous != 0 || CutOf(err2)&CutAmbiguous != 0
			if amb != c.unsure {
				t.Errorf("%s: cut as an ambiguous call %v, want %v (%v, %v)", c.name, amb, c.unsure, CutOf(err1), CutOf(err2))
			}
			if c.unsure {
				return // the file's calls were not all followed: auditPath says so with ErrCalls
			}
			if errors.Is(err2, ErrCalls) && !part.Cut {
				t.Logf("%s: ErrCalls %v", c.name, CutOf(err2))
			}
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
				t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
			}
		})
	}
}
