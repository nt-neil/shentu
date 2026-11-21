package engine

import (
	"errors"
	"slices"
	"testing"
)

// A call is not ambiguous (CutAmbiguous: "calls not followed") when the other
// files declaring its name cannot be what it reaches (and one of them matters
// to the rule, as only then is a call unsure): another file's closure
// variable of the same name, a module inside a package for an absolute import,
// or a stub that only returns a constant (WordPress's noop.php). On the code
// audit's path.
func TestAmbiguousCalls(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name  string
		files map[string]string
		scan  string
		want  []string // findings in the scanned file, as path:line:rule
	}{
		{"$callback(...) of a method's parameter, with $callback closures in other files", map[string]string{
			"a.php": "<?php\nclass A {\n    public function each($callback) {\n        return $callback($_GET['x']);\n    }\n}\n",
			"b.php": "<?php\nclass B {\n    public function run() {\n        $callback = function ($v) { exec($v); };\n        return $callback('x');\n    }\n}\n",
			"c.php": "<?php\nclass C {\n    public function run() {\n        $callback = fn ($v) => system($v);\n        return $callback('y');\n    }\n}\n",
		}, "a.php", nil},
		{"import json beside two package modules named json.py", map[string]string{
			"app/__init__.py":       "",
			"app/utils/__init__.py": "",
			"app/utils/json.py":     "def loads(s):\n    return s\n",
			"app/core/__init__.py":  "",
			"app/core/json.py":      "def loads(s):\n    return s\n",
			"app/views.py":          "import json\nimport os\nfrom flask import request\n\ndef view():\n    data = json.loads(request.args['x'])\n    os.system(data)\n",
		}, "app/views.py", []string{"app/views.py:7:python-cmdi-shell"}},
		// A top-level json.py (the project root on sys.path, no __init__.py
		// beside it) does shadow the standard library: it is followed.
		{"import json with a top-level json.py beside a package's", map[string]string{
			"json.py":               "import os\n\ndef loads(s):\n    os.system(s)\n",
			"app/__init__.py":       "",
			"app/utils/__init__.py": "",
			"app/utils/json.py":     "def loads(s):\n    return s\n",
			"views.py":              "import json\nfrom flask import request\n\ndef view():\n    json.loads(request.args['x'])\n",
		}, "views.py", []string{"json.py:4:python-cmdi-shell"}},
		// A relative import names its file by path: not touched (control).
		// (from . import json resolves to the package's __init__.py, before
		// and after: a gap of its own, in the plan's backlog.)
		{"from .json import loads inside a package", map[string]string{
			"app/__init__.py": "",
			"app/json.py":     "import os\n\ndef loads(s):\n    os.system(s)\n",
			"app/views.py":    "from .json import loads\nfrom flask import request\n\ndef view():\n    loads(request.args['x'])\n",
			"lib/__init__.py": "",
			"lib/json.py":     "def loads(s):\n    return s\n",
		}, "app/views.py", []string{"app/json.py:4:python-cmdi-shell"}},
		// The function with a body is followed, not the stub: where the stub is
		// what runs (noop.php for load-scripts.php), this reports more, never less.
		{"a function with a body beside a stub returning a constant", map[string]string{
			"wp-includes/load.php":       "<?php\nfunction pick($v) {\n    system($v);\n}\n",
			"wp-admin/includes/noop.php": "<?php\nfunction pick() {\n    return true;\n}\n",
			"wp-content/plugins/p/p.php": "<?php\npick($_GET['x']);\n",
		}, "wp-content/plugins/p/p.php", []string{"wp-includes/load.php:3:php-cmdi-shell-exec"}},
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
			for _, err := range []error{err1, err2} {
				if CutOf(err)&CutAmbiguous != 0 {
					t.Errorf("%s: cut as an ambiguous call: %v (%v)", c.name, err, CutOf(err))
				}
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
