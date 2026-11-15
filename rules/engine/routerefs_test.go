package engine

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

func routeEngine(t *testing.T) *Engine {
	t.Helper()
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A handler registered twice: the finding names both routes.
func TestRouteRefsRegisteredTwice(t *testing.T) {
	e := routeEngine(t)
	src := "const { exec } = require('child_process');\n" +
		"function ping(req, res) {\n" +
		"  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));\n" +
		"}\n" +
		"app.get('/ping', ping);\n" +
		"app.post('/api/ping', ping);\n"
	fs, err := e.Scan("js", "a.js", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("not reported")
	}
	for _, f := range fs {
		want := []RouteRef{
			{Model: "express-handler", Framework: "express", Method: "get", Pattern: "/ping", Handler: "ping", File: "a.js", Line: 5},
			{Model: "express-handler", Framework: "express", Method: "post", Pattern: "/api/ping", Handler: "ping", File: "a.js", Line: 6},
		}
		if len(f.Routes) != len(want) {
			t.Fatalf("%s line %d: routes %+v, want %+v", f.RuleID, f.Line, f.Routes, want)
		}
		for i := range want {
			if f.Routes[i] != want[i] {
				t.Errorf("%s: route %d is %+v, want %+v", f.RuleID, i, f.Routes[i], want[i])
			}
		}
	}
}

// A sink outside any handler gets no routes, and its JSON is what it was.
func TestRouteRefsOutsideHandler(t *testing.T) {
	e := routeEngine(t)
	fs, err := e.Scan("php", "a.php", []byte("<?php\nsystem('ls ' . $_GET['d']);\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("not reported")
	}
	for _, f := range fs {
		if f.Routes != nil {
			t.Errorf("%s: routes %+v outside a handler", f.RuleID, f.Routes)
		}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "routes") {
			t.Errorf("JSON carries routes: %s", b)
		}
	}
}

// A decorator gives the path but no method, and the line of the decorator;
// a sink in a plain function of the same file gets nothing.
func TestRouteRefsDecorator(t *testing.T) {
	e := routeEngine(t)
	src := "import os\nfrom flask import Flask\napp = Flask(__name__)\n\n" +
		"@app.route('/run/<cmd>')\n" +
		"def run(cmd):\n" +
		"    os.system('echo ' + cmd)\n" +
		"    return 'ok'\n"
	fs, err := e.Scan("python", "a.py", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("not reported")
	}
	want := RouteRef{Model: "flask-route", Framework: "flask", Pattern: "/run/<cmd>", Handler: "run", File: "a.py", Line: 5}
	for _, f := range fs {
		if len(f.Routes) != 1 || f.Routes[0] != want {
			t.Errorf("%s line %d: routes %+v, want [%+v]", f.RuleID, f.Line, f.Routes, want)
		}
	}
}

// The innermost handler holding the sink is the one named.
func TestRouteRefsInnermost(t *testing.T) {
	e := routeEngine(t)
	src := "const { exec } = require('child_process');\n" +
		"app.use('/admin', function outer(req, res, next) {\n" +
		"  app.get('/admin/run', function inner(rq, rs) {\n" +
		"    exec('ls ' + rq.query.d);\n" +
		"  });\n" +
		"  next();\n" +
		"});\n"
	fs, err := e.Scan("js", "a.js", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("not reported")
	}
	for _, f := range fs {
		if len(f.Routes) != 1 || f.Routes[0].Pattern != "/admin/run" {
			t.Errorf("%s line %d: routes %+v, want only /admin/run", f.RuleID, f.Line, f.Routes)
		}
	}
}

// A file registering one handler thousands of times: each finding keeps at
// most maxRoutesPerFinding routes.
func TestRouteRefsBounded(t *testing.T) {
	e := routeEngine(t)
	var b strings.Builder
	b.WriteString("const { exec } = require('child_process');\nfunction ping(req, res) {\n  exec('ping ' + req.query.host);\n}\n")
	for i := 0; i < 6000; i++ {
		b.WriteString("app.get('/p" + strconv.Itoa(i) + "', ping);\n")
	}
	fs, err := e.Scan("js", "a.js", []byte(b.String()))
	if err != nil && len(fs) == 0 {
		t.Skipf("scan cut short: %v", err)
	}
	for _, f := range fs {
		if len(f.Routes) == 0 || len(f.Routes) > maxRoutesPerFinding || !f.RoutesTruncated {
			t.Errorf("%s: %d routes, truncated %v; want 1..%d and truncated", f.RuleID, len(f.Routes), f.RoutesTruncated, maxRoutesPerFinding)
		}
	}
}

// Within the bounds nothing is flagged.
func TestRouteRefsNotTruncated(t *testing.T) {
	e := routeEngine(t)
	src := "const { exec } = require('child_process');\nfunction ping(req, res) {\n  exec('ping ' + req.query.host);\n}\napp.get('/p', ping);\n"
	fs, err := e.Scan("js", "a.js", []byte(src))
	if err != nil || len(fs) == 0 {
		t.Fatalf("not reported: %v", err)
	}
	for _, f := range fs {
		if f.RoutesTruncated {
			t.Errorf("%s: flagged truncated with one route", f.RuleID)
		}
	}
}

// N-1: a shortcode is a hook, not a URL: the route is named, with no path.
func TestRouteRefsShortcodeNoPattern(t *testing.T) {
	e := routeEngine(t)
	src := "<?php\nadd_shortcode('box', 'box_render');\nfunction box_render($atts, $content = '') {\n" +
		"\tglobal $wpdb;\n\treturn $wpdb->get_var(\"SELECT title FROM t WHERE slug = '\" . $atts['slug'] . \"'\");\n}\n"
	fs, err := e.Scan("php", "a.php", []byte(src))
	if err != nil || len(fs) == 0 {
		t.Fatalf("not reported: %v", err)
	}
	want := RouteRef{Model: "wp-shortcode", Framework: "wordpress", Handler: "box_render", File: "a.php", Line: 2}
	for _, f := range fs {
		if len(f.Routes) != 1 || f.Routes[0] != want {
			t.Errorf("%s: routes %+v, want [%+v]", f.RuleID, f.Routes, want)
		}
	}
}

// N-2: two handlers on one line: lines cannot tell which holds the sink, so
// neither is named (not the first registered).
func TestRouteRefsSameLine(t *testing.T) {
	e := routeEngine(t)
	src := "const { exec } = require('child_process');\n" +
		"app.get('/a', function (q, s) { s.send('ok'); }); app.get('/b', function (rq, rs) { exec('ls ' + rq.query.d); });\n"
	fs, err := e.Scan("js", "a.js", []byte(src))
	if err != nil || len(fs) == 0 {
		t.Fatalf("not reported: %v", err)
	}
	for _, f := range fs {
		if f.Routes != nil {
			t.Errorf("%s: routes %+v, want none", f.RuleID, f.Routes)
		}
	}
}

// S-A, a known limit: a one-line handler and a sink outside it on the same
// line cannot be told apart by line, and the handler's routes are given.
// If this starts failing because columns are now known, the limit is gone:
// drop it from the comments and RoutesMeaning.
func TestRouteRefsSameLineOutsideKnownLimit(t *testing.T) {
	e := routeEngine(t)
	src := "<?php\nadd_shortcode('a', function ($atts) { return 1; }); system('ls ' . $_GET['d']);\n"
	fs, err := e.Scan("php", "a.php", []byte(src))
	if err != nil || len(fs) == 0 {
		t.Fatalf("not reported: %v", err)
	}
	for _, f := range fs {
		if len(f.Routes) != 1 || f.Routes[0].Model != "wp-shortcode" {
			t.Errorf("%s: routes %+v, want the shortcode's (the known limit)", f.RuleID, f.Routes)
		}
	}
}
