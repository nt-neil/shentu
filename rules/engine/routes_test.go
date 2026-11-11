package engine

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// Every route model's samples: the vulnerable one is reported only with the
// model (its input reaches the sink through a handler's parameters, which no
// rule names as a source), and the safe one is not reported.
func TestRouteSamples(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rules.LoadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	bare, _ := New(rs)
	bare.routes = nil // no handlers found; sources of route models stay
	ext := map[string]string{"php": "x.php", "python": "x.py", "js": "x.js"}
	for _, r := range routes {
		if len(r.Samples) == 0 {
			t.Errorf("%s: no samples", r.ID)
		}
		for i, s := range r.Samples {
			fs, err := e.Scan(r.Lang, ext[r.Lang], []byte(s.Code))
			if err != nil {
				t.Errorf("%s sample %d: %v", r.ID, i, err)
			}
			switch s.Kind {
			case "vulnerable":
				if len(fs) == 0 && !missingClasses(e, r) {
					t.Errorf("%s sample %d (vulnerable): not reported", r.ID, i)
				}
				if len(r.Sources) == 0 && len(r.Clears) == 0 { // a model that only adds sources or clears shows its effect in the safe sample
					if without, _ := bare.Scan(r.Lang, ext[r.Lang], []byte(s.Code)); len(without) != 0 {
						t.Errorf("%s sample %d: reported without the route model too (%v): it shows nothing", r.ID, i, without)
					}
				}
			case "safe":
				if len(fs) != 0 {
					t.Errorf("%s sample %d (safe): reported %v", r.ID, i, fs)
				}
			default:
				t.Errorf("%s sample %d: kind %q", r.ID, i, s.Kind)
			}
		}
	}
}

// A handler whose file names no source and has no sink still passes its
// parameters to another file's sink: in a project the file is not skipped
// (the name prefilter counts route handlers), and the finding is at the sink.
func TestRouteHandlerAcrossFiles(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"box.php": "<?php\nrequire 'db.php';\nadd_shortcode('box', 'box_render');\nfunction box_render($atts) {\n\treturn box_title($atts['slug']);\n}\n",
		"db.php":  "<?php\nfunction box_title($slug) {\n\tglobal $wpdb;\n\treturn $wpdb->get_var(\"SELECT title FROM boxes WHERE slug = '\" . $slug . \"'\");\n}\n",
	}
	scan := func(e *Engine) []Finding {
		pr := e.NewProject([]string{"box.php", "db.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
		var all []Finding
		for _, p := range []string{"box.php", "db.php"} {
			fs, _ := pr.Scan(p, []byte(files[p]))
			all = append(all, fs...)
		}
		return all
	}
	if fs := scan(e); len(fs) != 1 || fs[0].Path != "db.php" || fs[0].Line != 4 {
		t.Errorf("with the route model: %v, want db.php:4", fs)
	}
	bare := engineForTest(t)
	bare.routes = nil
	if fs := scan(bare); len(fs) != 0 {
		t.Errorf("without it: %v", fs)
	}
}

// Registrations naming a handler in another file: Django's urls.py and a
// view in views.py, Laravel's routes/web.php and a controller method. The
// view or method is analyzed with the path's parameters as input, in the
// pass that follows calls across files (the file on its own cannot know).
func TestRouteRegisteredInAnotherFile(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		safe  map[string]string // replaced in files for the safe variant
		at    string
	}{
		{"django", map[string]string{
			"app/urls.py":  "from django.urls import path\nfrom . import views\n\nurlpatterns = [path('report/<str:name>/', views.report)]\n",
			"app/views.py": "import os\n\ndef report(request, name):\n    return os.popen('cat /srv/' + name).read()\n",
		}, map[string]string{
			"app/urls.py": "from django.urls import path\nfrom . import views\n\nurlpatterns = [path('report/<int:name>/', views.report)]\n",
		}, "app/views.py:4"},
		{"django from-import", map[string]string{
			"app/urls.py":  "from django.urls import re_path\nfrom .views import report\n\nurlpatterns = [re_path(r'^report/(?P<name>[^/]+)/$', report)]\n",
			"app/views.py": "import os\n\ndef report(request, name):\n    return os.popen('cat /srv/' + name).read()\n",
		}, map[string]string{
			"app/views.py": "import os\nimport shlex\n\ndef report(request, name):\n    return os.popen('cat /srv/' + shlex.quote(name)).read()\n",
		}, "app/views.py:4"},
		{"laravel controller", map[string]string{
			"routes/web.php": "<?php\nuse App\\Http\\Controllers\\HostController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/lookup/{host}', [HostController::class, 'show']);\n",
			"app/Http/Controllers/HostController.php": "<?php\nnamespace App\\Http\\Controllers;\nclass HostController {\n\tpublic function show($host) {\n\t\treturn shell_exec('host ' . $host);\n\t}\n}\n",
		}, map[string]string{
			"app/Http/Controllers/HostController.php": "<?php\nnamespace App\\Http\\Controllers;\nclass HostController {\n\tpublic function show($host) {\n\t\treturn shell_exec('host ' . escapeshellarg($host));\n\t}\n}\n",
		}, "app/Http/Controllers/HostController.php:5"},
	}
	for _, c := range cases {
		run := func(files map[string]string) []string {
			e := engineForTest(t)
			var paths []string
			for p := range files {
				paths = append(paths, p)
			}
			slices.Sort(paths)
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			var at []string
			for _, p := range paths {
				fs, _ := pr.ScanCalls(p, []byte(files[p]))
				for _, f := range fs {
					at = append(at, fmt.Sprintf("%s:%d", f.Path, f.Line))
				}
			}
			return at
		}
		if at := run(c.files); !slices.Contains(at, c.at) {
			t.Errorf("%s, vulnerable: %v, want %s", c.name, at, c.at)
		}
		safe := maps.Clone(c.files)
		maps.Copy(safe, c.safe)
		if at := run(safe); len(at) != 0 {
			t.Errorf("%s, safe: %v", c.name, at)
		}
	}
}

// A route model is for rules taking the request's input in general (Applies):
// a rule for one field of it (a password) does not get every handler
// parameter as input.
func TestRouteOnlyForGeneralRules(t *testing.T) {
	rule := func(id string, sources ...string) rules.Rule {
		return rules.Rule{ID: id, Lang: "js", Class: "weak-crypto", Severity: "medium", Title: "t", Sources: sources,
			Sinks: []string{"md5("}, Sanitizers: []string{}}
	}
	e, err := New([]rules.Rule{rule("general", "req.body"), rule("password", "req.body.password")})
	if err != nil {
		t.Fatal(err)
	}
	src := "app.post('/signup', function (request, response) {\n  md5(request.body.name);\n});\n"
	fs, _ := e.Scan("js", "a.js", []byte(src))
	if len(fs) != 1 || fs[0].RuleID != "general" {
		t.Errorf("%v: want the general rule only", fs)
	}
}

// A rule with route_input = false (one for the Host header) takes its own
// sources only, not what a route model makes input: req.query.next is not the
// host, req.get('host') still is.
func TestRouteInputOff(t *testing.T) {
	off := false
	rule := func(id string, routeInput *bool) rules.Rule {
		return rules.Rule{ID: id, Lang: "js", Class: "open-redirect", CWE: "CWE-601", Severity: "medium", Title: "t",
			Sources: []string{"req.get('host')", "req.hostname"}, Sinks: []string{"res.redirect("}, Sanitizers: []string{}, RouteInput: routeInput}
	}
	e, err := New([]rules.Rule{rule("default", nil), rule("host-only", &off)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		src  string
		want []string
	}{
		{"app.get('/go', (req, res) => {\n  res.redirect(req.query.next);\n});\n", []string{"default"}},
		{"app.get('/go', (req, res) => {\n  res.redirect('https://' + req.get('host') + '/x');\n});\n", []string{"default", "host-only"}},
	} {
		fs, _ := e.Scan("js", "a.js", []byte(c.src))
		var got []string
		for _, f := range fs {
			got = append(got, f.RuleID)
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: reported by %v, want %v", c.src, got, c.want)
		}
	}
}

// The rules a route model is not for are exactly those for one field of the
// request (a password) and those without sources: every other rule with
// sources gets the handlers' parameters.
func TestRouteRulesLeftOut(t *testing.T) {
	e := engineForTest(t)
	for lang, routes := range e.routes {
		for _, c := range routes {
			for _, r := range e.byLang[lang] {
				if c.takes(r) || len(r.rule.Sources) == 0 {
					continue
				}
				for _, s := range r.rule.Sources {
					if !c.field(s) {
						t.Errorf("%s leaves out %s, whose source %q is no field of a request root", c.r.ID, r.rule.ID, s)
					}
				}
			}
		}
	}
}

// Which sources are one field of the request (the rule is left out) and which
// are the input in general.
func TestRouteFieldSources(t *testing.T) {
	c := &croute{applies: map[string]bool{"$_POST": true, "$request": true, "req.body": true, "request.form": true}}
	for s, want := range map[string]bool{
		"$_POST['pass": true, "$request->password": true, "$request->input('pass": true, "req.body.password": true,
		"request.form.get('password": true, "request.form['pw": true,
		"$_POST": false, "$request->input(": false, "$request->get(": false, "req.body": false, "request.form.get(": false,
		"$_GET": false, "request.files": false,
	} {
		if got := c.field(s); got != want {
			t.Errorf("field(%q) = %v, want %v", s, got, want)
		}
	}
}

// A route model's clears are for its classes only: an attachment's path
// looked up by id clears a file read, not a query.
func TestRouteClearsForTheirClasses(t *testing.T) {
	e := engineForTest(t)
	read := "<?php\nfunction f() {\n\treturn file_get_contents(get_attached_file($_GET['id']));\n}\n"
	query := "<?php\nfunction f() {\n\tglobal $wpdb;\n\treturn $wpdb->query(\"DELETE FROM t WHERE path = '\" . get_attached_file($_GET['id']) . \"'\");\n}\n"
	if fs, _ := e.Scan("php", "a.php", []byte(read)); len(fs) != 0 {
		t.Errorf("file read of an attachment's path: %v", fs)
	}
	if fs, _ := e.Scan("php", "a.php", []byte(query)); len(fs) == 0 {
		t.Error("query: the clear is not for SQL")
	}
}

// missingClasses reports whether none of the rule classes a model's clears
// are for exists in this rule set (ssrf rules come with integ): its
// vulnerable sample cannot be reported here.
func missingClasses(e *Engine, r rules.Route) bool {
	if len(r.ClearsFor) == 0 {
		return false
	}
	for _, cr := range e.byLang[r.Lang] {
		if slices.Contains(r.ClearsFor, cr.rule.Class) {
			return false
		}
	}
	return true
}
