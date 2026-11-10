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
				if len(fs) == 0 {
					t.Errorf("%s sample %d (vulnerable): not reported", r.ID, i)
				}
				if len(r.Sources) == 0 {
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
