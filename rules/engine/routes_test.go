package engine

import (
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
