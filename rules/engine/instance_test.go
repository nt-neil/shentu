package engine

import "testing"

// A method called on an object whose class the code names is followed into
// the class: made in place (Repo().m(), (new Repo())->m(), new Repo().m()) or
// assigned to a name first, in the file and from another file of a project.
func TestInstanceMethodCalls(t *testing.T) {
	e := engineForTest(t)
	repo := "class Repo:\n    def by_label(self, label):\n        cur.execute(\"SELECT * FROM t WHERE label = '%s'\" % label)\n\n"
	safe := "class Repo:\n    def by_label(self, label):\n        cur.execute(\"SELECT * FROM t WHERE label = %s\", (label,))\n\n"
	for _, c := range []struct {
		name, lang, file, src string
		want                  bool
	}{
		{"made in place", "python", "a.py", repo + "def v(request):\n    Repo().by_label(request.GET['l'])\n", true},
		{"assigned first", "python", "a.py", repo + "def v(request):\n    r = Repo()\n    r.by_label(request.GET['l'])\n", true},
		{"QD9", "python", "a.py", "class Repo:\n    def by_label(self, label):\n        with connection.cursor() as cur:\n            cur.execute(\"SELECT * FROM t WHERE label = '%s'\" % label)\n\ndef v(request):\n    Repo().by_label(request.GET['l'])\n", true},
		{"PHP assigned in a function", "php", "a.php", "<?php\nclass Repo {\n\tfunction byLabel($l) {\n\t\tmysqli_query($db, \"SELECT * FROM t WHERE l = '$l'\");\n\t}\n}\nfunction v() {\n\t$r = new Repo();\n\t$r->byLabel($_GET['l']);\n}\n", true},
		{"a safe method", "python", "a.py", safe + "def v(request):\n    Repo().by_label(request.GET['l'])\n", false},
		{"PHP new in place", "php", "a.php", "<?php\nclass Repo {\n\tfunction byLabel($l) {\n\t\tmysqli_query($db, \"SELECT * FROM t WHERE l = '$l'\");\n\t}\n}\n(new Repo())->byLabel($_GET['l']);\n", true},
		{"JavaScript new in place", "js", "a.js", "class Repo {\n  run(c) {\n    require('child_process').exec('ls ' + c);\n  }\n}\napp.get('/x', (req, res) => {\n  new Repo().run(req.query.c);\n});\n", true},
	} {
		fs, err := e.Scan(c.lang, c.file, []byte(c.src))
		if err != nil || (len(fs) > 0) != c.want {
			t.Errorf("%s: %v (err %v), want reported %v", c.name, fs, err, c.want)
		}
	}
	files := map[string]string{
		"repo.py":  repo,
		"views.py": "from repo import Repo\n\ndef v(request):\n    Repo().by_label(request.GET['l'])\n\ndef w(request):\n    r = Repo()\n    r.by_label(request.GET['m'])\n",
	}
	pr := e.NewProject([]string{"repo.py", "views.py"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	n := 0
	for _, p := range []string{"repo.py", "views.py"} {
		fs, _ := pr.ScanCalls(p, []byte(files[p]))
		n += len(fs)
	}
	if n == 0 {
		t.Error("across files: not reported")
	}
}
