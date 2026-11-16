package engine

import "testing"

// zipfile.ZipFile given an uploaded file's stream (request.files["a"], as a
// whole and in the call) reads a file object, not a path; a path from the
// request, or the upload's client file name, is still reported.
func TestUnlessSubscript(t *testing.T) {
	e := engineForTest(t)
	h := func(arg string) string {
		return "import zipfile\nfrom flask import request\n\n@app.post('/u')\ndef up():\n    with zipfile.ZipFile(" + arg + ") as z:\n        return z.namelist()\n"
	}
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"the upload's stream", h("request.files['archive']"), false},
		{"Django's FILES", h("request.FILES['pkg']"), false},
		{"a path from the query", h("request.args['p']"), true},
		{"the client file name", h("request.files['a'].filename"), true},
		{"joined into a path", h("'/srv/' + request.args['p']"), true},
	} {
		fs, err := e.Scan("python", "a.py", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == "python-path-traversal-send-file"
		}
		if err != nil || got != c.want {
			t.Errorf("%s: reported %v (err %v), want %v", c.name, got, err, c.want)
		}
	}
}
