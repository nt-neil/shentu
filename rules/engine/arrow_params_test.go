package engine

import (
	"slices"
	"testing"
)

// An arrow function's parameters are its own: what the statement around it
// gathers next (the closing parenthesis of the call it is passed to) does not
// write over them, so app.get('/x', (req, res) => ...) has req as its first
// parameter and a route model makes it input.
func TestArrowParamsKept(t *testing.T) {
	for _, c := range []struct {
		src  string
		want []string
	}{
		{"app.post('/x', (request, response) => {\n  md5(request.query.name);\n});\n", []string{"request", "response"}},
		{"app.post('/x', async (request) => {\n  md5(request.query.name);\n}, other);\n", []string{"request"}},
		{"app.post('/x', request => md5(request.query.name), a, b);\n", []string{"request"}},
	} {
		b := newBudget(DefaultLimits)
		tree := parse("js", lex("js", c.src, b), b)
		if len(tree) != 1 || len(tree[0].funcs) != 1 {
			t.Fatalf("%q: want one statement with one function", c.src)
		}
		var got []string
		for _, p := range splitTop(tree[0].funcs[0].params, isComma) {
			for _, tk := range p {
				got = append(got, tk.Text)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: parameters %q, want %q", c.src, got, c.want)
		}
	}
	e := engineForTest(t)
	fs, _ := e.Scan("js", "a.js", []byte("const { exec } = require('child_process');\napp.get('/x', (request, response) => {\n  exec('ping ' + request.query.host);\n});\n"))
	if len(fs) == 0 {
		t.Error("an arrow handler's first parameter is not the route's input")
	}
}
