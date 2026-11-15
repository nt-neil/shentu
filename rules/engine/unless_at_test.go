package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// unless_at narrows where unless looks. "start": only at the start of the
// argument (a line starting "data: "); the words elsewhere, or a ternary one
// branch of which starts so, do not count. "top": only as an element or key of
// the argument itself ({ where, relations }); a key of that name inside a
// value it holds does not. Without unless_at, unless counts anywhere.
func TestUnlessAt(t *testing.T) {
	one := 1
	rule := func(id, sink, at string, arg *int, unless ...string) rules.Rule {
		return rules.Rule{ID: id, Lang: "js", Class: "xss", CWE: "CWE-79", Severity: "medium", Title: "t",
			Sources: []string{"req.query"}, Sinks: []string{sink}, Sanitizers: []string{},
			Args: []rules.Args{{Arg: arg, Unless: unless, UnlessAt: at}}}
	}
	e, err := New([]rules.Rule{
		rule("start", "res.write(", "start", nil, "\"data: ", "`data: "),
		rule("anywhere", "res.write(", "", nil, "\"data: ", "`data: "),
		rule("top", ".find(", "top", &one, "relations:"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := func(body string) string { return "app.get('/x', (req, res) => {\n  " + body + "\n});\n" }
	for _, c := range []struct {
		name, rule, src string
		want            bool
	}{
		{"a line starting data:", "start", h(`res.write("data: " + req.query.q + "\n\n");`), false},
		{"a template starting data:", "start", h("res.write(`data: ${req.query.q}\\n\\n`);"), false},
		{"a ternary, one branch starting data:", "start", h(`res.write(s ? "data: ready" : "<h1>" + req.query.q + "</h1>");`), true},
		{"the words later", "start", h(`res.write("<p>" + req.query.q + "</p><p>data: x</p>");`), true},
		{"a ternary, unless anywhere", "anywhere", h(`res.write(s ? "data: ready" : "<h1>" + req.query.q + "</h1>");`), false}, // what unless_at is for
		{"relations as an option", "top", h(`orders.find({ where: { status: req.query.s }, relations: ["items"] });`), false},
		{"relations inside a value", "top", h(`people.find({ name: req.query.n, meta: { relations: 1 } });`), true},
		{"relations in another argument", "top", h(`people.find({ name: req.query.n }, { relations: 1 });`), true},
	} {
		fs, err := e.Scan("js", "a.js", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == c.rule
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %s reported %v (err %v), want %v", c.name, c.rule, got, err, c.want)
		}
	}
}
