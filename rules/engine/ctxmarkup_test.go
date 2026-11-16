package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// An output sink with markup counts input only after markup written in the
// same value: Koa's ctx.body = x sends JSON or text as often as a page, so a
// bare value, an object or input before any tag is not reported.
func TestContextMarkup(t *testing.T) {
	rule := func(markup bool) rules.Rule {
		return rules.Rule{ID: "koa", Lang: "js", Class: "xss", Severity: "medium", Title: "t",
			Sources: []string{"ctx.query"}, Sinks: []string{"ctx.body ="}, Sanitizers: []string{},
			Args: []rules.Args{{Context: []string{"html", "attr"}, Markup: markup}}}
	}
	strict, err := New([]rules.Rule{rule(true)})
	if err != nil {
		t.Fatal(err)
	}
	loose, err := New([]rules.Rule{rule(false)})
	if err != nil {
		t.Fatal(err)
	}
	h := func(body string) string {
		return "router.get('/x', async (ctx) => {\n  ctx.body = " + body + ";\n});\n"
	}
	for _, c := range []struct {
		name, src     string
		strict, loose bool
	}{
		{"a bare value", h("ctx.query.q"), false, true},
		{"an object", h("{ q: ctx.query.q }"), false, false},
		{"after a tag", h("'<p>' + ctx.query.q"), true, true},
		{"in a template", h("`<p>${ctx.query.q}</p>`"), true, true},
		{"in an attribute", h("'<a title=\"' + ctx.query.q + '\">x</a>'"), true, true},
		{"before any tag", h("ctx.query.q + '<br>'"), false, true},
		{"text, no tag", h("'Hello ' + ctx.query.q"), false, true},
	} {
		for _, x := range []struct {
			e    *Engine
			want bool
			kind string
		}{{strict, c.strict, "markup"}, {loose, c.loose, "no markup"}} {
			fs, err := x.e.Scan("js", "a.js", []byte(c.src))
			if err != nil || (len(fs) > 0) != x.want {
				t.Errorf("%s (%s): %v (err %v), want reported %v", c.name, x.kind, fs, err, x.want)
			}
		}
	}
	bad := rule(true)
	bad.Args[0].Context = nil
	if _, err := New([]rules.Rule{bad}); err == nil {
		t.Error("markup without context: no error")
	}
}
