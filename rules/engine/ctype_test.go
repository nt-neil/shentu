package engine

import "testing"

// js-xss-response leaves out a write once the handler set Content-Type
// text/event-stream on every path before it, in each way it is set; not when
// it was set in one branch only, merely asked about (req.accepts), or set to
// something else.
func TestUnlessContentType(t *testing.T) {
	e := engineForTest(t)
	h := func(body string) string {
		return "app.get('/e', (req, res) => {\n" + body + "\n  res.write(\"data: \" + req.query.q + \"\\n\\n\");\n});\n"
	}
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"setHeader", h(`  res.setHeader("Content-Type", "text/event-stream");`), false},
		{"set with charset", h(`  res.set("content-type", "text/event-stream; charset=utf-8");`), false},
		{"type", h(`  res.type("text/event-stream");`), false},
		{"writeHead", h(`  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });`), false},
		{"set with an object", h(`  res.set({ "Content-Type": "text/event-stream" });`), false},
		{"no Content-Type", h(``), true},
		{"in one branch only", h(`  if (req.query.s) { res.setHeader("Content-Type", "text/event-stream"); }`), true},
		{"asked, not set", h(`  const s = req.accepts("text/event-stream");`), true},
		{"another type", h(`  res.setHeader("Content-Type", "text/html");`), true},
		{"another header", h(`  res.setHeader("X-Type", "text/event-stream");`), true},
	} {
		fs, err := e.Scan("js", "a.js", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == "js-xss-response"
		}
		if err != nil || got != c.want {
			t.Errorf("%s: reported %v (err %v), want %v", c.name, got, err, c.want)
		}
	}
}
