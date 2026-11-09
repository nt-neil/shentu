package engine

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// 1f. Minified handling.
func TestR20Minified(t *testing.T) {
	rs, _ := rules.Load()
	e, _ := New(rs)
	pad := strings.Repeat(" ", 1200)
	cases := []struct {
		id, src string
	}{
		{"M01 vulnerable line padded past 1000 bytes in a small file", "app.get('/x', (req, res) => { exec(req.query.c); });" + pad + "\nmodule.exports = app;\n"},
		{"M02 long template literal opens; vuln on a short line after it", "const tpl = `" + strings.Repeat("x", 1200) + "\n`;\napp.get('/x', (req, res) => {\n  exec(req.query.c);\n});\n" + strings.Repeat("// "+strings.Repeat("y", 1100)+"\n", 2)},
		{"M03 long data line then vuln", "const DATA = '" + strings.Repeat("A", 3000) + "';\napp.get('/x', (req, res) => {\n  exec(req.query.c);\n});\n"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			fs, err := e.Scan("js", "app.js", []byte(c.src))
			n := 0
			for _, f := range fs {
				if strings.HasPrefix(f.RuleID, "js-cmdi") {
					n++
				}
			}
			t.Logf("minified=%v err=%v cmdi findings=%d", Minified([]byte(c.src)), err, n)
			if n == 0 {
				t.Errorf("%s: exec(req.query.c) not reported (err %v)", c.id, err)
			}
		})
	}
}
