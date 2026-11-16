package engine

import "testing"

// A sink with several [[args]] blocks is reported when any one holds:
// js-cmdi-spawn-shell looks at spawn's command and its arguments under
// shell: true, not at the options beside it (cwd, env).
func TestSeveralArgsBlocks(t *testing.T) {
	e := engineForTest(t)
	h := func(call string) string { return "app.post('/b', (req, res) => {\n  " + call + ";\n});\n" }
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"the command", h("spawn(req.body.cmd, [], { shell: true })"), true},
		{"an argument", h("spawn('gradle', ['build', `-P${req.body.f}`], { shell: true })"), true},
		{"execFile's argument", h("execFile('git', ['log', req.query.ref], { shell: true })"), true},
		{"only the options", h("spawn('gradle', ['build'], { shell: true, cwd: req.body.dir })"), false},
		{"only the env", h("execFile('git', ['log'], { shell: true, env: { REF: req.query.ref } })"), false},
		{"no shell", h("spawn(req.body.cmd, [req.body.arg])"), false},
	} {
		fs, err := e.Scan("js", "a.js", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == "js-cmdi-spawn-shell"
		}
		if err != nil || got != c.want {
			t.Errorf("%s: reported %v (err %v), want %v", c.name, got, err, c.want)
		}
	}
}
