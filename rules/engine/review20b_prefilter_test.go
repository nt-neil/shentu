package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// The name prefilter must never drop a rule hasSink would keep. Checks every
// rule sample and the PHP/Python/JS samples of the held-out style below.
func TestR20bPrefilter(t *testing.T) {
	rs, _ := rules.Load()
	e, _ := New(rs)
	srcs := []struct{ lang, src string }{
		{"php", "<?php\nSYSTEM($_GET['c']);\nEcho $_GET['x'];\n"},
		{"php", "<?php\n$f = 'system';\n$f($_GET['c']);\ncall_user_func('system', $_GET['c']);\n"},
		{"js", "app.get('/x', (req, res) => { res['send'](req.query.q); child_process['exec'](req.query.c); });\n"},
		{"js", "db.collection('u').find({ '$where': req.body.w });\n"},
		{"python", "getattr(os, 'system')(request.args['c'])\n"},
	}
	for _, r := range rs {
		for _, s := range r.Samples {
			srcs = append(srcs, struct{ lang, src string }{r.Lang, s.Code})
		}
	}
	bad := 0
	for _, s := range srcs {
		b := newBudget(e.Limits)
		toks := lex(s.lang, s.src, b)
		names := nameSet(toks, map[string]bool{})
		for _, r := range e.byLang[s.lang] {
			if hasSink(r, toks) && !sinkNames(r, names, []byte(s.src)) {
				bad++
				t.Errorf("prefilter drops %s on %q", r.rule.ID, s.src)
			}
		}
	}
	t.Logf("%d sources checked, %d dropped", len(srcs), bad)
}
