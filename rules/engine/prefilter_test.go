package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// For every rule hasSink skips on a sample or a tricky snippet, run the analysis
// anyway: it must find nothing (the prefilter only saves time).
func TestPrefilterSound(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	type src struct{ lang, code string }
	var corpus []src
	for _, r := range rs {
		for _, s := range r.Samples {
			corpus = append(corpus, src{r.Lang, s.Code})
		}
	}
	corpus = append(corpus,
		src{"php", "<?php\n$o = `ls {$_GET['d']}`;\n"},
		src{"php", "<?php\n$c = $_GET['c'];\necho `$c`;\n"},
		src{"php", "<?php\n$x = <<<EOT\n{${system($_GET['c'])}}\nEOT;\n"},
		src{"php", "<?php\n$f = 'system';\n$f($_GET['c']);\n"},
		src{"php", "<?php\ncall_user_func('system', $_GET['c']);\n"},
		src{"php", "<?php\nSYSTEM($_GET['c']);\n"},
		src{"php", "<?php\n\\system($_GET['c']);\n"},
		src{"python", "import os\nx = request.args['c']\ngetattr(os, 'system')(x)\n"},
		src{"python", "from os import system as s\ns(request.args['c'])\n"},
		src{"js", "const { exec } = require('child_process')\nexec(req.query.c)\n"},
		src{"js", "const cp = require('child_process')\nconst run = cp.exec\nrun(req.query.c)\n"},
	)
	checked, skipped := 0, 0
	for _, c := range corpus {
		b := newBudget(e.Limits)
		toks := lex(c.lang, c.code, b)
		tree := parse(c.lang, toks, b)
		funcs := collectFuncs(tree, c.lang)
		for _, r := range e.byLang[c.lang] {
			checked++
			if hasSink(r, toks) {
				continue
			}
			skipped++
			a := &analysis{r: r, php: c.lang == "php", py: c.lang == "python", js: c.lang == "js", b: b, kw: keywords[c.lang], seen: map[int]bool{}, sc: newSummaries(funcs)}
			a.block(tree, state{})
			if len(a.lines) > 0 {
				t.Errorf("prefilter skipped %s but analysis reports %v on:\n%s", r.rule.ID, a.lines, c.code)
			}
		}
	}
	t.Logf("pairs %d, skipped by prefilter %d", checked, skipped)
}
