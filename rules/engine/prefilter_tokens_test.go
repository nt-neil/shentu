package engine

import "testing"

// TestPrefilterTokens: the first-pass filters match sinks and sources token by
// token, as the analysis does, not by names that merely occur somewhere: a large
// bundle with re.exec(s), a request variable and a url property is skipped by
// js-cmdi-exec, while child_process.exec with request.url is still scanned.
func TestPrefilterTokens(t *testing.T) {
	e := engineForTest(t)
	var r *crule
	for _, c := range e.byLang["js"] {
		if c.rule.ID == "js-cmdi-exec" {
			r = c
		}
	}
	if r == nil {
		t.Fatal("js-cmdi-exec not found")
	}
	for _, c := range []struct {
		src  string
		scan bool
	}{
		{"var m = re.exec(s);\nvar request = new XMLHttpRequest();\nopts.url = base + path;\n", false},
		{"const cp = require('child_process');\nexport async function GET(request) { cp.exec('curl ' + request.url); }\n", true},
	} {
		src := []byte(c.src)
		toks := lex("js", c.src, newBudget(e.Limits))
		names := nameSet(toks, map[string]bool{})
		scan := sinkNames(r, names, src) && hasSink(r, toks) && !e.skipBySources(r, names, src, newSrcIndex(toks, nil))
		if scan != c.scan {
			t.Errorf("%q: scanned %v, want %v", c.src, scan, c.scan)
		}
	}
}

// TestSourcePrefilterSound: for every rule the source filter skips on a sample,
// the analysis without the filter finds nothing either.
func TestSourcePrefilterSound(t *testing.T) {
	e := engineForTest(t)
	off := engineForTest(t)
	off.SourcePrefilter = false
	checked, skipped := 0, 0
	for lang, rs := range e.byLang {
		for _, owner := range rs {
			for _, s := range owner.rule.Samples {
				l := lang
				if s.Dialect != "" {
					l = s.Dialect
				}
				src := []byte(s.Code)
				toks := lex(l, s.Code, newBudget(e.Limits))
				names := nameSet(toks, map[string]bool{})
				for _, r := range rs {
					checked++
					if !sinkNames(r, names, src) || !hasSink(r, toks) || !e.skipBySources(r, names, src, newSrcIndex(toks, nil)) {
						continue
					}
					skipped++
					one := &Engine{byLang: map[string][]*crule{lang: {r}}, Limits: off.Limits}
					if fs, _ := one.Scan(l, "x", src); len(fs) > 0 {
						t.Errorf("the source filter skips %s, but it reports %v on a sample of %s", r.rule.ID, fs, owner.rule.ID)
					}
				}
			}
		}
	}
	t.Logf("pairs %d, skipped by the source filter %d", checked, skipped)
}
