package engine

import (
	"strings"
	"testing"
	"time"
)

// hasSourceByScan is what the source index replaced: every rule reading every
// token. The index must say the same.
func hasSourceByScan(r *crule, toks []Token) bool {
	if len(r.sources) == 0 && len(r.textSources) == 0 {
		return true
	}
	for i := range toks {
		for _, s := range r.sources {
			if s.text == nil && (s.at(toks, i, false) || s.baseAt(toks, i)) {
				return true
			}
		}
		if toks[i].Kind == Str {
			for _, s := range r.textSources {
				if s.text.MatchString(toks[i].Text) {
					return true
				}
			}
			for _, p := range toks[i].Parts {
				if hasSourceByScan(r, p.Toks) {
					return true
				}
			}
		}
	}
	return false
}

// TestSourceIndexAsScan: for every rule and every sample of its language, the
// index finds a source, a sink and their names exactly where reading every
// token for every rule does.
func TestSourceIndexAsScan(t *testing.T) {
	e := engineForTest(t)
	checked, found := 0, 0
	for lang, rs := range e.byLang {
		for _, owner := range rs {
			for _, s := range owner.rule.Samples {
				l := lang
				if s.Dialect != "" {
					l = s.Dialect
				}
				toks := lex(l, s.Code, newBudget(e.Limits))
				si := newSrcIndex(toks, nil)
				src, names := []byte(s.Code), nameSet(toks, map[string]bool{})
				for _, r := range rs {
					want := hasSourceByScan(r, toks)
					if got := si.hasSource(r); got != want {
						t.Errorf("%s on a sample of %s: index %v, scan %v", r.rule.ID, owner.rule.ID, got, want)
					}
					if got, want := si.hasSink(r), hasSink(r, toks); got != want {
						t.Errorf("%s on a sample of %s: sink by the index %v, by scan %v", r.rule.ID, owner.rule.ID, got, want)
					}
					if got, want := si.names(r.sinks, r.textSinks, names, src), sinkNames(r, names, src); got != want {
						t.Errorf("%s on a sample of %s: sink names by the index %v, without %v", r.rule.ID, owner.rule.ID, got, want)
					}
					if got, want := e.skipBySources(r, names, src, si), !sourceNames(r, names, src) || !want; got != want {
						t.Errorf("%s on a sample of %s: skipped by the index %v, without %v", r.rule.ID, owner.rule.ID, got, want)
					}
					checked++
					if want {
						found++
					}
				}
			}
		}
	}
	if checked == 0 || found == 0 || found == checked {
		t.Fatalf("checked %d, found %d: nothing compared", checked, found)
	}
}

// TestSourceIndexClock: out of time, the search stops, says yes and cuts the
// file's scan on its clock.
func TestSourceIndexClock(t *testing.T) {
	p, err := compilePattern("php", "read_input(", false)
	if err != nil {
		t.Fatal(err)
	}
	r := &crule{sources: []*pat{p}}
	src := "<?php " + strings.Repeat("read_input; ", 5000) // the first token everywhere, the source nowhere
	b := newBudget(DefaultLimits)
	toks := lex("php", src, b)
	b.deadline = time.Now().Add(-time.Second)
	si := newSrcIndex(toks, b)
	if hasSourceByScan(r, toks) {
		t.Fatal("the sample holds the source")
	}
	if !si.hasSource(r) || !b.hit || !b.timeHit {
		t.Errorf("past the deadline: hit %v timeHit %v, want the scan cut by its clock", b.hit, b.timeHit)
	}
}
