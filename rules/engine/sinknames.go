package engine

// nameSet adds every identifier and variable of toks, also inside string
// interpolations, to set.
func nameSet(toks []Token, set map[string]bool) map[string]bool {
	for _, t := range toks {
		switch t.Kind {
		case Ident, Var:
			set[t.Text] = true
		case Str:
			for _, p := range t.Parts {
				nameSet(p.Toks, set)
			}
		}
	}
	return set
}

// sinkNames is a quick test before hasSink: a code pattern can match only where
// all of its names are in the file, and a text pattern only where its text is.
// Reading the names once per file keeps the cost of many rules low; hasSink then
// decides.
func sinkNames(r *crule, names map[string]bool, src []byte) bool {
	return anyName(r.sinks, r.textSinks, names, src)
}

// sourceNames: a rule with sources reports only from one of them (outside
// library mode, where parameters are input), so a file holding none of their
// names cannot give it a finding.
func sourceNames(r *crule, names map[string]bool, src []byte) bool {
	return len(r.sources) == 0 && len(r.textSources) == 0 || anyName(r.sources, r.textSources, names, src)
}

func anyName(code, text []*pat, names map[string]bool, src []byte) bool {
	for _, p := range code {
		all := true // every name of the pattern is matched token by token, so each must be in the file
		for _, t := range p.toks {
			if (t.Kind == Ident || t.Kind == Var) && !names[t.Text] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	for _, p := range text {
		if p.text.Match(src) {
			return true
		}
	}
	return false
}
