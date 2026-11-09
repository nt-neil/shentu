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

// sinkNames is a quick test before hasSink: a code sink can match only where
// its last name is in the file, and a text sink only where its text is. Reading
// the names once per file keeps the cost of many rules low; hasSink then
// decides.
func sinkNames(r *crule, names map[string]bool, src []byte) bool {
	for _, p := range r.sinks {
		k := ""
		for i := len(p.toks) - 1; i >= 0 && k == ""; i-- {
			if t := p.toks[i]; t.Kind == Ident || t.Kind == Var {
				k = t.Text
			}
		}
		if k == "" || names[k] {
			return true
		}
	}
	for _, p := range r.textSinks {
		if p.text.Match(src) {
			return true
		}
	}
	return false
}
