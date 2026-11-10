package engine

// recvDefs maps, for one file, a name to what the code says it holds: the
// right side of each assignment to it (x = ..., self.x = ..., with or without
// an annotation) and the annotation of a parameter or variable of that name
// (db: Database). self.x and cls.x are kept as "self.x". The receiver
// condition of [[args]] follows a receiver back through these.
func recvDefs(toks []Token) map[string][][]Token {
	defs := map[string][][]Token{}
	stmt := func(i int) []Token { // the rest of the line, or of the bracketed expression
		depth := 0
		j := i
		for ; j < len(toks); j++ {
			if depth == 0 && j > i && toks[j].Line != toks[j-1].Line || depth == 0 && toks[j].op(";") {
				break
			}
			switch {
			case toks[j].op("(") || toks[j].op("[") || toks[j].op("{"):
				depth++
			case toks[j].op(")") || toks[j].op("]") || toks[j].op("}"):
				if depth == 0 {
					return toks[i:j]
				}
				depth--
			}
			if j-i > 256 {
				break
			}
		}
		return toks[i:j]
	}
	for i := 0; i+2 < len(toks); i++ {
		if toks[i].Kind != Ident {
			continue
		}
		key, k := toks[i].Text, i+1
		if (key == "self" || key == "cls") && toks[i+1].op(".") && toks[i+2].Kind == Ident {
			if i > 0 && toks[i-1].op(".") {
				continue
			}
			key, k = "self."+toks[i+2].Text, i+3
		} else if i > 0 && toks[i-1].op(".") {
			continue // a member of something else
		}
		if k >= len(toks) {
			continue
		}
		switch {
		case toks[k].op("="):
			if k+1 < len(toks) {
				defs[key] = append(defs[key], stmt(k+1))
			}
		case toks[k].op(":"): // an annotation: a parameter, or a variable declared with its type
			if k+1 < len(toks) {
				ann := stmt(k + 1)
				for j, t := range ann {
					if t.op(",") || t.op("=") {
						ann = ann[:j]
						break
					}
				}
				defs[key] = append(defs[key], ann)
			}
		}
	}
	return defs
}

// recvIs reports whether the receiver of a method sink is one of the kinds the
// patterns name: one appears in it, or in what its root (x, self.x) is assigned
// or annotated with in the file, followed a few steps.
func (a *analysis) recvIs(ps []*pat, recv []Token) bool {
	if a.rdefs == nil {
		a.rdefs = recvDefs(a.ftoks)
	}
	seen := map[string]bool{}
	var is func(t []Token, depth int) bool
	is = func(t []Token, depth int) bool {
		for i := range t {
			for _, p := range ps {
				if p.at(t, i, false) {
					return true
				}
			}
		}
		if depth >= 4 || len(t) == 0 || t[0].Kind != Ident {
			return false
		}
		key := t[0].Text
		if (key == "self" || key == "cls") && len(t) > 2 && t[1].op(".") && t[2].Kind == Ident {
			key = "self." + t[2].Text
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		for _, d := range a.rdefs[key] {
			if is(d, depth+1) {
				return true
			}
		}
		return false
	}
	return is(recv, 0)
}
