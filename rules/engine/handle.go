package engine

import "slices"

// handleIs is the handle condition of [[args]]: the argument holding a function
// sink's handle (fwrite($fp, ...)) was made by one of ps. The argument, or what
// its root ($fp, $this->fp in PHP; x, self.x elsewhere) is assigned in the
// file, followed a few steps, must name one of them. Unlike recvIs, a root the
// file says nothing about (a parameter, a name from another file) is not one:
// a handle of unknown origin is not taken for a socket.
func (a *analysis) handleIs(ps []*pat, arg []Token) bool {
	if a.hdefs == nil {
		if a.php {
			a.hdefs = phpHandleDefs(a.ftoks)
		} else {
			if a.rdefs == nil {
				a.rdefs = recvDefs(a.ftoks)
			}
			a.hdefs = a.rdefs
		}
	}
	seen := map[string]bool{}
	var is func(t []Token, depth int) bool
	is = func(t []Token, depth int) bool {
		t = stripParens(t)
		for i := range t {
			for _, p := range ps {
				if p.at(t, i, false) {
					return true
				}
			}
		}
		if depth >= 4 || len(t) == 0 {
			return false
		}
		key, ok := handleKey(t)
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		for _, d := range a.hdefs[key] {
			if is(d, depth+1) {
				return true
			}
		}
		return false
	}
	return is(arg, 0)
}

// handleKey is the name t is as a whole: $fp, $this->fp, x or self.x (also cls.x).
func handleKey(t []Token) (string, bool) {
	switch {
	case len(t) == 1 && (t[0].Kind == Var || t[0].Kind == Ident):
		return t[0].Text, true
	case len(t) == 3 && t[0].Kind == Var && t[0].Text == "$this" && t[1].op("->") && t[2].Kind == Ident:
		return "$this->" + t[2].Text, true
	case len(t) == 3 && t[0].Kind == Ident && (t[0].Text == "self" || t[0].Text == "cls") && t[1].op(".") && t[2].Kind == Ident:
		return "self." + t[2].Text, true
	}
	return "", false
}

// phpHandleDefs maps, for one PHP file, $x and $this->x to the right side of
// each plain assignment to them ($fp = fsockopen(...);).
func phpHandleDefs(toks []Token) map[string][][]Token {
	defs := map[string][][]Token{}
	for i := 0; i < len(toks); i++ {
		if toks[i].Kind != Var || i > 0 && (toks[i-1].op("->") || toks[i-1].op("::") || toks[i-1].op("$")) {
			continue
		}
		key, k := toks[i].Text, i+1
		if key == "$this" {
			if i+3 >= len(toks) || !toks[i+1].op("->") || toks[i+2].Kind != Ident {
				continue
			}
			key, k = "$this->"+toks[i+2].Text, i+3
		}
		if k+1 >= len(toks) || !toks[k].op("=") {
			continue
		}
		depth, j := 0, k+1
		for ; j < len(toks) && j-k < 256; j++ {
			if toks[j].op("(") || toks[j].op("[") || toks[j].op("{") {
				depth++
			} else if toks[j].op(")") || toks[j].op("]") || toks[j].op("}") {
				if depth == 0 {
					break
				}
				depth--
			} else if depth == 0 && (toks[j].op(";") || toks[j].op(",")) {
				break
			}
		}
		if j-(k+1) <= maxHandleDef {
			defs[key] = append(defs[key], slices.Clone(toks[k+1:j])) // a copy: the file's tokens need not stay
		}
	}
	return defs
}

// maxHandleDef: a longer right side is not a handle being made.
const maxHandleDef = 32

// fileHandleDefs is phpHandleDefs for a PHP file kept by a project, so an
// analysis of one of its functions made from another file reads this file's
// assignments ($this->fp = stream_socket_client(...) in connect()).
func fileHandleDefs(lang string, toks []Token) map[string][][]Token {
	if lang != "php" {
		return nil
	}
	return phpHandleDefs(toks)
}
