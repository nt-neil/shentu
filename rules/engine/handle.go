package engine

import (
	"slices"
	"strings"
)

// The handle condition of [[args]] (handle = N with receiver, for a function
// sink: fwrite($fp, ...) counts only when $fp was made by fsockopen() or
// stream_socket_client()). It costs nothing when no loaded rule has one: the
// state below is written only for a rule with a handle condition, and a
// project keeps the property table only when some rule has one.
//
//   - A variable ($fp, and $this->fp within one method) is followed in the
//     analysis's own state: an assignment records which of the rule's receivers
//     made the value, and the next assignment to it replaces that, so within a
//     function the nearest assignment before the sink counts, and another
//     function's $fp of the same name does not.
//   - A property ($this->fp) set in another method, or in a class in another
//     file, is read from the file's property table: which receivers some
//     assignment to $this->x names (handleProps). Positions only: no token is
//     kept. A file with more than maxHandleProps property assignments has no
//     table; a handle read from it is not known (not reported) and the file's
//     scan records CutHandles.
//   - Not followed (not reported): a method's return value ($this->fp =
//     $this->connect()), a static property set in another method
//     (self::$conn), an array element, a foreach variable, list(), a parameter.

const (
	handleSt       = "\x00handle:" // state key prefix: handleSt + key + "\x00" + receiver
	maxHandleProps = 4096          // property assignments read per file
	maxHandleRHS   = 32            // tokens of a right side looked at
)

// handleProps is a file's property table: for each property name, the
// receivers (as the rules write them) some assignment to $this->name calls.
type handleProps struct {
	props map[string][]string
	cut   bool // more property assignments than maxHandleProps: nothing is known
}

// rhsEnd is the end of the right side starting at i: the first ";" or ","
// outside brackets, or the closing bracket of an enclosing one, at most
// maxHandleRHS tokens on.
func rhsEnd(toks []Token, i int) int {
	depth, j := 0, i
	for ; j < len(toks) && j-i < maxHandleRHS; j++ {
		switch {
		case toks[j].op("(") || toks[j].op("[") || toks[j].op("{"):
			depth++
		case toks[j].op(")") || toks[j].op("]") || toks[j].op("}"):
			if depth == 0 {
				return j
			}
			depth--
		case depth == 0 && (toks[j].op(";") || toks[j].op(",")):
			return j
		}
	}
	return j
}

// madeBy lists the receivers (raws, compiled as ps) that t calls.
func madeBy(t []Token, raws []string, ps []*pat) []string {
	var out []string
	for k, p := range ps {
		for i := range t {
			if p.at(t, i, false) {
				out = append(out, raws[k])
				break
			}
		}
	}
	return out
}

// buildHandleProps reads a PHP file's $this->x = ... assignments.
func buildHandleProps(toks []Token, raws []string, ps []*pat) *handleProps {
	h := &handleProps{props: map[string][]string{}}
	n := 0
	for i := 0; i+3 < len(toks); i++ {
		if toks[i].Kind != Var || toks[i].Text != "$this" || !toks[i+1].op("->") || toks[i+2].Kind != Ident || !toks[i+3].op("=") {
			continue
		}
		if n++; n > maxHandleProps {
			return &handleProps{cut: true}
		}
		name := toks[i+2].Text
		for _, r := range madeBy(toks[i+4:rhsEnd(toks, i+4)], raws, ps) {
			if !slices.Contains(h.props[name], r) {
				h.props[name] = append(h.props[name], r)
			}
		}
	}
	return h
}

// fileHandleProps is the property table a project keeps for a PHP file, or nil
// when no rule has a handle condition.
func (e *Engine) fileHandleProps(lang string, toks []Token) *handleProps {
	if lang != "php" || len(e.handleRaw) == 0 {
		return nil
	}
	return buildHandleProps(toks, e.handleRaw, e.handlePats)
}

// handleAssign records, for a rule with a handle condition, which of its
// receivers made what op assigns to key (rhs), replacing what key held.
func (a *analysis) handleAssign(st state, key string, rhs []Token, op string) {
	for _, r := range a.r.handleRaw {
		delete(st, handleSt+key+"\x00"+r)
	}
	if op != "=" {
		return
	}
	rhs = stripParens(rhs)
	for len(rhs) > 0 && rhs[0].op("@") {
		rhs = rhs[1:]
	}
	made := madeBy(rhs[:min(len(rhs), maxHandleRHS)], a.r.handleRaw, a.r.handlePats)
	if from, _, ok := a.pathKey(rhs); ok {
		for _, r := range a.r.handleRaw {
			if _, had := st[handleSt+from+"\x00"+r]; had && !slices.Contains(made, r) {
				made = append(made, r)
			}
		}
	}
	for _, r := range made {
		st[handleSt+key+"\x00"+r] = entry{san: true}
	}
}

// handleIs: the handle argument arg was made by one of cond's receivers: in
// place (fwrite(fsockopen(...), ...)), by the nearest assignment before the
// sink in this function, or, for $this->x, by an assignment to the property in
// its file (handleProps). Anything else is not one.
func (a *analysis) handleIs(st state, cond *argCond, arg []Token) bool {
	arg = stripParens(arg)
	for len(arg) > 0 && arg[0].op("@") {
		arg = arg[1:]
	}
	if len(madeBy(arg, cond.handleRecv, cond.receiver)) > 0 {
		return true
	}
	key, _, ok := a.pathKey(arg)
	if !ok {
		return false
	}
	for _, r := range cond.handleRecv {
		if _, had := st[handleSt+key+"\x00"+r]; had {
			return true
		}
	}
	prop, isProp := strings.CutPrefix(key, "$this"+sepCh+".")
	if !a.php || !isProp || strings.Contains(prop, sepCh) {
		return false
	}
	if a.hprops == nil && a.ftoks != nil {
		a.hprops = buildHandleProps(a.ftoks, a.r.handleRaw, a.r.handlePats)
	}
	if a.hprops == nil {
		return false
	}
	if a.hprops.cut {
		a.b.limited = true
		a.b.deep |= CutHandles
		return false
	}
	for _, r := range a.hprops.props[prop] {
		if slices.Contains(cond.handleRecv, r) {
			return true
		}
	}
	return false
}
