package engine

import "strings"

// arrUnsure reports whether the arr mark of the variable name cannot be
// believed: the file writes it some way the analysis does not follow
// (writtenOtherwise: a reference, a foreach target, a destructuring, any
// extract()), or passes it whole to a call that may take it by reference and
// put a string there (set($a) of function set(&$x)). A function or method of
// this file is read for an & at that place; one only another file of the
// project declares is taken to; of the others, only PHP functions that write
// a string through a reference argument (sscanf, openssl_open, ...) do.
// Worked out once per name.
func (a *analysis) arrUnsure(name string) bool {
	if v, ok := a.arrRef[name]; ok {
		return v
	}
	if a.arrRef == nil {
		a.arrRef = map[string]bool{}
	}
	u := a.writtenOtherwise(name)
	t := a.ftoks
	for i := 1; i+1 < len(t) && !u; i++ {
		if t[i].Kind != Var || t[i].Text != name || !(t[i+1].op(",") || t[i+1].op(")")) {
			continue
		}
		j := i - 1
		if t[j].op("&") {
			j-- // f(&$a): an old call-time reference
		}
		if j < 0 || !(t[j].op("(") || t[j].op(",")) {
			continue
		}
		open, k := callOpenOf(t, j)
		if open < 1 || t[open-1].Kind != Ident {
			continue
		}
		u = a.mayTakeRef(t, open-1, k)
	}
	a.arrRef[name] = u
	return u
}

// callOpenOf returns the "(" of the call whose argument list holds t[j] (that
// "(" itself, or a comma at its top level) and the argument's place (from 0).
func callOpenOf(t []Token, j int) (int, int) {
	k, depth := 0, 0
	for ; j >= 0 && depth >= 0; j-- {
		switch {
		case isClose(t[j]):
			depth++
		case isOpen(t[j]) && depth > 0:
			depth--
		case isOpen(t[j]):
			if !t[j].op("(") {
				return -1, 0
			}
			return j, k
		case t[j].op(",") && depth == 0:
			k++
		}
	}
	return -1, 0
}

// refWriters are PHP functions that write a string made from their input
// through a reference argument: the first such argument's place (from 0).
var refWriters = map[string]int{"sscanf": 2, "openssl_open": 1, "openssl_private_decrypt": 1, "openssl_public_decrypt": 1}

// mayTakeRef reports whether the function or method named at t[n] may take
// its argument k by reference.
func (a *analysis) mayTakeRef(t []Token, n, k int) bool {
	name := strings.ToLower(t[n].Text)
	if at, ok := refWriters[name]; ok && !(n > 0 && memberOp(true, t[n-1])) {
		return k >= at
	}
	found := false
	for i := 0; i+2 < len(t); i++ {
		if !t[i].word("function") || !strings.EqualFold(t[i+1].Text, t[n].Text) || !t[i+2].op("(") {
			continue
		}
		found = true
		for q, p := range splitTop(inside(t, i+2, closeOf(t, i+2)), isComma) {
			ref, rest := false, false
			for _, x := range p {
				ref = ref || x.op("&")
				rest = rest || x.op("...")
			}
			if ref && (q == k || rest && q <= k) {
				return true
			}
		}
	}
	if found {
		return false
	}
	if a.cproj != nil {
		for _, f := range a.cproj.declared["php"][name] {
			if f != a.file {
				return true // declared in another file: its parameters are not read here
			}
		}
	}
	return false
}
