package engine

import (
	_ "embed"
	"slices"
	"strconv"
	"strings"
)

// arrUnsure reports whether the arr mark of the variable name cannot be
// believed: the file may write it some way the analysis does not follow.
// That is
//   - a reference, a foreach target, a destructuring or any extract()
//     (writtenOtherwise);
//   - a variable the file names outside every function body, or declares
//     global: another file's function can write it through global or
//     $GLOBALS;
//   - any $$name, ${...} or $GLOBALS in the file, or parse_str() with one
//     argument;
//   - passing it whole to a call that may take it by reference and put a
//     string there (arrCallUnsure);
//   - a variable the file assigns an object made with new (newBound): its
//     index is ArrayAccess's.
//
// Worked out once per name.
func (a *analysis) arrUnsure(name string) bool {
	if v, ok := a.arrRef[name]; ok {
		return v
	}
	if a.arrRef == nil {
		a.arrRef = map[string]bool{}
	}
	t := a.ftoks
	u := a.writtenOtherwise(name) || a.arrDynamic() || globalScoped(t, name) || newBound(t, name)
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
		if open, k := callOpenOf(t, j); open >= 1 {
			u = a.arrCallUnsure(t, open, k)
		}
	}
	a.arrRef[name] = u
	return u
}

// arrPath reports whether a value read under key may keep its arr mark: a
// variable of the function, or an index of one ($a, $a['k']). A member of an
// object ($this->x, $o->p) or what a call returned ($o->get()) may not: the
// object may be shared with another variable or rewritten by a method the
// analysis does not follow, so its array may be a string by then.
func arrPath(key string) bool {
	return !strings.Contains(key, sepCh+".") && !strings.Contains(key, sepCh+"()")
}

// allLitKeys reports whether every element of an array literal's elements
// (inner, between its brackets) has a literal key or none: 'db.host' => $v,
// 3 => $v, $v. A computed key ($k => $v, "k{$k}" => $v) or a spread (...$a)
// does not.
func allLitKeys(inner []Token) bool {
	for _, e := range splitTop(inner, isComma) {
		if len(e) == 0 {
			continue
		}
		if e[0].op("...") {
			return false
		}
		if k := indexTop(e, 0, isOp("=>")); k >= 0 && !(k == 1 && (e[0].Kind == Str && len(e[0].Parts) == 0 || e[0].Kind == Num)) {
			return false
		}
	}
	return true
}

// litKeysSure reports whether a foreach over iter may trust its litKeys mark:
// the array literal itself, or a variable the code does not write some way
// the analysis does not follow (arrUnsure: a reference, extract(), a call
// that may take it by reference, the global scope).
func (a *analysis) litKeysSure(iter []Token) bool {
	iter = stripParens(iter)
	if len(iter) > 0 && iter[0].op("[") || len(iter) > 1 && iter[0].word("array") && iter[1].op("(") {
		return true
	}
	return len(iter) == 1 && iter[0].Kind == Var && !a.arrUnsure(iter[0].Text)
}

// arrDynamic reports whether the file writes variables by a name it computes
// or through $GLOBALS: $$k, ${'x'}, $GLOBALS['x'], parse_str($s) with no
// array to fill (PHP 7 makes variables of it).
func (a *analysis) arrDynamic() bool {
	if a.arrDyn == nil {
		d := false
		t := a.ftoks
		for i := 0; i < len(t) && !d; i++ {
			switch {
			case t[i].op("$"), t[i].Kind == Var && t[i].Text == "$GLOBALS":
				d = true
			case (t[i].word("parse_str") || t[i].word("mb_parse_str")) && i+1 < len(t) && t[i+1].op("("):
				d = len(splitTop(inside(t, i+1, closeOf(t, i+1)), isComma)) < 2
			}
		}
		a.arrDyn = &d
	}
	return *a.arrDyn
}

// globalScoped reports whether the file names the variable name outside every
// function body (a variable of the global scope, which another file's
// function can write with global or $GLOBALS) or in a global statement.
func globalScoped(t []Token, name string) bool {
	depth, body := 0, []int{} // brace depth; the depths at which function bodies open
	pending := false          // after "function": its body is the next "{"
	for i, tk := range t {
		switch {
		case tk.word("function"):
			pending = true
		case tk.op(";") && pending:
			pending = false // an abstract or interface method: no body
		case tk.op("{"):
			depth++
			if pending {
				body, pending = append(body, depth), false
			}
		case tk.op("}"):
			if len(body) > 0 && body[len(body)-1] == depth {
				body = body[:len(body)-1]
			}
			depth--
		case tk.Kind == Var && tk.Text == name:
			if len(body) == 0 {
				return true
			}
			for k := i; k > 0 && (k == i || t[k].Kind == Var || t[k].op(",")); k-- {
				if t[k-1].word("global") {
					return true // global $a, $x;
				}
			}
		}
	}
	return false
}

// newBound reports whether the file assigns the variable an object made with
// new ($o = new Bag()): $o['k'] is then ArrayAccess's offsetGet, which may
// return anything, not an index of an array.
func newBound(t []Token, name string) bool {
	for i := 0; i+2 < len(t); i++ {
		if t[i].Kind == Var && t[i].Text == name && (t[i+1].op("=") || t[i+1].op("??=")) {
			j := i + 2
			if t[j].op("&") && j+1 < len(t) {
				j++
			}
			if t[j].word("new") {
				return true
			}
		}
	}
	return false
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

// notCalls are PHP words a "(" follows that call nothing: a variable in
// their parentheses is read, or declared.
var notCalls = words("if elseif while switch for foreach isset empty unset array list echo print return match catch " +
	"exit die include include_once require require_once and or xor not function fn use declare clone yield throw case new")

// arrCallUnsure reports whether the call whose "(" is t[open] may take its
// argument k by reference. A method, a constructor and a call of a computed
// name may; a function is read where the analysis can see it (mayTakeRef).
func (a *analysis) arrCallUnsure(t []Token, open, k int) bool {
	c := t[open-1]
	switch {
	case c.Kind == Var || c.op(")") || c.op("]") || c.op("}"):
		return true // $f($a), $o->{$m}($a), $fs[0]($a): a callee the analysis does not know
	case c.Kind != Ident:
		return false // ($a): parentheses, no call
	case open >= 2 && (memberOp(true, t[open-2]) || t[open-2].word("new") || t[open-2].op(`\`) && open >= 3 && t[open-3].word("new")):
		return true // $o->put($a), Helper::fill($a), new Box($a)
	case open >= 2 && t[open-2].word("function"), notCalls[strings.ToLower(c.Text)]:
		return false // function f($a) declares it; if ($a), isset($a) read it
	}
	return a.mayTakeRef(t, open-1, k)
}

//go:embed php_refparams.txt
var phpRefParamList string

// phpRefParams: per PHP internal function taking a parameter by reference,
// the places of those parameters, a negative one for a variadic (every place
// from -p-1 on).
var phpRefParams = func() map[string][]int {
	m := map[string][]int{}
	for _, l := range strings.Split(phpRefParamList, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || strings.HasPrefix(l, "#") {
			continue
		}
		for _, p := range strings.Split(f[1], ",") {
			n, _ := strconv.Atoi(strings.TrimSuffix(p, "+"))
			if strings.HasSuffix(p, "+") {
				n = -n - 1
			}
			m[f[0]] = append(m[f[0]], n)
		}
	}
	return m
}()

//go:embed wp_byvalue.txt
var wpByValueList string

// wpByValue are WordPress functions known to take their arguments by value
// (wp_byvalue.txt, each with why): maybe_unserialize() itself, and those code
// passes a settings array to.
var wpByValue = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(wpByValueList, "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			m[strings.ToLower(f[0])] = true
		}
	}
	return m
}()

// mayTakeRef reports whether the function named at t[n] may take its
// argument k by reference:
//   - a PHP internal function: when a parameter at that place is one
//     (php_refparams.txt);
//   - a function of this file: when its declaration writes & there;
//   - a function another file of the project declares: when that file
//     declares one of that name with a parameter by reference
//     (fileIndex.RefFuncs);
//   - any other function (WordPress's, another plugin's): yes, unless it
//     is one known to take arguments by value (wpByValue).
//
// In a pass with no project (the file scanned on its own), another file
// cannot be read, so a function this file does not declare may.
func (a *analysis) mayTakeRef(t []Token, n, k int) bool {
	name := strings.ToLower(t[n].Text)
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
	if phpBuiltins[name] {
		for _, p := range phpRefParams[name] {
			if p == k || p < 0 && k >= -p-1 {
				return true
			}
		}
		return false
	}
	if wpByValue[name] {
		return false
	}
	pr := a.cproj
	if pr == nil {
		pr = a.proj // the pass that follows calls
	}
	if pr == nil {
		return true
	}
	declared := false
	for _, f := range pr.declared["php"][name] {
		fi := pr.files[f]
		if fi == nil || fi.Limited {
			return true
		}
		if !slices.ContainsFunc(fi.Funcs, func(s string) bool { return strings.EqualFold(s, name) }) {
			continue // only a method of that name there
		}
		declared = true
		if slices.Contains(fi.RefFuncs, name) {
			return true
		}
	}
	return !declared // declared nowhere in the project: not known
}
