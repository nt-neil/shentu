package engine

import "strings"

// A callback some calls are known to call with a value they were given:
// Laravel's $query->when($value, fn ($q, $v) => ...) (and ->unless) calls the
// closure with the query and $value, so $v holds what $value held.

// paramSeed: the parameter (from 0) of a function literal and the value it
// is called with.
type paramSeed struct {
	param int
	v     val
}

// whenSeeds finds, in a PHP statement, the closures written as the second
// argument of ->when( or ->unless( (also ::when(), and the value their
// second parameter is called with: the call's first argument.
func (a *analysis) whenSeeds(st state, t []Token, funcs []*fn) map[*fn]*paramSeed {
	if !a.php || len(funcs) == 0 {
		return nil
	}
	var out map[*fn]*paramSeed
	for i := 1; i+1 < len(t); i++ {
		if !(t[i].word("when") || t[i].word("unless")) || !memberOp(true, t[i-1]) || !t[i+1].op("(") {
			continue
		}
		args := splitTop(inside(t, i+1, closeOf(t, i+1)), isComma)
		if len(args) < 2 || len(args[1]) != 1 || args[1][0].Kind != Func || args[1][0].Fn >= len(funcs) {
			continue
		}
		if out == nil {
			out = map[*fn]*paramSeed{}
		}
		out[funcs[args[1][0].Fn]] = &paramSeed{param: 1, v: a.expr(st, args[0], false)}
	}
	return out
}

// paramName returns the name of parameter k (from 0) of a parameter list:
// its last variable ($s of string $s = 'x'), or "".
func paramName(params []Token, k int) string {
	parts := splitTop(params, isComma)
	if k >= len(parts) {
		return ""
	}
	name := ""
	for _, tk := range parts[k] {
		if tk.op("=") {
			break
		}
		if tk.Kind == Var || tk.Kind == Ident {
			name = tk.Text
		}
	}
	return name
}

// laravelRequest reports whether the PHP variable name may be Laravel's
// request, whose magic properties ($request->sort) are input: the file
// imports from Illuminate, holds a class extending a Controller, or declares
// the variable with a type named Request or ending in it (Request $request,
// StorePostRequest $request). In a project some PHP file of which uses a
// class of Illuminate, an untyped parameter of that name counts too (a
// service the controller passes the request to). A file analysed without its
// tokens (a callee in another file of a project) counts, failing toward a
// finding.
func (a *analysis) laravelRequest(name string) bool {
	if v, ok := a.laravelVars[name]; ok {
		return v
	}
	if a.laravelVars == nil {
		a.laravelVars = map[string]bool{}
	}
	t, v := a.ftoks, len(a.ftoks) == 0 // a file analysed for a call without its tokens: unknown, kept
	for i, tk := range t {
		if tk.Kind == Ident && strings.EqualFold(tk.Text, "Illuminate") || tk.Kind == Ident && strings.HasSuffix(tk.Text, "Request") && i+1 < len(t) && t[i+1].Kind == Var && t[i+1].Text == name ||
			tk.Kind == Ident && strings.HasSuffix(tk.Text, "Controller") && i > 0 && t[i-1].word("extends") {
			v = true
			break
		}
	}
	if !v && (a.proj != nil && a.proj.laravel || a.cproj != nil && a.cproj.laravel) {
		// a Laravel project: a service's untyped $request parameter is the
		// request a controller passed on (apply($q, $request)); a typed one
		// (SearchQuery $request) is that type
		v = untypedParam(t, name)
	}
	a.laravelVars[name] = v
	return v
}

// untypedParam reports whether name is a parameter of a function of the file
// declared without a type: function apply($q, $request), fn ($request) => ...
func untypedParam(t []Token, name string) bool {
	for j := 1; j < len(t); j++ {
		if t[j].Kind != Var || t[j].Text != name {
			continue
		}
		b := j - 1 // before the name: by reference (&$request) or variadic (...$request)
		for b > 0 && (t[b].op("&") || t[b].op("...")) {
			b--
		}
		if !(t[b].op("(") || t[b].op(",")) {
			continue
		}
		depth := 0
		for k := b; k >= 1; k-- {
			switch {
			case isClose(t[k]):
				depth++
			case isOpen(t[k]):
				if depth > 0 {
					depth--
					continue
				}
				h := k - 1 // function name(, function &name(, function (, function &(, fn (
				if h > 0 && t[h].Kind == Ident && !t[h].word("function") && !t[h].word("fn") {
					h--
				}
				if h > 0 && t[h].op("&") {
					h--
				}
				if t[k].op("(") && (t[h].word("function") || t[h].word("fn")) {
					return true
				}
				k = 0
			}
		}
	}
	return false
}
