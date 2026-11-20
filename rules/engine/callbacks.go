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
// StorePostRequest $request). A file analysed without its tokens (a callee
// in another file of a project) counts, failing toward a finding.
func (a *analysis) laravelRequest(name string) bool {
	if v, ok := a.laravelVars[name]; ok {
		return v
	}
	if a.laravelVars == nil {
		a.laravelVars = map[string]bool{}
	}
	t, v := a.ftoks, len(a.ftoks) == 0 // a file analysed for a call without its tokens: unknown, kept
	for i, tk := range t {
		if tk.Kind == Ident && tk.Text == "Illuminate" || tk.Kind == Ident && strings.HasSuffix(tk.Text, "Request") && i+1 < len(t) && t[i+1].Kind == Var && t[i+1].Text == name ||
			tk.Kind == Ident && strings.HasSuffix(tk.Text, "Controller") && i > 0 && t[i-1].word("extends") {
			v = true
			break
		}
	}
	a.laravelVars[name] = v
	return v
}
