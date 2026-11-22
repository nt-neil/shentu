package engine

import (
	"slices"
	"strings"
)

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
func (a *analysis) whenSeeds(st state, t []Token, funcs []*fn) map[*fn][]*paramSeed {
	if !a.php || len(funcs) == 0 {
		return nil
	}
	var out map[*fn][]*paramSeed
	for i := 1; i+1 < len(t); i++ {
		if !(t[i].word("when") || t[i].word("unless")) || !memberOp(true, t[i-1]) || !t[i+1].op("(") {
			continue
		}
		args := splitTop(inside(t, i+1, closeOf(t, i+1)), isComma)
		if len(args) < 2 || len(args[1]) != 1 || args[1][0].Kind != Func || args[1][0].Fn >= len(funcs) {
			continue
		}
		if out == nil {
			out = map[*fn][]*paramSeed{}
		}
		f := funcs[args[1][0].Fn]
		out[f] = append(out[f], &paramSeed{param: 1, v: a.expr(st, args[0], false)})
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

// phpUseOther reports whether the file's use statements make the class name
// another library's than Laravel's: use Httpful\Request (or Unirest\Request)
// makes Request::get( an HTTP client's call, not the Request facade. A name
// no use statement gives, or one from Illuminate, is not another's.
func (a *analysis) phpUseOther(name string) bool {
	if a.phpUses == nil {
		a.phpUses = map[string]string{}
		t := a.ftoks
		for i := 0; i+1 < len(t); i++ {
			if !t[i].word("use") || i > 0 && !(t[i-1].op(";") || t[i-1].op("{") || t[i-1].op("}") || t[i-1].Kind == Newline || t[i-1].Text == "<?php") {
				continue
			}
			j, q := i+1, ""
			for j < len(t) && (t[j].Kind == Ident && !t[j].word("as") || t[j].op("\\")) {
				q += t[j].Text
				j++
			}
			if j < len(t) && t[j].op("{") || q == "" {
				continue // a group use names its classes inside the braces
			}
			short := q[strings.LastIndex(q, "\\")+1:]
			if j+1 < len(t) && t[j].word("as") && t[j+1].Kind == Ident {
				short = t[j+1].Text
			}
			a.phpUses[strings.ToLower(short)] = strings.TrimPrefix(q, "\\")
		}
	}
	q, ok := a.phpUses[strings.ToLower(name)]
	return ok && !strings.HasPrefix(strings.ToLower(q), "illuminate\\") && strings.Contains(q, "\\")
}

// fnParamNames lists a function's parameter names, in order ("" where a
// parameter has no plain name).
func fnParamNames(f *fn) []string {
	n := len(splitTop(f.params, isComma))
	out := make([]string, n)
	for k := range n {
		out[k] = paramName(f.params, k)
	}
	return out
}

// paramIndex returns which parameter of the function being analysed name is,
// or -1: a PHP $callback(...) of one is called with what the caller passed
// (summary.pcall), not with another file's $callback.
func (a *analysis) paramIndex(name string) int {
	if !a.isParamName(name) || a.curMoved[name] {
		return -1
	}
	return slices.Index(a.curParams, name)
}

// isParamName reports whether name is a parameter of the function being
// analysed, assigned again in its body or not: either way it is no other
// file's $callback.
func (a *analysis) isParamName(name string) bool {
	return a.php && strings.HasPrefix(name, "$") && slices.Contains(a.curParams, name)
}

// paramsMoved returns the parameters a function's body may write: every use of
// one but a call ($cb(...)) or a whole argument or parenthesized operand
// (f($cb), if ($cb)) counts, so an assignment ($cb = wrap($cb), $cb .= ...),
// destructuring ([$cb] = ..., list($cb) = ...), a foreach target (as $cb), a
// reference (&$cb) and any other expression are all moves. Nested functions'
// tokens are included (a closure using a variable of that name moves it too).
// The safe side: after a move a call of it is cut, not followed. A whole
// argument handed to a by-reference parameter is not seen.
func paramsMoved(body []*stmt, params []string) map[string]bool {
	var out map[string]bool
	walkToks(body, 0, func(t []Token) {
		for i := range t {
			if t[i].Kind != Var || !slices.Contains(params, t[i].Text) || i > 0 && memberOp(true, t[i-1]) {
				continue
			}
			called := i+1 < len(t) && t[i+1].op("(")
			whole := i > 0 && (t[i-1].op("(") || t[i-1].op(",")) && i+1 < len(t) && (t[i+1].op(")") || t[i+1].op(","))
			if whole && i > 1 && t[i-1].op("(") && (t[i-2].word("list") || t[i-2].word("array")) {
				whole = false // list($cb) = ...: a target
			}
			if !called && !whole {
				if out == nil {
					out = map[string]bool{}
				}
				out[t[i].Text] = true
			}
		}
	})
	return out
}

// pcallSeeds finds, in a PHP statement, calls of a function whose summary
// calls one of its parameters (summary.pcall: tap($value, $callback), Arr::
// first($array, $callback)) and follows the callable passed there:
//   - a closure literal: its parameters are seeded with what the callee passes
//     them (the input of the call's arguments the effect names), so its sinks
//     are found;
//   - the caller's own parameter: the effect moves up into the caller's
//     summary (a.summ.pcall), to be followed where that is called;
//   - anything else, when input would reach it: cut as callable-param, said,
//     not followed (a function name, [$obj, 'm'] and foo(...) are not yet).
func (a *analysis) pcallSeeds(st state, t []Token, funcs []*fn) map[*fn][]*paramSeed {
	if !a.php {
		return nil
	}
	var out map[*fn][]*paramSeed
	for i := 0; i+1 < len(t); i++ {
		if !t[i+1].op("(") || t[i].Kind != Ident && t[i].Kind != Var {
			continue
		}
		if t[i].Kind == Var && (i == 0 || !memberOp(true, t[i-1])) {
			// $callback(...) of a parameter: the input its arguments carry is
			// what the function gives the callable (summary.pcall)
			if a.isParamName(t[i].Text) && a.paramIndex(t[i].Text) < 0 {
				// a parameter the body assigned again ($cb = wrap($cb)): what it
				// calls is not followed; with input in its arguments, said
				for _, arg := range callArgs(t, i+1) {
					if a.expr(st, arg, false).taint {
						a.b.tooDeepFor(CutCallableParam)
						break
					}
				}
				continue
			}
			if p := a.paramIndex(t[i].Text); p >= 0 {
				record := a.summ != nil && a.nested == 0
				for k, arg := range callArgs(t, i+1) {
					if !a.expr(st, arg, false).taint {
						continue
					}
					if record {
						a.summ.pcall[[2]int{p, k}] = true
					} else {
						// input reaches a callable no summary takes the effect
						// of (a closure's own parameter, a function analysed
						// on its own): said, not followed
						a.b.tooDeepFor(CutCallableParam)
					}
				}
				continue
			}
		}
		if t[i].Kind == Ident && (declWords[t[i].Text] || t[i].word("function") || t[i].word("fn")) {
			continue
		}
		sum := a.callSummary(t, i, a.calleeKey(t, i))
		if sum == nil || len(sum.pcall) == 0 && len(sum.pcallSrc) == 0 {
			continue
		}
		args, mapped := byParam(callArgs(t, i+1), sum.params)
		if !mapped {
			// a named argument no parameter has, or a spread: the arguments
			// cannot be put in the callee's places. With input in any of them,
			// the callable may get it: said, not followed
			for _, arg := range callArgs(t, i+1) {
				if a.expr(st, arg, false).taint {
					a.b.tooDeepFor(CutCallableParam)
					break
				}
			}
			continue
		}
		for _, n := range sortedKeys2(sum.pcall, sum.pcallSrc) {
			masks, srcs := sum.pcall[n], sum.pcallSrc[n]
			seed := func(k int) val {
				var v val
				if k < len(masks) {
					for m := range args {
						if m < 64 && masks[k]&(1<<m) != 0 && args[m] != nil {
							v = or(v, a.expr(st, args[m], false))
						}
					}
				}
				if k < len(srcs) && srcs[k] {
					v.taint = true
				}
				return v
			}
			width := max(len(masks), len(srcs))
			input := false
			for k := range width {
				input = input || seed(k).taint
			}
			switch {
			case n >= len(args) || args[n] == nil:
				if input {
					a.b.tooDeepFor(CutCallableParam)
				}
			case len(args[n]) == 1 && args[n][0].Kind == Func && args[n][0].Fn < len(funcs):
				f := funcs[args[n][0].Fn]
				if out == nil {
					out = map[*fn][]*paramSeed{}
				}
				for k := range width {
					out[f] = append(out[f], &paramSeed{param: k, v: seed(k)})
				}
			case len(args[n]) == 1 && args[n][0].Kind == Var && a.paramIndex(args[n][0].Text) >= 0:
				if a.summ != nil && a.nested == 0 {
					p := a.paramIndex(args[n][0].Text)
					for k := range width {
						if seed(k).taint {
							a.summ.pcall[[2]int{p, k}] = true
						}
					}
				}
			case input:
				a.b.tooDeepFor(CutCallableParam)
			}
		}
	}
	return out
}

// sortedKeys2 is the sorted union of two maps' keys.
func sortedKeys2[V1, V2 any](x map[int]V1, y map[int]V2) []int {
	var out []int
	for k := range x {
		out = append(out, k)
	}
	for k := range y {
		if _, ok := x[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// callsParam reports whether a PHP function's body calls one of its own
// parameters ($callback(...)), outside nested functions as well as in them (a
// closure there may call it through use).
func callsParam(fi *fnInfo) bool {
	found := false
	walkToks(fi.f.body, 0, func(t []Token) {
		for i := 0; !found && i+1 < len(t); i++ {
			found = t[i].Kind == Var && t[i+1].op("(") && slices.Contains(fi.params, t[i].Text)
		}
	})
	return found
}

// byParam puts a PHP call's arguments in the callee's parameter places: by
// position, then by name for named arguments (tap(callback: fn () => ...,
// value: $v)); a place no argument fills is nil. mapped is false when an
// argument has a name no parameter has, or is a spread (...$args).
func byParam(args [][]Token, params []string) ([][]Token, bool) {
	var out [][]Token
	for i, arg := range args {
		if len(arg) > 0 && arg[0].op("...") {
			return nil, false
		}
		if len(arg) > 1 && arg[0].Kind == Ident && arg[1].op(":") {
			p := slices.Index(params, "$"+arg[0].Text)
			if p < 0 {
				return nil, false
			}
			for len(out) <= p {
				out = append(out, nil)
			}
			out[p] = arg[2:]
			continue
		}
		for len(out) <= i {
			out = append(out, nil)
		}
		out[i] = arg
	}
	return out, true
}
