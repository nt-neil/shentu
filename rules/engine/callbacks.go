package engine

import (
	_ "embed"
	"slices"
	"strconv"
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

// paramsMoved returns the parameters a function's body may write, nested
// functions' tokens included (a closure writing a variable of that name moves
// it too):
//   - assigned: $cb = ..., $cb .= ..., $cb ??= ... (comparisons are reads);
//   - a destructuring target, at any depth: [$cb] = ..., [[$a, $cb]] = ...,
//     list($x, $cb) = ...;
//   - a foreach target, destructured too: as $cb, as $k => $cb, as [$a, $cb];
//   - referenced: &$cb (=& $cb, use (&$cb), f(&$cb));
//   - declared again: global $cb, static $cb, catch (E $cb).
//
// Reads ($cb === null, $cb instanceof Closure, f($cb)) are not moves. After a
// move a call of it is cut, not followed. Not seen: a whole argument handed to
// a by-reference parameter (preg_match($p, $s, $cb)).
func paramsMoved(body []*stmt, params []string) map[string]bool {
	var out map[string]bool
	reads := map[string]bool{"==": true, "===": true, "!=": true, "!==": true, "<=": true, ">=": true, "=>": true, "<=>": true}
	walkToks(body, 0, func(t []Token) {
		for i := range t {
			if t[i].Kind != Var || !slices.Contains(params, t[i].Text) || i > 0 && memberOp(true, t[i-1]) {
				continue
			}
			moved := false
			switch {
			case i+1 < len(t) && t[i+1].Kind == Op && strings.HasSuffix(t[i+1].Text, "=") && !reads[t[i+1].Text]:
				moved = true // assigned
			case i > 0 && t[i-1].op("&"):
				moved = true // referenced
			case foreachTarget(t, i):
				moved = true // a foreach target
			case i > 0 && (t[i-1].word("global") || t[i-1].word("static")) || i > 1 && t[i-1].Kind == Ident && t[i-2].op("(") && i > 2 && t[i-3].word("catch"):
				moved = true // declared again
			case destructured(t, i):
				moved = true
			}
			if moved {
				if out == nil {
					out = map[string]bool{}
				}
				out[t[i].Text] = true
			}
		}
	})
	return out
}

// foreachTarget reports whether t[i] comes after the as of a foreach header in
// the same tokens: as $cb, as $k => $cb, as [$a, $cb], as list($a, $cb).
func foreachTarget(t []Token, i int) bool {
	for k := i - 1; k >= 0; k-- {
		if t[k].word("as") {
			return true
		}
		if t[k].op(";") || t[k].op("{") || t[k].op("}") {
			return false
		}
	}
	return false
}

// destructured reports whether t[i] sits inside a [...] or list(...), at any
// depth, that an assignment's = follows: [$a, $cb] = ..., [[$cb]] = ...,
// list($cb) = ...
func destructured(t []Token, i int) bool {
	depth := 0
	for k := i + 1; k < len(t); k++ {
		switch {
		case isOpen(t[k]):
			depth++
		case isClose(t[k]):
			if depth > 0 {
				depth--
				continue
			}
			// an enclosing bracket closes here: a target when = follows it;
			// otherwise go on out (the next level up may be the target)
			if k+1 < len(t) && t[k+1].op("=") && (t[k].op("]") || t[k].op(")") && listOpen(t, k)) {
				return true
			}
		case t[k].op(";"):
			return false
		}
	}
	return false
}

// listOpen reports whether the ) at t[c] closes a list( ... ).
func listOpen(t []Token, c int) bool {
	d := 0
	for o := c - 1; o >= 0; o-- {
		if isClose(t[o]) {
			d++
		} else if isOpen(t[o]) {
			if d == 0 {
				return o > 0 && t[o-1].word("list")
			}
			d--
		}
	}
	return false
}

// pcallSeeds finds, in a PHP statement, a closure called where it is written
// ((function ($a) { ... })($x): seeded like a closure literal below) and
// calls of a function whose summary calls one of its parameters
// (summary.pcall: tap($value, $callback), Arr::first($array, $callback)) and
// follows the callable passed there:
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
		if t[i].op("(") && i+3 < len(t) && t[i+1].Kind == Func && t[i+2].op(")") && t[i+3].op("(") {
			// (function ($a) use ($b) { ... })($atts): a closure called where it
			// is written gets each argument in the parameter of its place
			args := callArgs(t, i+3)
			seed := func(k int) val {
				if k < len(args) {
					return a.expr(st, args[k], false)
				}
				return val{}
			}
			out = a.passCallable(st, t[i+1:i+2], funcs, seed, len(args), false, out)
			continue
		}
		if !t[i+1].op("(") || t[i].Kind != Ident && t[i].Kind != Var {
			continue
		}
		if t[i].Kind == Var && (i == 0 || !memberOp(true, t[i-1]) && !newWord(t[i-1])) {
			// $callback(...) of a parameter (new $class(...) makes an object: no call): the input its arguments carry is
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
		if cb, ok := callableBuiltins[strings.ToLower(t[i].Text)]; ok && t[i].Kind == Ident && (i == 0 || !memberOp(true, t[i-1]) && !t[i-1].op("::")) {
			args := callArgs(t, i+1)
			// A parameter handed on (array_map($callback, $x)) is not followed
			// yet: which callable a caller passes, often inside an options
			// array, needs its own design.
			if cb.pos < len(args) && !(len(args[cb.pos]) == 1 && args[cb.pos][0].Kind == Var && a.paramIndex(args[cb.pos][0].Text) >= 0) {
				seed := func(k int) val {
					var v val
					for _, m := range cb.from(k, len(args)) {
						if m < len(args) {
							v = or(v, a.expr(st, args[m], false))
						}
					}
					return v
				}
				out = a.passCallable(st, args[cb.pos], funcs, seed, cb.width(len(args)), false, out)
			}
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
			if n >= len(args) || args[n] == nil {
				if input {
					a.b.tooDeepFor(CutCallableParam)
				}
				continue
			}
			out = a.passCallable(st, args[n], funcs, seed, width, true, out)
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
		found = found || callsParamIn(t, fi.params)
	})
	return found
}

// callsParamIn reports whether tokens call one of params ($callback(...); not
// new $class(...), which makes an object).
func callsParamIn(t []Token, params []string) bool {
	for i := 0; i+1 < len(t); i++ {
		if t[i].Kind == Var && t[i+1].op("(") && slices.Contains(params, t[i].Text) && (i == 0 || !newWord(t[i-1])) {
			return true
		}
	}
	return false
}

// newWord reports whether t is PHP's new, in any case (NEW $class(...)).
func newWord(t Token) bool { return t.Kind == Ident && strings.EqualFold(t.Text, "new") }

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

// passCallable follows the callable a call passes where the callee (or a
// builtin) calls it with arguments whose input seed(k) gives:
//   - a closure literal: seeded, its sinks found when it is analysed;
//   - the caller's own parameter: the effect moves up (a.summ.pcall);
//   - a function name ('foo', 'Cls::m'), an array callable ([$this, 'm'],
//     [Cls::class, 'm'], array(...)) or a first-class callable (foo(...)):
//     resolved and its summary's sinks reported for the seeded arguments;
//   - anything else: with input, cut as callable-param when cutUnknown (a
//     callee's effect; a builtin's unknown callable stays as it was).
func (a *analysis) passCallable(st state, arg []Token, funcs []*fn, seed func(int) val, width int, cutUnknown bool, out map[*fn][]*paramSeed) map[*fn][]*paramSeed {
	input := false
	for k := range width {
		input = input || seed(k).taint
	}
	switch {
	case len(arg) == 1 && arg[0].Kind == Func && arg[0].Fn < len(funcs):
		f := funcs[arg[0].Fn]
		if out == nil {
			out = map[*fn][]*paramSeed{}
		}
		for k := range width {
			out[f] = append(out[f], &paramSeed{param: k, v: seed(k)})
		}
	case len(arg) == 1 && arg[0].Kind == Var && a.paramIndex(arg[0].Text) >= 0:
		if a.summ != nil && a.nested == 0 {
			p := a.paramIndex(arg[0].Text)
			for k := range width {
				if seed(k).taint {
					a.summ.pcall[[2]int{p, k}] = true
				}
			}
		}
	default:
		if !input {
			return out
		}
		if call := callableCall(arg); call != nil {
			at := len(call) - 3 // the name before "(" ")"
			if sum := a.callSummary(call, at, a.calleeKey(call, at)); sum != nil {
				if a.nonced(st) {
					return out // as at a sink: the request is the site's own (context.go)
				}
				for k := range width {
					v := seed(k)
					if !v.taint || v.weak {
						continue
					}
					// as callSinks: in library mode only input embedded on the way
					if emb := v.emb || sum.sinkEmb&(1<<k) != 0; !a.lib || emb {
						for _, l := range sum.sinkOf(k) {
							a.reportSink(l, emb)
						}
					}
				}
				return out
			}
			if a.irrelevant(call, at) {
				return out // a function the rule finds nothing in: nothing of this rule reaches it
			}
			if name := strings.ToLower(call[0].Text); a.php && len(call) == 3 && call[0].Kind == Ident && phpBuiltins[name] {
				a.builtinCallable(st, name, arg[0].Line, seed, width) // 'SYSTEM' is system: PHP names are case-insensitive
				return out
			}
		}
		if cutUnknown {
			a.b.tooDeepFor(CutCallableParam)
		}
	}
	return out
}

// callableCall turns a PHP callable written as a value into the tokens of a
// call of it, ending in "(" ")", or nil: 'foo' and 'Cls::m', [$this, 'm'],
// [Cls::class, 'm'] and array(...) alike, and foo(...).
func callableCall(arg []Token) []Token {
	op := func(s string) Token { return Token{Kind: Op, Text: s} }
	id := func(s string) Token { return Token{Kind: Ident, Text: s} }
	tail := []Token{op("("), op(")")}
	switch {
	case len(arg) == 1 && arg[0].Kind == Str && len(arg[0].Parts) == 0:
		name := globalName(arg[0].Text) // '\system': the global name, as \system(
		if c, m, ok := strings.Cut(name, "::"); ok && c != "" && m != "" {
			return append([]Token{id(c), op("::"), id(m)}, tail...)
		}
		if name == "" || strings.ContainsAny(name, " ()$") {
			return nil
		}
		return append([]Token{id(name)}, tail...)
	case len(arg) == 4 && arg[0].Kind == Ident && arg[1].op("(") && arg[2].op("...") && arg[3].op(")"):
		return append([]Token{arg[0]}, tail...)
	}
	inner := arg
	switch {
	case len(arg) >= 2 && arg[0].op("[") && arg[len(arg)-1].op("]"):
		inner = arg[1 : len(arg)-1]
	case len(arg) >= 3 && arg[0].word("array") && arg[1].op("(") && arg[len(arg)-1].op(")"):
		inner = arg[2 : len(arg)-1]
	default:
		return nil
	}
	parts := splitTop(inner, isComma)
	if len(parts) != 2 || len(parts[1]) != 1 || parts[1][0].Kind != Str || len(parts[1][0].Parts) != 0 {
		return nil
	}
	m := id(parts[1][0].Text)
	switch obj := parts[0]; {
	case len(obj) == 1 && obj[0].Kind == Var:
		return append([]Token{obj[0], op("->"), m}, tail...)
	case len(obj) == 3 && obj[0].Kind == Ident && obj[1].op("::") && obj[2].word("class"):
		return append([]Token{obj[0], op("::"), m}, tail...)
	case len(obj) == 1 && obj[0].Kind == Str && len(obj[0].Parts) == 0:
		return append([]Token{id(obj[0].Text), op("::"), m}, tail...)
	}
	return nil
}

// builtinCallable reports what a PHP builtin given by name ('system',
// 'intval', 'urlencode') does with the arguments it is called with: the rule's
// sinks and sanitizers apply as to a call written out, with the seeded input in
// its arguments, at the line the name is written. A builtin is no unknown
// function, so it is not cut.
func (a *analysis) builtinCallable(st state, name string, line int, seed func(int) val, width int) {
	tmp := st.clone()
	toks := []Token{{Kind: Ident, Text: name, Line: line}, {Kind: Op, Text: "(", Line: line}}
	for k := range width {
		if k > 0 {
			toks = append(toks, Token{Kind: Op, Text: ",", Line: line})
		}
		v := seed(k)
		x := Token{Kind: Var, Text: "$\x00cb" + strconv.Itoa(k), Line: line}
		tmp[x.Text] = entry{taint: v.taint, raw: v.raw, emb: v.emb, weak: v.weak}
		toks = append(toks, x)
	}
	toks = append(toks, Token{Kind: Op, Text: ")", Line: line})
	a.sinks(tmp, toks)
}

// globalName drops the leading backslash of a fully qualified name written in
// a string literal: '\system', and '\\system', which PHP reads as \system too
// (the literal keeps its escapes).
func globalName(s string) string {
	if strings.HasPrefix(s, `\\`) {
		return s[2:]
	}
	return strings.TrimPrefix(s, `\`)
}

// strNames returns the lower-case plain string literals of toks that are no
// array key ($info['filesize'], 'filesize' => 0), made once per file into *set.
func strNames(toks []Token, set *map[string]bool) map[string]bool {
	if *set == nil {
		*set = map[string]bool{}
		for i, tk := range toks {
			if tk.Kind != Str || len(tk.Parts) > 0 || len(tk.Text) >= 64 {
				continue
			}
			if i+1 < len(toks) && (toks[i+1].op("=>") || toks[i+1].op("]") && i > 0 && toks[i-1].op("[")) {
				continue
			}
			(*set)[globalName(strings.ToLower(tk.Text))] = true
		}
	}
	return *set
}

// namedSink reports whether a sink of r that is a plain call of a PHP builtin
// (system(, exec() is named by one of strs: the file may hand it to a builtin
// or a function that calls it (builtinCallable).
func namedSink(r *crule, strs map[string]bool) bool {
	if r.rule.Lang != "php" {
		return false
	}
	for _, s := range r.sinks {
		if s.text == nil && !s.member && len(s.toks) == 2 && s.toks[0].Kind == Ident && s.toks[1].op("(") &&
			phpBuiltins[strings.ToLower(s.toks[0].Text)] && strs[strings.ToLower(s.toks[0].Text)] {
			return true
		}
	}
	return false
}

//go:embed php_builtins.txt
var phpBuiltinList string

// phpBuiltins are PHP's internal functions (php_builtins.txt), lower case.
var phpBuiltins = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(phpBuiltinList, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			m[strings.ToLower(l)] = true
		}
	}
	return m
}()

// callableBuiltin: a PHP builtin that calls a callable it is given. pos is the
// callable's argument; arg k of each call it makes gets the input of the
// call's arguments from(k) names (an array argument's input reaches the
// callable through its elements).
type callableBuiltin struct {
	pos   int
	from  func(k, nargs int) []int
	width func(nargs int) int
}

func fixedFrom(m ...[]int) func(int, int) []int {
	return func(k, _ int) []int {
		if k < len(m) {
			return m[k]
		}
		return nil
	}
}

func fixedWidth(n int) func(int) int { return func(int) int { return n } }

var callableBuiltins = map[string]callableBuiltin{
	"array_map":             {0, func(k, n int) []int { return []int{k + 1} }, func(n int) int { return max(n-1, 1) }},
	"array_filter":          {1, fixedFrom([]int{0}, []int{0}), fixedWidth(2)},
	"array_walk":            {1, fixedFrom([]int{0}, []int{0}, []int{2}), fixedWidth(3)},
	"array_walk_recursive":  {1, fixedFrom([]int{0}, []int{0}, []int{2}), fixedWidth(3)},
	"usort":                 {1, fixedFrom([]int{0}, []int{0}), fixedWidth(2)},
	"uasort":                {1, fixedFrom([]int{0}, []int{0}), fixedWidth(2)},
	"uksort":                {1, fixedFrom([]int{0}, []int{0}), fixedWidth(2)},
	"array_reduce":          {1, fixedFrom([]int{2}, []int{0}), fixedWidth(2)},
	"preg_replace_callback": {1, fixedFrom([]int{2}), fixedWidth(1)},
	"call_user_func":        {0, func(k, n int) []int { return []int{k + 1} }, func(n int) int { return max(n-1, 0) }},
	"call_user_func_array":  {0, fixedFrom([]int{1}, []int{1}, []int{1}, []int{1}), fixedWidth(4)},
}

// irrelevant reports whether the call at t[i] reaches a function, in this file
// or another, that the rule finds nothing in (relevance.go): no summary of it
// is worked out because none is needed. A function whose summary is not ready
// (a cycle still being worked out) or that is not found is not irrelevant.
func (a *analysis) irrelevant(t []Token, i int) bool {
	if key := a.calleeKey(t, i); key != "" {
		return a.sc != nil && len(a.sc.funcs[key]) > 0 && !a.relevant(key)
	}
	if a.proj == nil {
		return false
	}
	c, ok := a.callee(t, i)
	if !ok {
		return false
	}
	f, name, _, _ := a.proj.target(a, c)
	if f == "" {
		return false
	}
	x := a.proj.analysisFor(a, f)
	return x != nil && x.sc != nil && len(x.sc.funcs[name]) > 0 && !x.relevant(name)
}
